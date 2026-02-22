"""Memcached-protocol honeypot emulator with query artifact capture."""

from __future__ import annotations

import base64
import socket
import socketserver
import threading
from typing import Any
from uuid import uuid4

from clownpeanuts.config.schema import ServiceConfig
from clownpeanuts.core.logging import get_logger
from clownpeanuts.services.base import ServiceEmulator
from clownpeanuts.tarpit.throttle import AdaptiveThrottle


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args: Any, max_concurrent_connections: int = 256, **kwargs: Any) -> None:
        self._connection_slots = threading.BoundedSemaphore(max(1, int(max_concurrent_connections)))
        super().__init__(*args, **kwargs)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._connection_slots.acquire(blocking=False):
            try:
                request.close()
            except OSError:
                pass
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


class Emulator(ServiceEmulator):
    _MAX_VALUE_BYTES = 65_536
    _MAX_TOTAL_STORE_BYTES = 64 * 1024 * 1024
    _MAX_KEYS_PER_GET = 64
    _MAX_COMMAND_LINE_BYTES = 4_096

    def __init__(self) -> None:
        super().__init__()
        self.logger = get_logger("clownpeanuts.services.database.memcached")
        self._server: _ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._bound_host: str | None = None
        self._bound_port: int | None = None
        self._socket_timeout_seconds = 45.0
        self._server_version = "1.6.24-clownpeanuts"
        self._max_concurrent_connections = 256
        self._store_lock = threading.RLock()
        self._store: dict[str, bytes] = {}
        self._cas_tokens: dict[str, int] = {}
        self._cas_counter = 10_000
        self._tarpit = AdaptiveThrottle(service_name=self.name)

    @property
    def name(self) -> str:
        return "memcached_db"

    @property
    def default_ports(self) -> list[int]:
        return [11211, 11212]

    @property
    def config_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "server_version": {"type": "string"},
                "socket_timeout_seconds": {"type": "number", "minimum": 1},
                "max_concurrent_connections": {"type": "integer", "minimum": 1, "maximum": 5000},
                "adaptive_tarpit_enabled": {"type": "boolean"},
                "tarpit_min_delay_ms": {"type": "integer", "minimum": 0, "maximum": 10000},
                "tarpit_max_delay_ms": {"type": "integer", "minimum": 0, "maximum": 20000},
                "tarpit_ramp_events": {"type": "integer", "minimum": 1, "maximum": 1000},
                "tarpit_jitter_ratio": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            },
        }

    async def start(self, config: ServiceConfig) -> None:
        self._server_version = str(config.config.get("server_version", self._server_version))
        self._socket_timeout_seconds = float(config.config.get("socket_timeout_seconds", self._socket_timeout_seconds))
        self._max_concurrent_connections = max(
            1,
            int(config.config.get("max_concurrent_connections", self._max_concurrent_connections)),
        )
        self._tarpit.configure(config=config.config)
        host = config.listen_host
        port = config.ports[0] if config.ports else self.default_ports[0]
        self._server = _ThreadingTCPServer(
            (host, port),
            self._build_handler(),
            max_concurrent_connections=self._max_concurrent_connections,
        )
        self._bound_host = host
        self._bound_port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.running = True
        self.logger.info(
            "service started",
            extra={"service": self.name, "payload": {"host": self._bound_host, "port": self._bound_port}},
        )
        if self.runtime:
            self.runtime.event_logger.emit(
                message="memcached emulator started",
                service=self.name,
                action="service_start",
                event_type="start",
                payload={"host": self._bound_host, "port": self._bound_port},
            )

    async def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        self._thread = None
        self.running = False
        self.logger.info("service stopped", extra={"service": self.name})
        if self.runtime:
            self.runtime.event_logger.emit(
                message="memcached emulator stopped",
                service=self.name,
                action="service_stop",
                event_type="end",
            )

    async def handle_connection(self, conn: dict[str, Any]) -> dict[str, Any]:
        command = str(conn.get("command", "version"))
        source_ip = str(conn.get("source_ip", "127.0.0.1"))
        source_port = int(conn.get("source_port", 0))
        session_id = str(conn.get("session_id", f"memcached-{uuid4().hex}"))
        if self.runtime:
            self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
            self._record_command(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                command=command,
                details={},
            )
        return {
            "service": self.name,
            "session_id": session_id,
            "command": command,
            "status": "ok",
        }

    def inject_activity(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.runtime is None:
            return {
                "accepted": False,
                "service": self.name,
                "reason": "runtime not initialized",
            }
        activity_type = str(payload.get("type", "cache_command")).strip().lower()
        if activity_type not in {"database_query", "cache_command", "command"}:
            return {
                "accepted": False,
                "service": self.name,
                "reason": f"unsupported activity type '{activity_type}'",
            }
        source_ip = str(payload.get("source_ip", "127.0.0.1")).strip() or "127.0.0.1"
        try:
            source_port = int(payload.get("source_port", 0) or 0)
        except (TypeError, ValueError):
            source_port = 0
        session_id = str(payload.get("session_id", f"memcached-injected-{uuid4().hex[:12]}")).strip()
        if not session_id:
            session_id = f"memcached-injected-{uuid4().hex[:12]}"
        command = str(payload.get("command", "get")).strip().lower() or "get"
        details = payload.get("payload")
        command_details = dict(details) if isinstance(details, dict) else {}

        self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", "")).strip()
        if username and password:
            self._record_auth(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                username=username,
                password=password,
            )
        self._record_command(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            command=command,
            details=command_details,
        )
        return {
            "accepted": True,
            "service": self.name,
            "activity_type": activity_type,
            "session_id": session_id,
            "command": command,
        }

    @property
    def bound_endpoint(self) -> tuple[str, int] | None:
        if self._bound_host is None or self._bound_port is None:
            return None
        return (self._bound_host, self._bound_port)

    def _build_handler(self) -> type[socketserver.BaseRequestHandler]:
        emulator = self

        class MemcachedHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                emulator._handle_client(self.request, self.client_address)

        return MemcachedHandler

    def _handle_client(self, conn: socket.socket, client_address: tuple[str, int]) -> None:
        conn.settimeout(self._socket_timeout_seconds)
        source_ip, source_port = client_address
        session_id = f"memcached-{source_ip}-{uuid4().hex[:12]}"
        if self.runtime:
            self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
            self.runtime.event_logger.emit(
                message="memcached connection opened",
                service=self.name,
                action="connection_open",
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                event_type="access",
                outcome="success",
            )

        with conn.makefile("rb") as reader:
            while True:
                raw = reader.readline(self._MAX_COMMAND_LINE_BYTES + 2)
                if not raw:
                    return
                if len(raw) > self._MAX_COMMAND_LINE_BYTES or not raw.endswith(b"\n"):
                    self._send(conn, "CLIENT_ERROR command line too long\r\n")
                    return
                line = raw.rstrip(b"\r\n")
                if not line:
                    continue
                parts = line.decode("utf-8", errors="replace").split()
                if not parts:
                    continue
                command = parts[0].lower()

                self._record_command(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    command=command,
                    details={"args": parts[1:]},
                )
                self._tarpit.maybe_delay(
                    runtime=self.runtime,
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    trigger=f"memcached_{command}",
                )

                if command == "quit":
                    return
                if command == "version":
                    self._send(conn, f"VERSION {self._server_version}\r\n")
                    continue
                if command == "stats":
                    self._handle_stats(conn, parts)
                    continue
                if command == "get":
                    keys = parts[1:]
                    self._handle_get(conn, keys)
                    continue
                if command == "gets":
                    keys = parts[1:]
                    self._handle_get(conn, keys, include_cas=True)
                    continue
                if command in {"set", "add", "cas", "append", "prepend"}:
                    self._handle_storage_command(conn, reader, parts, source_ip, source_port, session_id, command)
                    continue
                if command == "delete":
                    self._handle_delete(conn, parts)
                    continue
                if command in {"incr", "decr"}:
                    self._handle_incr_decr(conn, parts, decrement=(command == "decr"))
                    continue
                if command == "touch":
                    self._handle_touch(conn, parts)
                    continue
                if command == "flush_all":
                    with self._store_lock:
                        self._store.clear()
                        self._cas_tokens.clear()
                    self._send(conn, "OK\r\n")
                    continue
                if command == "auth":
                    self._handle_auth(conn, parts, source_ip, source_port, session_id)
                    continue
                self._send(conn, "ERROR\r\n")

    def _handle_get(self, conn: socket.socket, keys: list[str], *, include_cas: bool = False) -> None:
        selected_keys = keys[: self._MAX_KEYS_PER_GET]
        with self._store_lock:
            for key in selected_keys:
                value = self._store.get(key)
                if value is None:
                    continue
                header_suffix = ""
                if include_cas:
                    header_suffix = f" {self._cas_tokens.get(key, 0)}"
                header = f"VALUE {key} 0 {len(value)}{header_suffix}\r\n".encode("utf-8")
                self._send_bytes(conn, header + value + b"\r\n")
        self._send(conn, "END\r\n")

    def _handle_storage_command(
        self,
        conn: socket.socket,
        reader: Any,
        parts: list[str],
        source_ip: str,
        source_port: int,
        session_id: str,
        command: str,
    ) -> None:
        minimum_args = 6 if command == "cas" else 5
        if len(parts) < minimum_args:
            self._send(conn, "CLIENT_ERROR bad command line format\r\n")
            return
        key = parts[1]
        try:
            bytes_len = int(parts[4])
        except ValueError:
            self._send(conn, "CLIENT_ERROR invalid bytes length\r\n")
            return
        if bytes_len < 0:
            self._send(conn, "CLIENT_ERROR invalid bytes length\r\n")
            return
        if bytes_len > self._MAX_VALUE_BYTES:
            self._send(conn, "SERVER_ERROR object too large for cache\r\n")
            return
        value = reader.read(bytes_len)
        if value is None or len(value) != bytes_len:
            self._send(conn, "SERVER_ERROR read failure\r\n")
            return
        trailing = reader.read(2)
        if trailing != b"\r\n":
            self._send(conn, "CLIENT_ERROR bad data chunk\r\n")
            return

        incoming_value = bytes(value)
        with self._store_lock:
            exists = key in self._store
            if command == "add" and exists:
                self._send(conn, "NOT_STORED\r\n")
                return
            if command == "cas":
                if not exists:
                    self._send(conn, "NOT_FOUND\r\n")
                    return
                try:
                    expected_cas = int(parts[5])
                except ValueError:
                    self._send(conn, "CLIENT_ERROR invalid cas token\r\n")
                    return
                current_cas = self._cas_tokens.get(key, 0)
                if expected_cas != current_cas:
                    self._send(conn, "EXISTS\r\n")
                    return
                candidate = incoming_value
            elif command == "append":
                if not exists:
                    self._send(conn, "NOT_STORED\r\n")
                    return
                candidate = self._store[key] + incoming_value
                if len(candidate) > self._MAX_VALUE_BYTES:
                    self._send(conn, "SERVER_ERROR value too large\r\n")
                    return
            elif command == "prepend":
                if not exists:
                    self._send(conn, "NOT_STORED\r\n")
                    return
                candidate = incoming_value + self._store[key]
                if len(candidate) > self._MAX_VALUE_BYTES:
                    self._send(conn, "SERVER_ERROR value too large\r\n")
                    return
            else:
                candidate = incoming_value
            if not self._can_store_value_locked(key, candidate):
                self._send(conn, "SERVER_ERROR out of memory storing object\r\n")
                return
            self._store[key] = candidate
            self._cas_tokens[key] = self._next_cas_token()
        preview = incoming_value[:80].decode("utf-8", errors="replace")
        self._record_command(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            command=command,
            details={"key": key, "size_bytes": len(incoming_value), "value_preview": preview},
        )
        self._send(conn, "STORED\r\n")

    def _handle_delete(self, conn: socket.socket, parts: list[str]) -> None:
        if len(parts) < 2:
            self._send(conn, "CLIENT_ERROR bad command line format\r\n")
            return
        key = parts[1]
        with self._store_lock:
            existed = key in self._store
            if existed:
                del self._store[key]
                self._cas_tokens.pop(key, None)
        self._send(conn, "DELETED\r\n" if existed else "NOT_FOUND\r\n")

    def _handle_incr_decr(self, conn: socket.socket, parts: list[str], *, decrement: bool) -> None:
        if len(parts) < 3:
            self._send(conn, "CLIENT_ERROR bad command line format\r\n")
            return
        key = parts[1]
        try:
            delta = int(parts[2])
        except ValueError:
            self._send(conn, "CLIENT_ERROR invalid numeric delta\r\n")
            return
        with self._store_lock:
            value = self._store.get(key)
            if value is None:
                self._send(conn, "NOT_FOUND\r\n")
                return
            try:
                current = int(value.decode("utf-8", errors="replace"))
            except ValueError:
                current = 0
            next_value = max(0, current - delta) if decrement else current + delta
            next_bytes = str(next_value).encode("utf-8")
            if not self._can_store_value_locked(key, next_bytes):
                self._send(conn, "SERVER_ERROR out of memory storing object\r\n")
                return
            self._store[key] = next_bytes
            self._cas_tokens[key] = self._next_cas_token()
        self._send(conn, f"{next_value}\r\n")

    def _handle_touch(self, conn: socket.socket, parts: list[str]) -> None:
        if len(parts) < 2:
            self._send(conn, "CLIENT_ERROR bad command line format\r\n")
            return
        key = parts[1]
        with self._store_lock:
            exists = key in self._store
        self._send(conn, "TOUCHED\r\n" if exists else "NOT_FOUND\r\n")

    def _handle_stats(self, conn: socket.socket, parts: list[str]) -> None:
        mode = parts[1].lower() if len(parts) > 1 else ""
        with self._store_lock:
            item_count = len(self._store)
            total_bytes = self._current_store_bytes_locked()

        if mode == "items":
            self._send(
                conn,
                (
                    "STAT items:1:number 64\r\n"
                    f"STAT items:1:number_hot {max(1, item_count // 3)}\r\n"
                    f"STAT items:1:number_warm {max(1, item_count // 4)}\r\n"
                    "END\r\n"
                ),
            )
            return

        if mode == "slabs":
            self._send(
                conn,
                (
                    "STAT 1:chunk_size 96\r\n"
                    "STAT 1:chunks_per_page 10922\r\n"
                    f"STAT 1:used_chunks {max(10, item_count)}\r\n"
                    "STAT active_slabs 1\r\n"
                    "END\r\n"
                ),
            )
            return

        if mode == "settings":
            self._send(
                conn,
                (
                    f"STAT maxbytes {self._MAX_TOTAL_STORE_BYTES}\r\n"
                    "STAT maxconns 1024\r\n"
                    "STAT verbosity 1\r\n"
                    f"STAT item_size_max {self._MAX_VALUE_BYTES}\r\n"
                    "END\r\n"
                ),
            )
            return

        self._send(
            conn,
            (
                "STAT pid 4112\r\n"
                "STAT curr_connections 9\r\n"
                f"STAT curr_items {item_count}\r\n"
                f"STAT bytes {total_bytes}\r\n"
                "END\r\n"
            ),
        )

    def _current_store_bytes_locked(self) -> int:
        return sum(len(value) for value in self._store.values())

    def _can_store_value_locked(self, key: str, value: bytes) -> bool:
        current_total = self._current_store_bytes_locked()
        current_key_bytes = len(self._store.get(key, b""))
        projected_total = current_total - current_key_bytes + len(value)
        return projected_total <= self._MAX_TOTAL_STORE_BYTES

    def _next_cas_token(self) -> int:
        self._cas_counter += 1
        return self._cas_counter

    def _handle_auth(
        self,
        conn: socket.socket,
        parts: list[str],
        source_ip: str,
        source_port: int,
        session_id: str,
    ) -> None:
        if len(parts) >= 2 and parts[1].lower() == "list":
            self._send(conn, "MECHS PLAIN\r\nEND\r\n")
            return
        if len(parts) < 3 or parts[1].lower() != "plain":
            self._send(conn, "CLIENT_ERROR unsupported auth mechanism\r\n")
            return
        username = ""
        password = ""
        try:
            decoded = base64.b64decode(parts[2]).decode("utf-8", errors="replace")
            chunks = decoded.split("\x00")
            if len(chunks) >= 3:
                username = chunks[1]
                password = chunks[2]
        except Exception:
            pass
        self._record_auth(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            password=password,
        )
        self._send(conn, "OK\r\n")

    @staticmethod
    def _send(conn: socket.socket, text: str) -> None:
        Emulator._send_bytes(conn, text.encode("utf-8", errors="replace"))

    @staticmethod
    def _send_bytes(conn: socket.socket, payload: bytes) -> None:
        try:
            conn.sendall(payload)
        except OSError:
            return

    def _record_command(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        command: str,
        details: dict[str, Any],
    ) -> None:
        if not self.runtime:
            return
        payload = {
            "source_ip": source_ip,
            "protocol": "memcached",
            "command": command,
            "details": details,
        }
        self.runtime.session_manager.record_event(
            session_id=session_id,
            service=self.name,
            action="command",
            payload=payload,
        )
        self.runtime.event_logger.emit(
            message="memcached command",
            service=self.name,
            action="command",
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            event_type="info",
            outcome="success",
            payload=payload,
        )

    def _record_auth(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        username: str,
        password: str,
    ) -> None:
        if not self.runtime:
            return
        payload = {
            "source_ip": source_ip,
            "protocol": "memcached",
            "username": username,
            "password": password,
            "outcome": "success",
        }
        self.runtime.session_manager.record_event(
            session_id=session_id,
            service=self.name,
            action="auth_attempt",
            payload=payload,
        )
        self.runtime.event_logger.emit(
            message="memcached auth attempt",
            service=self.name,
            action="auth_attempt",
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            event_type="authentication",
            outcome="success",
            payload=payload,
        )
