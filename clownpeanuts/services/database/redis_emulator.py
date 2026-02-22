"""Redis-protocol honeypot emulator with command capture."""

from __future__ import annotations

from fnmatch import fnmatch
import random
import socket
import socketserver
import threading
import time
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
    _MAX_RESP_ARRAY_ITEMS = 256
    _MAX_RESP_BULK_BYTES = 65_536
    _MAX_RECV_BYTES = 1_048_576
    _MAX_TOTAL_STORE_BYTES = 64 * 1024 * 1024
    _OOM_REPLY = b"-OOM command not allowed when used memory > 'maxmemory'.\r\n"

    def __init__(self) -> None:
        super().__init__()
        self.logger = get_logger("clownpeanuts.services.database.redis")
        self._config: ServiceConfig | None = None
        self._server: _ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._bound_host: str | None = None
        self._bound_port: int | None = None
        self._store_lock = threading.RLock()
        self._store: dict[str, str] = {}
        self._hash_store: dict[str, dict[str, str]] = {}
        self._list_store: dict[str, list[str]] = {}
        self._set_store: dict[str, set[str]] = {}
        self._expirations: dict[str, float] = {}
        self._server_version = "7.0.12"
        self._socket_timeout_seconds = 45.0
        self._max_concurrent_connections = 256
        self._tarpit = AdaptiveThrottle(service_name=self.name)

    @property
    def name(self) -> str:
        return "redis_db"

    @property
    def default_ports(self) -> list[int]:
        return [6379, 6380]

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
        self._config = config
        self._server_version = str(config.config.get("server_version", self._server_version))
        self._socket_timeout_seconds = float(config.config.get("socket_timeout_seconds", self._socket_timeout_seconds))
        self._max_concurrent_connections = max(
            1,
            int(config.config.get("max_concurrent_connections", self._max_concurrent_connections)),
        )
        self._tarpit.configure(config=config.config)
        listen_host = config.listen_host
        listen_port = config.ports[0] if config.ports else self.default_ports[0]
        self._server = _ThreadingTCPServer(
            (listen_host, listen_port),
            self._build_handler(),
            max_concurrent_connections=self._max_concurrent_connections,
        )
        self._bound_host = listen_host
        self._bound_port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.running = True
        self.logger.info(
            "service started",
            extra={
                "service": self.name,
                "payload": {"host": self._bound_host, "port": self._bound_port},
            },
        )
        if self.runtime:
            self.runtime.event_logger.emit(
                message="redis emulator started",
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
                message="redis emulator stopped",
                service=self.name,
                action="service_stop",
                event_type="end",
            )

    async def handle_connection(self, conn: dict[str, Any]) -> dict[str, Any]:
        command = [str(part) for part in conn.get("command", [])]
        if not command:
            command = ["PING"]
        source_ip = str(conn.get("source_ip", "127.0.0.1"))
        source_port = int(conn.get("source_port", 0))
        session_id = str(conn.get("session_id", f"redis-{uuid4().hex}"))

        if self.runtime:
            self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)

        response, close_after = self._execute_command(
            command=command,
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
        )
        return {
            "service": self.name,
            "session_id": session_id,
            "request": command,
            "response": response.decode("utf-8", errors="replace"),
            "close": close_after,
        }

    def inject_activity(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.runtime is None:
            return {
                "accepted": False,
                "service": self.name,
                "reason": "runtime not initialized",
            }
        activity_type = str(payload.get("type", "redis_command")).strip().lower()
        if activity_type not in {"database_query", "redis_command", "command"}:
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
        session_id = str(payload.get("session_id", f"redis-injected-{uuid4().hex[:12]}")).strip()
        if not session_id:
            session_id = f"redis-injected-{uuid4().hex[:12]}"
        self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)

        username = str(payload.get("username", "default")).strip() or "default"
        password = str(payload.get("password", "")).strip()
        if password:
            self._record_auth(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                username=username,
                password=password,
            )

        commands: list[list[str]] = []
        commands_raw = payload.get("commands")
        if isinstance(commands_raw, list):
            for item in commands_raw:
                if isinstance(item, list):
                    parts = [str(part).strip() for part in item if str(part).strip()]
                    if parts:
                        commands.append(parts)
                    continue
                text = str(item).strip()
                if text:
                    commands.append(text.split())
        command_raw = payload.get("command")
        if isinstance(command_raw, list):
            parts = [str(part).strip() for part in command_raw if str(part).strip()]
            if parts:
                commands.append(parts)
        else:
            text = str(command_raw or "").strip()
            if text:
                commands.append(text.split())
        details = payload.get("payload")
        if isinstance(details, dict):
            nested_command = details.get("command")
            if isinstance(nested_command, list):
                parts = [str(part).strip() for part in nested_command if str(part).strip()]
                if parts:
                    commands.append(parts)
            else:
                text = str(nested_command or "").strip()
                if text:
                    commands.append(text.split())
        if not commands:
            commands = [["PING"]]

        responses: list[str] = []
        close_requested = False
        for command in commands[:120]:
            response, close_after = self._execute_command(
                command=command,
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
            )
            responses.append(response.decode("utf-8", errors="replace").strip())
            close_requested = close_requested or close_after
            if close_after:
                break

        return {
            "accepted": True,
            "service": self.name,
            "activity_type": activity_type,
            "session_id": session_id,
            "command_count": len(commands[:120]),
            "close_requested": close_requested,
            "responses": responses[:10],
        }

    @property
    def bound_endpoint(self) -> tuple[str, int] | None:
        if self._bound_host is None or self._bound_port is None:
            return None
        return (self._bound_host, self._bound_port)

    def _build_handler(self) -> type[socketserver.BaseRequestHandler]:
        emulator = self

        class RedisHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                emulator._handle_client(self.request, self.client_address)

        return RedisHandler

    def _handle_client(self, conn: socket.socket, client_address: tuple[str, int]) -> None:
        conn.settimeout(self._socket_timeout_seconds)
        source_ip, source_port = client_address
        session_id = f"redis-{source_ip}-{uuid4().hex[:12]}"
        if self.runtime:
            self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
            self.runtime.event_logger.emit(
                message="redis connection opened",
                service=self.name,
                action="connection_open",
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                event_type="access",
                outcome="success",
            )

        while True:
            command = self._read_command(conn)
            if not command:
                return
            response, close_after = self._execute_command(
                command=command,
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
            )
            try:
                conn.sendall(response)
            except OSError:
                return
            if close_after:
                return

    def _execute_command(
        self,
        *,
        command: list[str],
        session_id: str,
        source_ip: str,
        source_port: int,
    ) -> tuple[bytes, bool]:
        cmd = command[0].upper()
        args = command[1:]

        self._record_command(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            command=command,
        )
        self._tarpit.maybe_delay(
            runtime=self.runtime,
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            trigger=f"redis_{cmd.lower()}",
        )

        if cmd == "PING":
            if args:
                return self._bulk(args[0]), False
            return b"+PONG\r\n", False

        if cmd == "ECHO":
            if not args:
                return b"-ERR wrong number of arguments for 'echo' command\r\n", False
            return self._bulk(args[0]), False

        if cmd == "AUTH":
            username = args[0] if args else "default"
            password = args[-1] if args else ""
            self._record_auth(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                username=username,
                password=password,
            )
            return b"+OK\r\n", False

        if cmd == "SET":
            if len(args) < 2:
                return b"-ERR wrong number of arguments for 'set' command\r\n", False
            with self._store_lock:
                self._purge_expired_key_locked(args[0])
                if not self._set_key_string_locked(args[0], args[1], clear_expiration=True):
                    return self._OOM_REPLY, False
            return b"+OK\r\n", False

        if cmd == "MSET":
            if not args or (len(args) % 2) != 0:
                return b"-ERR wrong number of arguments for 'mset' command\r\n", False
            with self._store_lock:
                updates: dict[str, str] = {}
                for index in range(0, len(args), 2):
                    key = args[index]
                    value = args[index + 1]
                    self._purge_expired_key_locked(key)
                    updates[key] = value
                projected_usage = {key: self._encoded_len(value) for key, value in updates.items()}
                if not self._fits_key_updates_locked(projected_usage):
                    return self._OOM_REPLY, False
                for key, value in updates.items():
                    # Capacity check was already completed as a single atomic budget decision.
                    self._set_key_string_locked(key, value, clear_expiration=True)
            return b"+OK\r\n", False

        if cmd == "GET":
            if len(args) != 1:
                return b"-ERR wrong number of arguments for 'get' command\r\n", False
            with self._store_lock:
                self._purge_expired_key_locked(args[0])
                if args[0] in self._hash_store or args[0] in self._list_store or args[0] in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                value = self._store.get(args[0])
            if value is None:
                return b"$-1\r\n", False
            return self._bulk(value), False

        if cmd == "MGET":
            if not args:
                return b"*0\r\n", False
            with self._store_lock:
                values: list[str | None] = []
                for key in args:
                    self._purge_expired_key_locked(key)
                    if key in self._hash_store or key in self._list_store or key in self._set_store:
                        return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                    values.append(self._store.get(key))
            return self._bulk_array(values), False

        if cmd == "HSET":
            if len(args) < 3 or (len(args) % 2) == 0:
                return b"-ERR wrong number of arguments for 'hset' command\r\n", False
            key = args[0]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._list_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                current = dict(self._hash_store.get(key, {}))
                added = 0
                for index in range(1, len(args), 2):
                    field = args[index]
                    value = args[index + 1]
                    if field not in current:
                        added += 1
                    current[field] = value
                if not self._set_key_hash_locked(key, current):
                    return self._OOM_REPLY, False
            return self._integer(added), False

        if cmd == "HGET":
            if len(args) != 2:
                return b"-ERR wrong number of arguments for 'hget' command\r\n", False
            key = args[0]
            field = args[1]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._list_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._hash_store.get(key)
                if values is None:
                    return b"$-1\r\n", False
                value = values.get(field)
            if value is None:
                return b"$-1\r\n", False
            return self._bulk(value), False

        if cmd == "HGETALL":
            if len(args) != 1:
                return b"-ERR wrong number of arguments for 'hgetall' command\r\n", False
            key = args[0]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._list_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._hash_store.get(key, {})
                payload: list[str] = []
                for field, value in values.items():
                    payload.extend([field, value])
            return self._array(payload), False

        if cmd == "HKEYS":
            if len(args) != 1:
                return b"-ERR wrong number of arguments for 'hkeys' command\r\n", False
            key = args[0]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._list_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._hash_store.get(key, {})
                fields = list(values.keys())
            return self._array(fields), False

        if cmd == "HLEN":
            if len(args) != 1:
                return b"-ERR wrong number of arguments for 'hlen' command\r\n", False
            key = args[0]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._list_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._hash_store.get(key, {})
                size = len(values)
            return self._integer(size), False

        if cmd == "SADD":
            if len(args) < 2:
                return b"-ERR wrong number of arguments for 'sadd' command\r\n", False
            key = args[0]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._list_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = set(self._set_store.get(key, set()))
                added = 0
                for member in args[1:]:
                    if member not in values:
                        values.add(member)
                        added += 1
                if not self._set_key_set_locked(key, values):
                    return self._OOM_REPLY, False
            return self._integer(added), False

        if cmd == "SREM":
            if len(args) < 2:
                return b"-ERR wrong number of arguments for 'srem' command\r\n", False
            key = args[0]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._list_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._set_store.get(key)
                if values is None:
                    return b":0\r\n", False
                removed = 0
                for member in args[1:]:
                    if member in values:
                        values.remove(member)
                        removed += 1
                if not values:
                    self._set_store.pop(key, None)
                    self._expirations.pop(key, None)
            return self._integer(removed), False

        if cmd == "SMEMBERS":
            if len(args) != 1:
                return b"-ERR wrong number of arguments for 'smembers' command\r\n", False
            key = args[0]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._list_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._set_store.get(key, set())
            return self._array(sorted(values)), False

        if cmd == "SISMEMBER":
            if len(args) != 2:
                return b"-ERR wrong number of arguments for 'sismember' command\r\n", False
            key, member = args
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._list_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._set_store.get(key, set())
                present = member in values
            return self._integer(1 if present else 0), False

        if cmd == "SMISMEMBER":
            if len(args) < 2:
                return b"-ERR wrong number of arguments for 'smismember' command\r\n", False
            key = args[0]
            members = args[1:]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._list_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._set_store.get(key, set())
                result = [1 if member in values else 0 for member in members]
            return self._integer_array(result), False

        if cmd == "SCARD":
            if len(args) != 1:
                return b"-ERR wrong number of arguments for 'scard' command\r\n", False
            key = args[0]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._list_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._set_store.get(key, set())
            return self._integer(len(values)), False

        if cmd == "SRANDMEMBER":
            if not args or len(args) > 2:
                return b"-ERR wrong number of arguments for 'srandmember' command\r\n", False
            key = args[0]
            count: int | None = None
            if len(args) == 2:
                try:
                    count = int(args[1])
                except ValueError:
                    return b"-ERR value is not an integer or out of range\r\n", False
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._list_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = list(self._set_store.get(key, set()))
            if count is None:
                if not values:
                    return b"$-1\r\n", False
                return self._bulk(random.choice(values)), False
            if count == 0 or not values:
                return b"*0\r\n", False
            if count > 0:
                bounded = min(count, len(values))
                return self._array(random.sample(values, bounded)), False
            duplicate_count = abs(count)
            selected = [random.choice(values) for _ in range(duplicate_count)]
            return self._array(selected), False

        if cmd == "SPOP":
            if not args or len(args) > 2:
                return b"-ERR wrong number of arguments for 'spop' command\r\n", False
            key = args[0]
            count: int | None = None
            if len(args) == 2:
                try:
                    count = int(args[1])
                except ValueError:
                    return b"-ERR value is not an integer or out of range\r\n", False
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._list_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._set_store.get(key)
                if not values:
                    if count is None:
                        return b"$-1\r\n", False
                    return b"*0\r\n", False
                members = list(values)
                if count is None:
                    selected = [random.choice(members)]
                else:
                    if count <= 0:
                        return b"*0\r\n", False
                    selected = random.sample(members, min(count, len(members)))
                for member in selected:
                    values.discard(member)
                if not values:
                    self._set_store.pop(key, None)
                    self._expirations.pop(key, None)
            if count is None:
                return self._bulk(selected[0]), False
            return self._array(selected), False

        if cmd == "SMOVE":
            if len(args) != 3:
                return b"-ERR wrong number of arguments for 'smove' command\r\n", False
            source, destination, member = args
            with self._store_lock:
                self._purge_expired_key_locked(source)
                self._purge_expired_key_locked(destination)
                if source in self._store or source in self._hash_store or source in self._list_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                if destination in self._store or destination in self._hash_store or destination in self._list_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                source_values = self._set_store.get(source)
                if not source_values or member not in source_values:
                    return b":0\r\n", False
                if source == destination:
                    return b":1\r\n", False
                source_values.discard(member)
                destination_values = self._set_store.setdefault(destination, set())
                destination_values.add(member)
                if not source_values:
                    self._set_store.pop(source, None)
                    self._expirations.pop(source, None)
            return b":1\r\n", False

        if cmd == "SUNION":
            if not args:
                return b"-ERR wrong number of arguments for 'sunion' command\r\n", False
            with self._store_lock:
                union: set[str] = set()
                for key in args:
                    self._purge_expired_key_locked(key)
                    if key in self._store or key in self._hash_store or key in self._list_store:
                        return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                    values = self._set_store.get(key)
                    if values:
                        union.update(values)
            return self._array(sorted(union)), False

        if cmd == "SINTER":
            if not args:
                return b"-ERR wrong number of arguments for 'sinter' command\r\n", False
            with self._store_lock:
                intersection: set[str] | None = None
                for key in args:
                    self._purge_expired_key_locked(key)
                    if key in self._store or key in self._hash_store or key in self._list_store:
                        return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                    values = self._set_store.get(key, set())
                    if intersection is None:
                        intersection = set(values)
                    else:
                        intersection.intersection_update(values)
            if intersection is None:
                return b"*0\r\n", False
            return self._array(sorted(intersection)), False

        if cmd == "SINTERCARD":
            if len(args) < 2:
                return b"-ERR wrong number of arguments for 'sintercard' command\r\n", False
            try:
                numkeys = int(args[0])
            except ValueError:
                return b"-ERR value is not an integer or out of range\r\n", False
            if numkeys <= 0:
                return b"-ERR numkeys should be greater than 0\r\n", False
            if len(args) < 1 + numkeys:
                return b"-ERR wrong number of arguments for 'sintercard' command\r\n", False
            source_keys = args[1 : 1 + numkeys]
            tail = args[1 + numkeys :]
            limit: int | None = None
            if tail:
                if len(tail) != 2 or tail[0].upper() != "LIMIT":
                    return b"-ERR syntax error\r\n", False
                try:
                    limit = int(tail[1])
                except ValueError:
                    return b"-ERR value is not an integer or out of range\r\n", False
                if limit < 0:
                    return b"-ERR value is not an integer or out of range\r\n", False
            with self._store_lock:
                intersection: set[str] | None = None
                for key in source_keys:
                    self._purge_expired_key_locked(key)
                    if key in self._store or key in self._hash_store or key in self._list_store:
                        return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                    values = self._set_store.get(key, set())
                    if intersection is None:
                        intersection = set(values)
                    else:
                        intersection.intersection_update(values)
                    if intersection == set():
                        break
            cardinality = len(intersection or set())
            if limit is not None and limit > 0:
                cardinality = min(cardinality, limit)
            return self._integer(cardinality), False

        if cmd == "SDIFF":
            if not args:
                return b"-ERR wrong number of arguments for 'sdiff' command\r\n", False
            with self._store_lock:
                self._purge_expired_key_locked(args[0])
                first = args[0]
                if first in self._store or first in self._hash_store or first in self._list_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                diff = set(self._set_store.get(first, set()))
                for key in args[1:]:
                    self._purge_expired_key_locked(key)
                    if key in self._store or key in self._hash_store or key in self._list_store:
                        return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                    values = self._set_store.get(key)
                    if values:
                        diff.difference_update(values)
            return self._array(sorted(diff)), False

        if cmd == "SUNIONSTORE":
            if len(args) < 2:
                return b"-ERR wrong number of arguments for 'sunionstore' command\r\n", False
            destination = args[0]
            source_keys = args[1:]
            with self._store_lock:
                union: set[str] = set()
                for key in source_keys:
                    self._purge_expired_key_locked(key)
                    if key in self._store or key in self._hash_store or key in self._list_store:
                        return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                    values = self._set_store.get(key)
                    if values:
                        union.update(values)
                if not self._set_key_set_locked(destination, union, clear_expiration=True):
                    return self._OOM_REPLY, False
            return self._integer(len(union)), False

        if cmd == "SINTERSTORE":
            if len(args) < 2:
                return b"-ERR wrong number of arguments for 'sinterstore' command\r\n", False
            destination = args[0]
            source_keys = args[1:]
            with self._store_lock:
                intersection: set[str] | None = None
                for key in source_keys:
                    self._purge_expired_key_locked(key)
                    if key in self._store or key in self._hash_store or key in self._list_store:
                        return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                    values = self._set_store.get(key, set())
                    if intersection is None:
                        intersection = set(values)
                    else:
                        intersection.intersection_update(values)
                result = intersection or set()
                if not self._set_key_set_locked(destination, result, clear_expiration=True):
                    return self._OOM_REPLY, False
            return self._integer(len(result)), False

        if cmd == "SDIFFSTORE":
            if len(args) < 2:
                return b"-ERR wrong number of arguments for 'sdiffstore' command\r\n", False
            destination = args[0]
            source_keys = args[1:]
            with self._store_lock:
                self._purge_expired_key_locked(source_keys[0])
                first = source_keys[0]
                if first in self._store or first in self._hash_store or first in self._list_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                result = set(self._set_store.get(first, set()))
                for key in source_keys[1:]:
                    self._purge_expired_key_locked(key)
                    if key in self._store or key in self._hash_store or key in self._list_store:
                        return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                    values = self._set_store.get(key)
                    if values:
                        result.difference_update(values)
                if not self._set_key_set_locked(destination, result, clear_expiration=True):
                    return self._OOM_REPLY, False
            return self._integer(len(result)), False

        if cmd == "LPUSH":
            if len(args) < 2:
                return b"-ERR wrong number of arguments for 'lpush' command\r\n", False
            key = args[0]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = list(self._list_store.get(key, []))
                for value in args[1:]:
                    values.insert(0, value)
                if not self._set_key_list_locked(key, values):
                    return self._OOM_REPLY, False
                length = len(values)
            return self._integer(length), False

        if cmd == "RPUSH":
            if len(args) < 2:
                return b"-ERR wrong number of arguments for 'rpush' command\r\n", False
            key = args[0]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = list(self._list_store.get(key, []))
                values.extend(args[1:])
                if not self._set_key_list_locked(key, values):
                    return self._OOM_REPLY, False
                length = len(values)
            return self._integer(length), False

        if cmd == "LPOP":
            if len(args) != 1:
                return b"-ERR wrong number of arguments for 'lpop' command\r\n", False
            key = args[0]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._list_store.get(key)
                if not values:
                    return b"$-1\r\n", False
                value = values.pop(0)
                if not values:
                    self._list_store.pop(key, None)
                    self._expirations.pop(key, None)
            return self._bulk(value), False

        if cmd == "RPOP":
            if len(args) != 1:
                return b"-ERR wrong number of arguments for 'rpop' command\r\n", False
            key = args[0]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._list_store.get(key)
                if not values:
                    return b"$-1\r\n", False
                value = values.pop()
                if not values:
                    self._list_store.pop(key, None)
                    self._expirations.pop(key, None)
            return self._bulk(value), False

        if cmd == "LLEN":
            if len(args) != 1:
                return b"-ERR wrong number of arguments for 'llen' command\r\n", False
            key = args[0]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._list_store.get(key, [])
                length = len(values)
            return self._integer(length), False

        if cmd == "LRANGE":
            if len(args) != 3:
                return b"-ERR wrong number of arguments for 'lrange' command\r\n", False
            key = args[0]
            try:
                start = int(args[1])
                stop = int(args[2])
            except ValueError:
                return b"-ERR value is not an integer or out of range\r\n", False
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._list_store.get(key, [])
                selected = self._list_range(values=values, start=start, stop=stop)
            return self._array(selected), False

        if cmd == "LINDEX":
            if len(args) != 2:
                return b"-ERR wrong number of arguments for 'lindex' command\r\n", False
            key = args[0]
            try:
                index = int(args[1])
            except ValueError:
                return b"-ERR value is not an integer or out of range\r\n", False
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._list_store.get(key)
                if not values:
                    return b"$-1\r\n", False
                normalized_index = index if index >= 0 else len(values) + index
                if normalized_index < 0 or normalized_index >= len(values):
                    return b"$-1\r\n", False
                value = values[normalized_index]
            return self._bulk(value), False

        if cmd == "LPOS":
            if len(args) < 2:
                return b"-ERR wrong number of arguments for 'lpos' command\r\n", False
            key, element = args[0], args[1]
            rank = 1
            count: int | None = None
            maxlen: int | None = None
            seen_rank = False
            seen_count = False
            seen_maxlen = False
            index = 2
            while index < len(args):
                option = args[index].strip().upper()
                if option not in {"RANK", "COUNT", "MAXLEN"} or (index + 1) >= len(args):
                    return b"-ERR syntax error\r\n", False
                raw_value = args[index + 1]
                try:
                    parsed = int(raw_value)
                except ValueError:
                    return b"-ERR value is not an integer or out of range\r\n", False
                if option == "RANK":
                    if seen_rank:
                        return b"-ERR syntax error\r\n", False
                    seen_rank = True
                    if parsed == 0:
                        return b"-ERR RANK can't be zero\r\n", False
                    rank = parsed
                elif option == "COUNT":
                    if seen_count:
                        return b"-ERR syntax error\r\n", False
                    seen_count = True
                    if parsed < 0:
                        return b"-ERR COUNT can't be negative\r\n", False
                    count = parsed
                else:
                    if seen_maxlen:
                        return b"-ERR syntax error\r\n", False
                    seen_maxlen = True
                    if parsed < 0:
                        return b"-ERR MAXLEN can't be negative\r\n", False
                    maxlen = parsed
                index += 2
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._list_store.get(key)
                if not values:
                    if count is None:
                        return b"$-1\r\n", False
                    return b"*0\r\n", False
                scan_values = values if maxlen is None else values[:maxlen]
                matches = [idx for idx, value in enumerate(scan_values) if value == element]
            if not matches:
                if count is None:
                    return b"$-1\r\n", False
                return b"*0\r\n", False
            if rank > 0:
                start = rank - 1
                ordered_matches = matches
            else:
                start = abs(rank) - 1
                ordered_matches = list(reversed(matches))
            if start >= len(ordered_matches):
                if count is None:
                    return b"$-1\r\n", False
                return b"*0\r\n", False
            if count is None:
                return self._integer(ordered_matches[start]), False
            if count == 0:
                selected = ordered_matches[start:]
            else:
                selected = ordered_matches[start : start + count]
            return self._integer_array(selected), False

        if cmd == "RPOPLPUSH":
            if len(args) != 2:
                return b"-ERR wrong number of arguments for 'rpoplpush' command\r\n", False
            source, destination = args
            with self._store_lock:
                self._purge_expired_key_locked(source)
                self._purge_expired_key_locked(destination)
                if source in self._store or source in self._hash_store or source in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                if destination in self._store or destination in self._hash_store or destination in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                source_values = self._list_store.get(source)
                if not source_values:
                    return b"$-1\r\n", False
                value = source_values.pop()
                destination_values = self._list_store.setdefault(destination, [])
                destination_values.insert(0, value)
                if not source_values:
                    self._list_store.pop(source, None)
                    self._expirations.pop(source, None)
            return self._bulk(value), False

        if cmd == "LMOVE":
            if len(args) != 4:
                return b"-ERR wrong number of arguments for 'lmove' command\r\n", False
            source, destination, where_from_raw, where_to_raw = args
            where_from = where_from_raw.strip().upper()
            where_to = where_to_raw.strip().upper()
            if where_from not in {"LEFT", "RIGHT"} or where_to not in {"LEFT", "RIGHT"}:
                return b"-ERR syntax error\r\n", False
            with self._store_lock:
                self._purge_expired_key_locked(source)
                self._purge_expired_key_locked(destination)
                if source in self._store or source in self._hash_store or source in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                if destination in self._store or destination in self._hash_store or destination in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                source_values = self._list_store.get(source)
                if not source_values:
                    return b"$-1\r\n", False
                if where_from == "LEFT":
                    value = source_values.pop(0)
                else:
                    value = source_values.pop()
                destination_values = self._list_store.setdefault(destination, [])
                if where_to == "LEFT":
                    destination_values.insert(0, value)
                else:
                    destination_values.append(value)
                if not source_values:
                    self._list_store.pop(source, None)
                    self._expirations.pop(source, None)
            return self._bulk(value), False

        if cmd == "LINSERT":
            if len(args) != 4:
                return b"-ERR wrong number of arguments for 'linsert' command\r\n", False
            key, where_raw, pivot, element = args
            where = where_raw.strip().upper()
            if where not in {"BEFORE", "AFTER"}:
                return b"-ERR syntax error\r\n", False
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._list_store.get(key)
                if values is None:
                    return b":0\r\n", False
                updated_values = list(values)
                try:
                    pivot_index = updated_values.index(pivot)
                except ValueError:
                    return b":-1\r\n", False
                insert_index = pivot_index if where == "BEFORE" else pivot_index + 1
                updated_values.insert(insert_index, element)
                if not self._set_key_list_locked(key, updated_values):
                    return self._OOM_REPLY, False
            return self._integer(len(updated_values)), False

        if cmd == "LSET":
            if len(args) != 3:
                return b"-ERR wrong number of arguments for 'lset' command\r\n", False
            key = args[0]
            try:
                index = int(args[1])
            except ValueError:
                return b"-ERR value is not an integer or out of range\r\n", False
            element = args[2]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._list_store.get(key)
                if values is None:
                    return b"-ERR no such key\r\n", False
                normalized_index = index if index >= 0 else len(values) + index
                if normalized_index < 0 or normalized_index >= len(values):
                    return b"-ERR index out of range\r\n", False
                updated_values = list(values)
                updated_values[normalized_index] = element
                if not self._set_key_list_locked(key, updated_values):
                    return self._OOM_REPLY, False
            return b"+OK\r\n", False

        if cmd == "LTRIM":
            if len(args) != 3:
                return b"-ERR wrong number of arguments for 'ltrim' command\r\n", False
            key = args[0]
            try:
                start = int(args[1])
                stop = int(args[2])
            except ValueError:
                return b"-ERR value is not an integer or out of range\r\n", False
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._list_store.get(key)
                if values is None:
                    return b"+OK\r\n", False
                trimmed = self._list_range(values=values, start=start, stop=stop)
                if not trimmed:
                    self._list_store.pop(key, None)
                    self._expirations.pop(key, None)
                else:
                    self._list_store[key] = trimmed
            return b"+OK\r\n", False

        if cmd == "LREM":
            if len(args) != 3:
                return b"-ERR wrong number of arguments for 'lrem' command\r\n", False
            key = args[0]
            try:
                count = int(args[1])
            except ValueError:
                return b"-ERR value is not an integer or out of range\r\n", False
            element = args[2]
            with self._store_lock:
                self._purge_expired_key_locked(key)
                if key in self._store or key in self._hash_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                values = self._list_store.get(key)
                if not values:
                    return b":0\r\n", False
                removed = 0
                if count == 0:
                    kept = [value for value in values if value != element]
                    removed = len(values) - len(kept)
                    if kept:
                        self._list_store[key] = kept
                    else:
                        self._list_store.pop(key, None)
                        self._expirations.pop(key, None)
                    return self._integer(removed), False
                if count > 0:
                    kept: list[str] = []
                    for value in values:
                        if value == element and removed < count:
                            removed += 1
                            continue
                        kept.append(value)
                    if kept:
                        self._list_store[key] = kept
                    else:
                        self._list_store.pop(key, None)
                        self._expirations.pop(key, None)
                    return self._integer(removed), False
                target = abs(count)
                kept_reversed: list[str] = []
                for value in reversed(values):
                    if value == element and removed < target:
                        removed += 1
                        continue
                    kept_reversed.append(value)
                kept = list(reversed(kept_reversed))
                if kept:
                    self._list_store[key] = kept
                else:
                    self._list_store.pop(key, None)
                    self._expirations.pop(key, None)
            return self._integer(removed), False

        if cmd == "DEL":
            if not args:
                return b":0\r\n", False
            removed = 0
            with self._store_lock:
                for key in args:
                    self._purge_expired_key_locked(key)
                    if key in self._store or key in self._hash_store or key in self._list_store or key in self._set_store:
                        removed += 1
                        self._delete_key_locked(key)
            return self._integer(removed), False

        if cmd == "INCR":
            if len(args) != 1:
                return b"-ERR wrong number of arguments for 'incr' command\r\n", False
            with self._store_lock:
                key = args[0]
                self._purge_expired_key_locked(key)
                if key in self._hash_store or key in self._list_store or key in self._set_store:
                    return b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", False
                existing = self._store.get(key, "0")
                try:
                    value = int(existing)
                except ValueError:
                    return b"-ERR value is not an integer or out of range\r\n", False
                value += 1
                if not self._set_key_string_locked(key, str(value)):
                    return self._OOM_REPLY, False
            return self._integer(value), False

        if cmd == "EXPIRE":
            if len(args) != 2:
                return b"-ERR wrong number of arguments for 'expire' command\r\n", False
            try:
                ttl_seconds = int(args[1])
            except ValueError:
                return b"-ERR value is not an integer or out of range\r\n", False
            with self._store_lock:
                key = args[0]
                self._purge_expired_key_locked(key)
                if key not in self._store and key not in self._hash_store and key not in self._list_store and key not in self._set_store:
                    return b":0\r\n", False
                if ttl_seconds <= 0:
                    self._delete_key_locked(key)
                    return b":1\r\n", False
                self._expirations[key] = time.monotonic() + float(ttl_seconds)
            return b":1\r\n", False

        if cmd == "PERSIST":
            if len(args) != 1:
                return b"-ERR wrong number of arguments for 'persist' command\r\n", False
            with self._store_lock:
                key = args[0]
                self._purge_expired_key_locked(key)
                if key not in self._store and key not in self._hash_store and key not in self._list_store and key not in self._set_store:
                    return b":0\r\n", False
                if key not in self._expirations:
                    return b":0\r\n", False
                self._expirations.pop(key, None)
            return b":1\r\n", False

        if cmd == "TTL":
            if len(args) != 1:
                return b"-ERR wrong number of arguments for 'ttl' command\r\n", False
            with self._store_lock:
                key = args[0]
                self._purge_expired_key_locked(key)
                if key not in self._store and key not in self._hash_store and key not in self._list_store and key not in self._set_store:
                    return b":-2\r\n", False
                deadline = self._expirations.get(key)
                if deadline is None:
                    return b":-1\r\n", False
                remaining = int(deadline - time.monotonic())
            return self._integer(max(0, remaining)), False

        if cmd == "PTTL":
            if len(args) != 1:
                return b"-ERR wrong number of arguments for 'pttl' command\r\n", False
            with self._store_lock:
                key = args[0]
                self._purge_expired_key_locked(key)
                if key not in self._store and key not in self._hash_store and key not in self._list_store and key not in self._set_store:
                    return b":-2\r\n", False
                deadline = self._expirations.get(key)
                if deadline is None:
                    return b":-1\r\n", False
                remaining_ms = int((deadline - time.monotonic()) * 1000.0)
            return self._integer(max(0, remaining_ms)), False

        if cmd == "TYPE":
            if len(args) != 1:
                return b"-ERR wrong number of arguments for 'type' command\r\n", False
            with self._store_lock:
                key = args[0]
                self._purge_expired_key_locked(key)
                if key in self._store:
                    return b"+string\r\n", False
                if key in self._hash_store:
                    return b"+hash\r\n", False
                if key in self._list_store:
                    return b"+list\r\n", False
                if key in self._set_store:
                    return b"+set\r\n", False
            return b"+none\r\n", False

        if cmd == "EXISTS":
            with self._store_lock:
                for key in args:
                    self._purge_expired_key_locked(key)
                count = sum(
                    1
                    for key in args
                    if key in self._store or key in self._hash_store or key in self._list_store or key in self._set_store
                )
            return self._integer(count), False

        if cmd == "KEYS":
            pattern = args[0] if args else "*"
            with self._store_lock:
                self._purge_expired_locked()
                keys = set(self._store).union(self._hash_store).union(self._list_store).union(self._set_store)
                matches = [key for key in sorted(keys) if fnmatch(key, pattern)]
            return self._array(matches), False

        if cmd == "SCAN":
            if not args:
                return b"-ERR wrong number of arguments for 'scan' command\r\n", False
            try:
                cursor = int(args[0])
            except ValueError:
                return b"-ERR invalid cursor\r\n", False
            if cursor < 0:
                return b"-ERR invalid cursor\r\n", False
            pattern = "*"
            count = 10
            index = 1
            while index < len(args):
                option = args[index].upper()
                if option == "MATCH" and (index + 1) < len(args):
                    pattern = args[index + 1]
                    index += 2
                    continue
                if option == "COUNT" and (index + 1) < len(args):
                    try:
                        count = int(args[index + 1])
                    except ValueError:
                        return b"-ERR value is not an integer or out of range\r\n", False
                    index += 2
                    continue
                return b"-ERR syntax error\r\n", False
            bounded_count = max(1, min(1000, count))
            with self._store_lock:
                self._purge_expired_locked()
                keys = set(self._store).union(self._hash_store).union(self._list_store).union(self._set_store)
                matched_keys = [key for key in sorted(keys) if fnmatch(key, pattern)]
            if cursor >= len(matched_keys):
                return self._scan(0, []), False
            end = min(len(matched_keys), cursor + bounded_count)
            next_cursor = 0 if end >= len(matched_keys) else end
            return self._scan(next_cursor, matched_keys[cursor:end]), False

        if cmd == "DBSIZE":
            with self._store_lock:
                self._purge_expired_locked()
                size = len(set(self._store).union(self._hash_store).union(self._list_store).union(self._set_store))
            return self._integer(size), False

        if cmd == "INFO":
            info = (
                "# Server\r\n"
                f"redis_version:{self._server_version}\r\n"
                "os:Linux 5.15 x86_64\r\n"
                "# Clients\r\n"
                "connected_clients:12\r\n"
                "# Memory\r\n"
                "used_memory_human:3.12M\r\n"
                "# Stats\r\n"
                "total_connections_received:8423\r\n"
            )
            return self._bulk(info), False

        if cmd == "CLIENT" and args and args[0].upper() == "LIST":
            listing = "id=1142 addr=10.9.2.13:60312 laddr=10.9.2.5:6379 name= age=186 idle=0 flags=N db=0"
            return self._bulk(listing), False

        if cmd == "COMMAND":
            return b"*0\r\n", False

        if cmd == "CONFIG" and len(args) >= 1 and args[0].upper() == "GET":
            param = args[1] if len(args) > 1 else "*"
            if param in {"*", "maxmemory"}:
                return self._array(["maxmemory", str(self._MAX_TOTAL_STORE_BYTES)]), False
            return self._array([]), False

        if cmd == "FLUSHALL":
            with self._store_lock:
                self._store.clear()
                self._hash_store.clear()
                self._list_store.clear()
                self._set_store.clear()
                self._expirations.clear()
            return b"+OK\r\n", False

        if cmd == "QUIT":
            return b"+OK\r\n", True

        return f"-ERR unknown command '{cmd.lower()}'\r\n".encode("utf-8"), False

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
            "username": username,
            "password": password,
            "outcome": "success",
            "protocol": "redis",
        }
        self.runtime.session_manager.record_event(
            session_id=session_id,
            service=self.name,
            action="auth_attempt",
            payload=payload,
        )
        self.runtime.event_logger.emit(
            message="redis auth attempt",
            service=self.name,
            action="auth_attempt",
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            event_type="authentication",
            outcome="success",
            payload=payload,
        )

    def _record_command(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        command: list[str],
    ) -> None:
        if not self.runtime:
            return
        payload = {
            "source_ip": source_ip,
            "protocol": "redis",
            "command": command,
            "verb": command[0].upper() if command else "",
        }
        self.runtime.session_manager.record_event(
            session_id=session_id,
            service=self.name,
            action="command",
            payload=payload,
        )
        self.runtime.event_logger.emit(
            message="redis command",
            service=self.name,
            action="command",
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            event_type="info",
            outcome="success",
            payload=payload,
        )

    def _read_command(self, conn: socket.socket) -> list[str] | None:
        first = self._recv_exact(conn, 1)
        if not first:
            return None

        if first == b"*":
            return self._read_resp_array(conn)
        line_rest = self._recvline(conn)
        if line_rest is None:
            return None
        line = (first + line_rest).decode("utf-8", errors="replace").strip()
        if not line:
            return None
        return line.split()

    def _read_resp_array(self, conn: socket.socket) -> list[str] | None:
        count_line = self._recvline(conn)
        if count_line is None:
            return None
        try:
            count = int(count_line.decode("utf-8", errors="replace").strip())
        except ValueError:
            return None
        if count < 0 or count > self._MAX_RESP_ARRAY_ITEMS:
            return None

        items: list[str] = []
        for _ in range(count):
            prefix = self._recv_exact(conn, 1)
            if prefix != b"$":
                return None
            length_line = self._recvline(conn)
            if length_line is None:
                return None
            try:
                length = int(length_line.decode("utf-8", errors="replace").strip())
            except ValueError:
                return None
            if length < 0:
                items.append("")
                continue
            if length > self._MAX_RESP_BULK_BYTES:
                return None
            data = self._recv_exact(conn, length)
            if data is None:
                return None
            crlf = self._recv_exact(conn, 2)
            if crlf != b"\r\n":
                return None
            items.append(data.decode("utf-8", errors="replace"))
        return items

    @staticmethod
    def _recv_exact(conn: socket.socket, count: int) -> bytes | None:
        if count < 0 or count > Emulator._MAX_RECV_BYTES:
            return None
        data = bytearray()
        try:
            while len(data) < count:
                chunk = conn.recv(count - len(data))
                if not chunk:
                    return None
                data.extend(chunk)
        except (TimeoutError, OSError):
            return None
        return bytes(data)

    @staticmethod
    def _recvline(conn: socket.socket, limit: int = 4096) -> bytes | None:
        data = bytearray()
        try:
            while len(data) < limit:
                byte = conn.recv(1)
                if not byte:
                    return None
                data.extend(byte)
                if len(data) >= 2 and data[-2:] == b"\r\n":
                    return bytes(data[:-2])
        except (TimeoutError, OSError):
            return None
        return None

    @staticmethod
    def _bulk(value: str) -> bytes:
        encoded = value.encode("utf-8")
        return f"${len(encoded)}\r\n".encode("utf-8") + encoded + b"\r\n"

    @staticmethod
    def _integer(value: int) -> bytes:
        return f":{value}\r\n".encode("utf-8")

    @staticmethod
    def _array(items: list[str]) -> bytes:
        payload = [f"*{len(items)}\r\n".encode("utf-8")]
        for item in items:
            encoded = item.encode("utf-8")
            payload.append(f"${len(encoded)}\r\n".encode("utf-8"))
            payload.append(encoded + b"\r\n")
        return b"".join(payload)

    @staticmethod
    def _integer_array(items: list[int]) -> bytes:
        payload = [f"*{len(items)}\r\n".encode("utf-8")]
        for item in items:
            payload.append(f":{item}\r\n".encode("utf-8"))
        return b"".join(payload)

    @staticmethod
    def _bulk_array(items: list[str | None]) -> bytes:
        payload = [f"*{len(items)}\r\n".encode("utf-8")]
        for item in items:
            if item is None:
                payload.append(b"$-1\r\n")
                continue
            encoded = item.encode("utf-8")
            payload.append(f"${len(encoded)}\r\n".encode("utf-8"))
            payload.append(encoded + b"\r\n")
        return b"".join(payload)

    @staticmethod
    def _scan(cursor: int, items: list[str]) -> bytes:
        return b"*2\r\n" + Emulator._bulk(str(max(0, int(cursor)))) + Emulator._array(items)

    @staticmethod
    def _list_range(*, values: list[str], start: int, stop: int) -> list[str]:
        length = len(values)
        if length == 0:
            return []
        normalized_start = start if start >= 0 else length + start
        normalized_stop = stop if stop >= 0 else length + stop
        normalized_start = max(0, normalized_start)
        if normalized_stop < 0:
            return []
        normalized_stop = min(length - 1, normalized_stop)
        if normalized_start >= length or normalized_stop < normalized_start:
            return []
        return values[normalized_start : normalized_stop + 1]

    @staticmethod
    def _encoded_len(value: str) -> int:
        return len(value.encode("utf-8"))

    @classmethod
    def _hash_usage_bytes(cls, mapping: dict[str, str]) -> int:
        return sum(cls._encoded_len(field) + cls._encoded_len(value) for field, value in mapping.items())

    @classmethod
    def _list_usage_bytes(cls, values: list[str]) -> int:
        return sum(cls._encoded_len(value) for value in values)

    @classmethod
    def _set_usage_bytes(cls, values: set[str]) -> int:
        return sum(cls._encoded_len(value) for value in values)

    def _key_usage_bytes_locked(self, key: str) -> int:
        if key in self._store:
            return self._encoded_len(self._store[key])
        if key in self._hash_store:
            return self._hash_usage_bytes(self._hash_store[key])
        if key in self._list_store:
            return self._list_usage_bytes(self._list_store[key])
        if key in self._set_store:
            return self._set_usage_bytes(self._set_store[key])
        return 0

    def _total_store_bytes_locked(self) -> int:
        return (
            sum(self._encoded_len(value) for value in self._store.values())
            + sum(self._hash_usage_bytes(values) for values in self._hash_store.values())
            + sum(self._list_usage_bytes(values) for values in self._list_store.values())
            + sum(self._set_usage_bytes(values) for values in self._set_store.values())
        )

    def _fits_key_updates_locked(self, updates: dict[str, int]) -> bool:
        if not updates:
            return True
        current_total = self._total_store_bytes_locked()
        current_usage = sum(self._key_usage_bytes_locked(key) for key in updates)
        projected_total = current_total - current_usage + sum(max(0, int(size)) for size in updates.values())
        return projected_total <= self._MAX_TOTAL_STORE_BYTES

    def _set_key_string_locked(self, key: str, value: str, *, clear_expiration: bool = False) -> bool:
        if not self._fits_key_updates_locked({key: self._encoded_len(value)}):
            return False
        self._store[key] = value
        self._hash_store.pop(key, None)
        self._list_store.pop(key, None)
        self._set_store.pop(key, None)
        if clear_expiration:
            self._expirations.pop(key, None)
        return True

    def _set_key_hash_locked(self, key: str, values: dict[str, str], *, clear_expiration: bool = False) -> bool:
        usage = self._hash_usage_bytes(values)
        if not self._fits_key_updates_locked({key: usage}):
            return False
        if values:
            self._hash_store[key] = dict(values)
        else:
            self._hash_store.pop(key, None)
        self._store.pop(key, None)
        self._list_store.pop(key, None)
        self._set_store.pop(key, None)
        if clear_expiration:
            self._expirations.pop(key, None)
        return True

    def _set_key_list_locked(self, key: str, values: list[str], *, clear_expiration: bool = False) -> bool:
        usage = self._list_usage_bytes(values)
        if not self._fits_key_updates_locked({key: usage}):
            return False
        if values:
            self._list_store[key] = list(values)
        else:
            self._list_store.pop(key, None)
        self._store.pop(key, None)
        self._hash_store.pop(key, None)
        self._set_store.pop(key, None)
        if clear_expiration:
            self._expirations.pop(key, None)
        return True

    def _set_key_set_locked(self, key: str, values: set[str], *, clear_expiration: bool = False) -> bool:
        usage = self._set_usage_bytes(values)
        if not self._fits_key_updates_locked({key: usage}):
            return False
        if values:
            self._set_store[key] = set(values)
        else:
            self._set_store.pop(key, None)
        self._store.pop(key, None)
        self._hash_store.pop(key, None)
        self._list_store.pop(key, None)
        if clear_expiration:
            self._expirations.pop(key, None)
        return True

    def _delete_key_locked(self, key: str) -> None:
        self._store.pop(key, None)
        self._hash_store.pop(key, None)
        self._list_store.pop(key, None)
        self._set_store.pop(key, None)
        self._expirations.pop(key, None)

    def _purge_expired_locked(self) -> None:
        if not self._expirations:
            return
        now = time.monotonic()
        expired = [key for key, deadline in self._expirations.items() if deadline <= now]
        for key in expired:
            self._delete_key_locked(key)

    def _purge_expired_key_locked(self, key: str) -> None:
        deadline = self._expirations.get(key)
        if deadline is None:
            return
        if deadline <= time.monotonic():
            self._delete_key_locked(key)
