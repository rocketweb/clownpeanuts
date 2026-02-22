"""HTTP admin-panel emulator with credential capture."""

from __future__ import annotations

import html
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4
from collections import OrderedDict

from clownpeanuts.config.schema import ServiceConfig
from clownpeanuts.core.logging import get_logger
from clownpeanuts.services.base import ServiceEmulator
from clownpeanuts.tarpit.infinite_exfil import InfiniteExfilConfig, InfiniteExfilStream
from clownpeanuts.tarpit.slowdrip import SlowDripProfile


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
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
    _LOGIN_ROUTES = {
        "/wp-login.php",
        "/admin",
        "/dashboard",
        "/internal",
        "/phpmyadmin",
        "/wp-admin",
        "/k8s/dashboard",
    }
    _MAX_POST_BODY_BYTES = 65_536
    _MAX_AUTH_ATTEMPTS_TRACKED = 10_000

    def __init__(self) -> None:
        super().__init__()
        self.logger = get_logger("clownpeanuts.services.http")
        self._config: ServiceConfig | None = None
        self._server: _BoundedThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._bound_host: str | None = None
        self._bound_port: int | None = None
        self._server_name = "Apache/2.4.54 (Ubuntu)"
        self._max_concurrent_connections = 256
        self._tarpit_enabled = True
        self._backup_stream_chunks = 40
        self._backup_chunk_size_bytes = 512
        self._slowdrip_min_delay_ms = 80
        self._slowdrip_max_delay_ms = 250
        self._slowdrip_jitter_ratio = 0.0
        self._infinite_exfil_enabled = True
        self._infinite_exfil_path = "/backup/live.sql.gz"
        self._infinite_exfil_chunk_size_bytes = 768
        self._infinite_exfil_max_chunks = 0
        self._auth_failures_before_success = 0
        self._auth_delay_pattern_ms: list[int] = [120, 450, 900]
        self._auth_delay_jitter_ratio = 0.15
        self._query_tarpit_enabled = True
        self._query_tarpit_min_delay_ms = 120
        self._query_tarpit_max_delay_ms = 700
        self._query_tarpit_jitter_ratio = 0.2
        self._query_tarpit_max_page_size = 50
        self._query_tarpit_estimated_total = 4200
        self._auth_attempts: OrderedDict[str, int] = OrderedDict()
        self._auth_attempts_lock = threading.RLock()
        self._slowdrip_profile = SlowDripProfile(
            min_delay_ms=self._slowdrip_min_delay_ms,
            max_delay_ms=self._slowdrip_max_delay_ms,
            jitter_ratio=self._slowdrip_jitter_ratio,
        )
        self._query_tarpit_profile = SlowDripProfile(
            min_delay_ms=self._query_tarpit_min_delay_ms,
            max_delay_ms=self._query_tarpit_max_delay_ms,
            jitter_ratio=self._query_tarpit_jitter_ratio,
        )

    @property
    def name(self) -> str:
        return "http_admin"

    @property
    def default_ports(self) -> list[int]:
        return [80, 8080]

    @property
    def config_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "server_name": {"type": "string"},
                "max_concurrent_connections": {"type": "integer", "minimum": 1, "maximum": 5000},
                "tarpit_enabled": {"type": "boolean"},
                "backup_stream_chunks": {"type": "integer", "minimum": 1, "maximum": 10000},
                "backup_chunk_size_bytes": {"type": "integer", "minimum": 64, "maximum": 4096},
                "slowdrip_min_delay_ms": {"type": "integer", "minimum": 0, "maximum": 2000},
                "slowdrip_max_delay_ms": {"type": "integer", "minimum": 0, "maximum": 5000},
                "slowdrip_jitter_ratio": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "infinite_exfil_enabled": {"type": "boolean"},
                "infinite_exfil_path": {"type": "string"},
                "infinite_exfil_chunk_size_bytes": {"type": "integer", "minimum": 64, "maximum": 8192},
                "infinite_exfil_max_chunks": {"type": "integer", "minimum": 0, "maximum": 1000000},
                "auth_failures_before_success": {"type": "integer", "minimum": 0, "maximum": 10},
                "auth_delay_pattern_ms": {"type": "array", "items": {"type": "integer", "minimum": 0, "maximum": 30000}},
                "auth_delay_jitter_ratio": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "query_tarpit_enabled": {"type": "boolean"},
                "query_tarpit_min_delay_ms": {"type": "integer", "minimum": 0, "maximum": 10000},
                "query_tarpit_max_delay_ms": {"type": "integer", "minimum": 0, "maximum": 20000},
                "query_tarpit_jitter_ratio": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "query_tarpit_max_page_size": {"type": "integer", "minimum": 1, "maximum": 2000},
                "query_tarpit_estimated_total": {"type": "integer", "minimum": 1, "maximum": 10000000},
            },
        }

    def apply_runtime_config(self, config: ServiceConfig) -> None:
        self._server_name = str(config.config.get("server_name", self._server_name))
        self._max_concurrent_connections = max(
            1,
            int(config.config.get("max_concurrent_connections", self._max_concurrent_connections)),
        )
        self._tarpit_enabled = bool(config.config.get("tarpit_enabled", self._tarpit_enabled))
        self._backup_stream_chunks = max(1, int(config.config.get("backup_stream_chunks", self._backup_stream_chunks)))
        self._backup_chunk_size_bytes = max(
            64, int(config.config.get("backup_chunk_size_bytes", self._backup_chunk_size_bytes))
        )
        self._slowdrip_min_delay_ms = max(0, int(config.config.get("slowdrip_min_delay_ms", self._slowdrip_min_delay_ms)))
        self._slowdrip_max_delay_ms = max(
            self._slowdrip_min_delay_ms,
            int(config.config.get("slowdrip_max_delay_ms", self._slowdrip_max_delay_ms)),
        )
        self._slowdrip_jitter_ratio = max(
            0.0,
            min(1.0, float(config.config.get("slowdrip_jitter_ratio", self._slowdrip_jitter_ratio))),
        )
        self._infinite_exfil_enabled = bool(config.config.get("infinite_exfil_enabled", self._infinite_exfil_enabled))
        self._infinite_exfil_path = str(config.config.get("infinite_exfil_path", self._infinite_exfil_path)).strip()
        if not self._infinite_exfil_path.startswith("/"):
            self._infinite_exfil_path = f"/{self._infinite_exfil_path}" if self._infinite_exfil_path else "/backup/live.sql.gz"
        self._infinite_exfil_chunk_size_bytes = max(
            64,
            int(config.config.get("infinite_exfil_chunk_size_bytes", self._infinite_exfil_chunk_size_bytes)),
        )
        self._infinite_exfil_max_chunks = max(
            0,
            int(config.config.get("infinite_exfil_max_chunks", self._infinite_exfil_max_chunks)),
        )
        self._auth_failures_before_success = max(
            0,
            int(config.config.get("auth_failures_before_success", self._auth_failures_before_success)),
        )
        auth_delay_pattern_raw = config.config.get("auth_delay_pattern_ms", self._auth_delay_pattern_ms)
        if isinstance(auth_delay_pattern_raw, list):
            parsed_pattern = [max(0, int(item)) for item in auth_delay_pattern_raw]
            if parsed_pattern:
                self._auth_delay_pattern_ms = parsed_pattern
        self._auth_delay_jitter_ratio = max(
            0.0,
            min(1.0, float(config.config.get("auth_delay_jitter_ratio", self._auth_delay_jitter_ratio))),
        )
        self._query_tarpit_enabled = bool(config.config.get("query_tarpit_enabled", self._query_tarpit_enabled))
        self._query_tarpit_min_delay_ms = max(
            0,
            int(config.config.get("query_tarpit_min_delay_ms", self._query_tarpit_min_delay_ms)),
        )
        self._query_tarpit_max_delay_ms = max(
            self._query_tarpit_min_delay_ms,
            int(config.config.get("query_tarpit_max_delay_ms", self._query_tarpit_max_delay_ms)),
        )
        self._query_tarpit_jitter_ratio = max(
            0.0,
            min(1.0, float(config.config.get("query_tarpit_jitter_ratio", self._query_tarpit_jitter_ratio))),
        )
        self._query_tarpit_max_page_size = max(
            1,
            int(config.config.get("query_tarpit_max_page_size", self._query_tarpit_max_page_size)),
        )
        self._query_tarpit_estimated_total = max(
            1,
            int(config.config.get("query_tarpit_estimated_total", self._query_tarpit_estimated_total)),
        )
        self._slowdrip_profile = SlowDripProfile(
            min_delay_ms=self._slowdrip_min_delay_ms,
            max_delay_ms=self._slowdrip_max_delay_ms,
            jitter_ratio=self._slowdrip_jitter_ratio,
        )
        self._query_tarpit_profile = SlowDripProfile(
            min_delay_ms=self._query_tarpit_min_delay_ms,
            max_delay_ms=self._query_tarpit_max_delay_ms,
            jitter_ratio=self._query_tarpit_jitter_ratio,
        )

    async def start(self, config: ServiceConfig) -> None:
        self._config = config
        self.apply_runtime_config(config)
        host = config.listen_host
        port = config.ports[0] if config.ports else self.default_ports[1]
        self._server = _BoundedThreadingHTTPServer(
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
                message="http admin service started",
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
        with self._auth_attempts_lock:
            self._auth_attempts.clear()
        self.running = False
        self.logger.info("service stopped", extra={"service": self.name})
        if self.runtime:
            self.runtime.event_logger.emit(
                message="http admin service stopped",
                service=self.name,
                action="service_stop",
                event_type="end",
            )

    async def handle_connection(self, conn: dict[str, Any]) -> dict[str, Any]:
        method = str(conn.get("method", "GET")).upper()
        path = str(conn.get("path", "/"))
        parsed_path = urlsplit(path)
        route = parsed_path.path or "/"
        query_params = self._query_params(parsed_path.query)
        source_ip = str(conn.get("source_ip", "127.0.0.1"))
        source_port = int(conn.get("source_port", 0))
        session_id = str(conn.get("session_id", f"http-{uuid4().hex}"))
        payload = dict(conn.get("payload", {}))
        status = 404
        body = "Not Found"
        narrative = self._resolve_narrative_context(
            session_id=session_id,
            source_ip=source_ip,
            route=route,
            method=method,
        )
        selected_lure_arm = self._select_lure_arm(
            session_id=session_id,
            source_ip=source_ip,
            route=route,
            method=method,
        )

        if self.runtime:
            self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)

        if method == "GET":
            if route == "/backup.sql.gz" and self._tarpit_enabled:
                planned_bytes = self._backup_stream_chunks * self._backup_chunk_size_bytes
                self._record_access(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    method=method,
                    path=route,
                    status=200,
                )
                self._record_tarpit(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    path=route,
                    chunks_sent=self._backup_stream_chunks,
                    bytes_sent=planned_bytes,
                    completed=True,
                )
                return {
                    "service": self.name,
                    "status": 200,
                    "body": f"streaming backup tarpit: {self._backup_stream_chunks} chunks / {planned_bytes} bytes",
                }
            if route == self._infinite_exfil_path and self._tarpit_enabled and self._infinite_exfil_enabled:
                planned_chunks = self._infinite_exfil_max_chunks
                planned_bytes = planned_chunks * self._infinite_exfil_chunk_size_bytes
                self._record_access(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    method=method,
                    path=route,
                    status=200,
                )
                self._record_tarpit(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    path=route,
                    chunks_sent=planned_chunks,
                    bytes_sent=planned_bytes,
                    completed=planned_chunks > 0,
                    mode="infinite_exfil",
                )
                mode = "bounded" if planned_chunks > 0 else "unbounded"
                return {
                    "service": self.name,
                    "status": 200,
                    "body": f"streaming infinite exfil tarpit ({mode})",
                }
            status, body, _ = self._route_get(
                route,
                query_params=query_params,
                narrative=narrative,
                lure_arm=selected_lure_arm,
            )
            self._record_access(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                method=method,
                path=route,
                status=status,
            )
        elif method == "POST":
            status, body, credentials = self._route_post(
                route,
                payload,
                session_id=session_id,
                narrative=narrative,
                lure_arm=selected_lure_arm,
            )
            self._record_access(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                method=method,
                path=route,
                status=status,
            )
            if credentials:
                self._record_credentials(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    path=route,
                    username=credentials["username"],
                    password=credentials["password"],
                    outcome=credentials.get("outcome", "success"),
                )

        return {"service": self.name, "status": status, "body": body}

    def inject_activity(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.runtime is None:
            return {
                "accepted": False,
                "service": self.name,
                "reason": "runtime not initialized",
            }
        activity_type = str(payload.get("type", "http_request")).strip().lower()
        if activity_type not in {"http_request", "web_request", "browser_session"}:
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
        session_id = str(payload.get("session_id", f"http-injected-{uuid4().hex[:12]}")).strip()
        if not session_id:
            session_id = f"http-injected-{uuid4().hex[:12]}"
        method = str(payload.get("method", "GET")).strip().upper() or "GET"
        path = str(payload.get("path", "/internal")).strip() or "/internal"
        try:
            status = int(payload.get("status", 200) or 200)
        except (TypeError, ValueError):
            status = 200
        status = max(100, min(599, status))

        self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
        self._record_access(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            method=method,
            path=path,
            status=status,
        )

        details = payload.get("payload")
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", "")).strip()
        outcome = str(payload.get("outcome", "success")).strip().lower() or "success"
        if isinstance(details, dict):
            username = str(details.get("username", username)).strip()
            password = str(details.get("password", password)).strip()
            outcome = str(details.get("outcome", outcome)).strip().lower() or "success"
        if username and password:
            self._record_credentials(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                path=path,
                username=username,
                password=password,
                outcome=outcome,
            )

        return {
            "accepted": True,
            "service": self.name,
            "activity_type": activity_type,
            "session_id": session_id,
            "method": method,
            "path": path,
            "status": status,
            "credential_capture": bool(username and password),
        }

    @property
    def bound_endpoint(self) -> tuple[str, int] | None:
        if self._bound_host is None or self._bound_port is None:
            return None
        return (self._bound_host, self._bound_port)

    def _build_handler(self) -> type[BaseHTTPRequestHandler]:
        emulator = self

        class AdminHandler(BaseHTTPRequestHandler):
            server_version = "nginx/1.18.0"
            sys_version = ""

            def do_GET(self) -> None:  # noqa: N802
                emulator._handle_http(self, "GET")

            def do_POST(self) -> None:  # noqa: N802
                emulator._handle_http(self, "POST")

            def log_message(self, format: str, *args: Any) -> None:
                return

        return AdminHandler

    def _handle_http(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        parsed = urlsplit(handler.path)
        route = parsed.path or "/"
        query_params = self._query_params(parsed.query)
        source_ip, source_port = handler.client_address
        session_id, set_cookie = self._session_id_for_request(handler, source_ip)
        if self.runtime:
            self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
        narrative = self._resolve_narrative_context(
            session_id=session_id,
            source_ip=source_ip,
            route=route,
            method=method,
        )
        selected_lure_arm = self._select_lure_arm(
            session_id=session_id,
            source_ip=source_ip,
            route=route,
            method=method,
        )

        if method == "GET":
            if route == "/backup.sql.gz" and self._tarpit_enabled:
                bytes_sent, chunks_sent, completed = self._respond_backup_stream(
                    handler=handler,
                    set_cookie=session_id if set_cookie else None,
                )
                self._record_access(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    method=method,
                    path=route,
                    status=200,
                )
                self._record_tarpit(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    path=route,
                    chunks_sent=chunks_sent,
                    bytes_sent=bytes_sent,
                    completed=completed,
                )
                return
            if route == self._infinite_exfil_path and self._tarpit_enabled and self._infinite_exfil_enabled:
                bytes_sent, chunks_sent, completed = self._respond_infinite_exfil_stream(
                    handler=handler,
                    set_cookie=session_id if set_cookie else None,
                )
                self._record_access(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    method=method,
                    path=route,
                    status=200,
                )
                self._record_tarpit(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    path=route,
                    chunks_sent=chunks_sent,
                    bytes_sent=bytes_sent,
                    completed=completed,
                    mode="infinite_exfil",
                )
                return

            status, body, content_type = self._route_get(
                route,
                query_params=query_params,
                narrative=narrative,
                lure_arm=selected_lure_arm,
            )
            self._respond(
                handler=handler,
                status=status,
                body=body,
                content_type=content_type,
                set_cookie=session_id if set_cookie else None,
            )
            self._record_access(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                method=method,
                path=route,
                status=status,
            )
            return

        content_length = self._bounded_content_length(handler.headers.get("Content-Length"), self._MAX_POST_BODY_BYTES)
        raw_body = handler.rfile.read(content_length).decode("utf-8", errors="replace")
        form = {key: values[0] for key, values in parse_qs(raw_body).items()}
        status, body, credentials = self._route_post(
            route,
            form,
            session_id=session_id,
            narrative=narrative,
            lure_arm=selected_lure_arm,
        )
        self._respond(
            handler=handler,
            status=status,
            body=body,
            content_type="text/html; charset=utf-8",
            set_cookie=session_id if set_cookie else None,
        )
        self._record_access(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            method=method,
            path=route,
            status=status,
        )
        if credentials:
            self._record_credentials(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                path=route,
                username=credentials["username"],
                password=credentials["password"],
                outcome=credentials.get("outcome", "success"),
            )

    @staticmethod
    def _bounded_content_length(raw_value: str | None, maximum: int) -> int:
        if maximum <= 0:
            return 0
        try:
            parsed = int(str(raw_value or "0").strip() or 0)
        except ValueError:
            return 0
        if parsed <= 0:
            return 0
        return min(parsed, maximum)

    def _respond(
        self,
        *,
        handler: BaseHTTPRequestHandler,
        status: int,
        body: str,
        content_type: str,
        set_cookie: str | None,
    ) -> None:
        encoded = body.encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(encoded)))
        handler.send_header("Server", self._server_name)
        if set_cookie:
            handler.send_header("Set-Cookie", f"CPSESSID={set_cookie}; Path=/; HttpOnly")
        handler.end_headers()
        handler.wfile.write(encoded)

    def _respond_backup_stream(
        self,
        *,
        handler: BaseHTTPRequestHandler,
        set_cookie: str | None,
    ) -> tuple[int, int, bool]:
        handler.send_response(200)
        handler.send_header("Content-Type", "application/octet-stream")
        handler.send_header("Server", self._server_name)
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Content-Disposition", 'attachment; filename="backup.sql.gz"')
        if set_cookie:
            handler.send_header("Set-Cookie", f"CPSESSID={set_cookie}; Path=/; HttpOnly")
        handler.end_headers()

        total_bytes = 0
        sent_chunks = 0
        for index in range(self._backup_stream_chunks):
            chunk = self._build_backup_chunk(index)
            try:
                handler.wfile.write(chunk)
                handler.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                return (total_bytes, sent_chunks, False)
            total_bytes += len(chunk)
            sent_chunks += 1
            if index < self._backup_stream_chunks - 1:
                time.sleep(self._slowdrip_delay_seconds())
        return (total_bytes, sent_chunks, True)

    def _respond_infinite_exfil_stream(
        self,
        *,
        handler: BaseHTTPRequestHandler,
        set_cookie: str | None,
    ) -> tuple[int, int, bool]:
        handler.send_response(200)
        handler.send_header("Content-Type", "application/octet-stream")
        handler.send_header("Server", self._server_name)
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Content-Disposition", 'attachment; filename="backup-live.sql.gz"')
        if set_cookie:
            handler.send_header("Set-Cookie", f"CPSESSID={set_cookie}; Path=/; HttpOnly")
        handler.end_headers()

        stream = InfiniteExfilStream(
            InfiniteExfilConfig(
                chunk_size_bytes=self._infinite_exfil_chunk_size_bytes,
                max_chunks=self._infinite_exfil_max_chunks,
            )
        )
        total_bytes = 0
        sent_chunks = 0
        for chunk in stream.iter_chunks():
            try:
                handler.wfile.write(chunk)
                handler.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                return (total_bytes, sent_chunks, False)
            total_bytes += len(chunk)
            sent_chunks += 1
            time.sleep(self._slowdrip_delay_seconds())
        return (total_bytes, sent_chunks, True)

    def _build_backup_chunk(self, index: int) -> bytes:
        prefix = (
            f"-- chunk {index + 1}\n"
            f"INSERT INTO users VALUES({index + 1},'admin{index}','admin{index}@acme.local');\n"
        ).encode("utf-8")
        if len(prefix) >= self._backup_chunk_size_bytes:
            return prefix[: self._backup_chunk_size_bytes]
        padding_size = self._backup_chunk_size_bytes - len(prefix)
        return prefix + (b"x" * padding_size)

    def _slowdrip_delay_seconds(self) -> float:
        return self._slowdrip_profile.next_delay_seconds()

    def _session_id_for_request(self, handler: BaseHTTPRequestHandler, source_ip: str) -> tuple[str, bool]:
        header = handler.headers.get("Cookie", "")
        jar = cookies.SimpleCookie()
        jar.load(header)
        token = jar.get("CPSESSID")
        if token and token.value:
            return token.value, False
        return f"http-{source_ip}-{uuid4().hex[:12]}", True

    @staticmethod
    def _query_params(raw_query: str) -> dict[str, str]:
        parsed = parse_qs(raw_query, keep_blank_values=True)
        params: dict[str, str] = {}
        for key, values in parsed.items():
            if not key:
                continue
            if not values:
                params[key] = ""
                continue
            params[key] = str(values[0])
        return params

    def _resolve_narrative_context(
        self,
        *,
        session_id: str,
        source_ip: str,
        route: str,
        method: str,
    ) -> dict[str, Any]:
        if not self.runtime or not self.runtime.rabbit_hole:
            return {}
        return self.runtime.rabbit_hole.resolve_narrative_context(
            session_id=session_id,
            source_ip=source_ip,
            tenant_id=self.runtime.tenant_id,
            service=self.name,
            action=f"{method.lower()}_{route}",
            hints={"route": route, "method": method.upper()},
        )

    def _select_lure_arm(
        self,
        *,
        session_id: str,
        source_ip: str,
        route: str,
        method: str,
    ) -> str:
        if not self.runtime or not callable(self.runtime.bandit_select):
            return ""
        context_key = f"http:{self._route_category(route)}:{method.lower()}"
        candidates = ["http-baseline", "http-query-bait", "http-backup-bait"]
        try:
            decision = self.runtime.bandit_select(context_key=context_key, candidates=candidates)
        except Exception:
            return ""
        if not isinstance(decision, dict):
            return ""
        selected_raw = decision.get("selected_arm")
        selected_arm = str(selected_raw).strip() if selected_raw is not None else ""
        payload = {
            "source_ip": source_ip,
            "context_key": context_key,
            "route": route,
            "method": method,
            "selected_arm": selected_arm,
            "candidates": candidates,
        }
        self.runtime.session_manager.record_event(
            session_id=session_id,
            service=self.name,
            action="lure_arm_selection",
            payload=payload,
        )
        self.runtime.event_logger.emit(
            message="http lure arm selection",
            service=self.name,
            action="lure_arm_selection",
            session_id=session_id,
            source_ip=source_ip,
            event_type="info",
            outcome="success" if selected_arm else "partial",
            payload=payload,
        )
        return selected_arm

    @staticmethod
    def _route_category(route: str) -> str:
        normalized = route.strip().lower()
        if normalized.startswith("/api/") or normalized.startswith("/internal/api/"):
            return "api"
        if "backup" in normalized or normalized.endswith(".sql.gz"):
            return "backup"
        if normalized in {"/wp-login.php", "/wp-admin", "/admin", "/dashboard", "/internal", "/phpmyadmin"}:
            return "auth"
        return "generic"

    @staticmethod
    def _narrative_focus_label(
        narrative: dict[str, Any] | None,
        *,
        kind: str,
        default: str,
    ) -> str:
        if not isinstance(narrative, dict):
            return default
        focus = narrative.get("focus", {})
        if not isinstance(focus, dict):
            return default
        payload = focus.get(kind, {})
        if not isinstance(payload, dict):
            return default
        label = str(payload.get("label", "")).strip()
        return html.escape(label, quote=True) if label else default

    def _route_get(
        self,
        route: str,
        query_params: dict[str, str] | None = None,
        narrative: dict[str, Any] | None = None,
        lure_arm: str = "",
    ) -> tuple[int, str, str]:
        if route in {"/", "/admin", "/dashboard", "/internal"}:
            return (200, self._generic_admin_login(route, narrative=narrative), "text/html; charset=utf-8")
        if route in {"/wp-login.php", "/wp-admin"}:
            return (200, self._wordpress_login(narrative=narrative), "text/html; charset=utf-8")
        if route == "/phpmyadmin":
            return (200, self._phpmyadmin_login(), "text/html; charset=utf-8")
        if route == "/robots.txt":
            return (200, "User-agent: *\nDisallow: /internal\nDisallow: /.git/\n", "text/plain; charset=utf-8")
        if route == "/.env":
            return (
                200,
                "APP_ENV=production\nDB_HOST=mysql.internal\nDB_USER=wp_admin\nDB_PASS=Str0ngP@ss!\n",
                "text/plain; charset=utf-8",
            )
        if route == "/.git/config":
            return (
                200,
                "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = git@github.com:acme/intranet.git\n",
                "text/plain; charset=utf-8",
            )
        if route == "/wp-config.php.bak":
            return (
                200,
                "<?php\ndefine('DB_NAME', 'wordpress');\ndefine('DB_USER', 'wp_admin');\ndefine('DB_PASSWORD', 'Str0ngP@ss!');\n",
                "text/plain; charset=utf-8",
            )
        if route in {"/s3", "/s3/", "/s3/buckets"}:
            return (200, self._s3_bucket_listing(), "application/xml; charset=utf-8")
        if route in {"/api/internal/orders", "/internal/api/orders"}:
            return (200, self._internal_api_orders(narrative=narrative, lure_arm=lure_arm), "application/json; charset=utf-8")
        if route in {"/api/internal/users", "/internal/api/users"}:
            return (
                200,
                self._internal_api_users(query_params or {}, narrative=narrative),
                "application/json; charset=utf-8",
            )
        if route in {"/api/internal/login-audit", "/internal/api/login-audit"}:
            return (
                200,
                self._internal_api_login_audit(query_params or {}, narrative=narrative),
                "application/json; charset=utf-8",
            )
        if route in {"/api/internal/search", "/internal/api/search"}:
            return (
                200,
                self._internal_api_search(query_params or {}, narrative=narrative),
                "application/json; charset=utf-8",
            )
        if route in {"/k8s/dashboard", "/kubernetes/dashboard"}:
            return (200, self._k8s_dashboard_login(), "text/html; charset=utf-8")
        return (404, self._not_found(), "text/html; charset=utf-8")

    def _route_post(
        self,
        route: str,
        form: dict[str, Any],
        *,
        session_id: str,
        narrative: dict[str, Any] | None = None,
        lure_arm: str = "",
    ) -> tuple[int, str, dict[str, str] | None]:
        if route not in self._LOGIN_ROUTES:
            return (404, self._not_found(), None)

        username = self._first_value(
            form,
            ["log", "username", "user", "pma_username", "email", "login"],
            default="admin",
        )
        password = self._first_value(
            form,
            ["pwd", "password", "pass", "pma_password"],
            default="password123",
        )
        if self._auth_should_reject(session_id):
            delay = self._auth_delay_seconds(session_id)
            if delay > 0:
                time.sleep(delay)
            with self._auth_attempts_lock:
                if session_id in self._auth_attempts:
                    self._auth_attempts[session_id] = self._auth_attempts.get(session_id, 0) + 1
                    self._auth_attempts.move_to_end(session_id)
                else:
                    if len(self._auth_attempts) >= self._MAX_AUTH_ATTEMPTS_TRACKED:
                        self._auth_attempts.popitem(last=False)
                    self._auth_attempts[session_id] = 1
            return (
                401,
                self._auth_failed_view(username=username, route=route),
                {"username": username, "password": password, "outcome": "failure"},
            )
        return (
            200,
            self._dashboard_view(username=username, route=route, narrative=narrative, lure_arm=lure_arm),
            {"username": username, "password": password, "outcome": "success"},
        )

    @staticmethod
    def _first_value(form: dict[str, Any], keys: list[str], default: str) -> str:
        for key in keys:
            value = form.get(key)
            if isinstance(value, list) and value:
                return str(value[0])
            if value:
                return str(value)
        return default

    def _record_access(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        method: str,
        path: str,
        status: int,
    ) -> None:
        if not self.runtime:
            return
        payload = {
            "source_ip": source_ip,
            "method": method,
            "path": path,
            "status_code": status,
        }
        self.runtime.session_manager.record_event(
            session_id=session_id,
            service=self.name,
            action="http_request",
            payload=payload,
        )
        self.runtime.event_logger.emit(
            message="http request",
            service=self.name,
            action="http_request",
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            outcome="success" if status < 400 else "failure",
            event_type="access",
            payload=payload,
        )

    def _record_credentials(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        path: str,
        username: str,
        password: str,
        outcome: str = "success",
    ) -> None:
        if not self.runtime:
            return
        normalized_outcome = outcome if outcome in {"success", "failure"} else "success"
        payload = {
            "source_ip": source_ip,
            "path": path,
            "username": username,
            "password": password,
            "outcome": normalized_outcome,
        }
        self.runtime.session_manager.record_event(
            session_id=session_id,
            service=self.name,
            action="credential_capture",
            payload=payload,
        )
        self.runtime.event_logger.emit(
            message="http credential captured",
            service=self.name,
            action="credential_capture",
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            outcome=normalized_outcome,
            event_type="authentication",
            payload=payload,
        )

    def _record_tarpit(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        path: str,
        chunks_sent: int,
        bytes_sent: int,
        completed: bool,
        mode: str = "slowdrip",
    ) -> None:
        if not self.runtime:
            return
        payload = {
            "source_ip": source_ip,
            "path": path,
            "chunks_sent": chunks_sent,
            "bytes_sent": bytes_sent,
            "completed": completed,
            "mode": mode,
        }
        self.runtime.session_manager.record_event(
            session_id=session_id,
            service=self.name,
            action="tarpit_stream",
            payload=payload,
        )
        self.runtime.event_logger.emit(
            message="http tarpit stream",
            service=self.name,
            action="tarpit_stream",
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            outcome="success" if completed else "partial",
            event_type="info",
            payload=payload,
        )

    @staticmethod
    def _int_value(raw: str | None, *, default: int, minimum: int = 0, maximum: int = 1_000_000) -> int:
        if raw is None:
            return default
        text = raw.strip()
        if not text:
            return default
        try:
            value = int(text)
        except ValueError:
            return default
        return max(minimum, min(maximum, value))

    def _auth_should_reject(self, session_id: str) -> bool:
        if self._auth_failures_before_success <= 0:
            return False
        with self._auth_attempts_lock:
            attempts = self._auth_attempts.get(session_id, 0)
        return attempts < self._auth_failures_before_success

    def _auth_delay_seconds(self, session_id: str) -> float:
        with self._auth_attempts_lock:
            attempts = self._auth_attempts.get(session_id, 0)
        if not self._auth_delay_pattern_ms:
            return 0.0
        index = min(max(0, attempts), len(self._auth_delay_pattern_ms) - 1)
        base_ms = max(0, int(self._auth_delay_pattern_ms[index]))
        if base_ms <= 0:
            return 0.0
        min_ms = int(base_ms * max(0.0, 1.0 - self._auth_delay_jitter_ratio))
        max_ms = int(base_ms * max(1.0, 1.0 + self._auth_delay_jitter_ratio))
        profile = SlowDripProfile(
            min_delay_ms=max(0, min_ms),
            max_delay_ms=max(max(0, min_ms), max_ms),
            jitter_ratio=0.0,
        )
        return profile.next_delay_seconds()

    def _query_tarpit_delay_seconds(self, *, query: str, page: int, page_size: int) -> float:
        if not self._query_tarpit_enabled:
            return 0.0
        base = self._query_tarpit_profile.next_delay_seconds()
        if base <= 0:
            return 0.0
        complexity = 1.0
        complexity += min(2.0, float(max(0, page - 1)) * 0.14)
        complexity += min(1.5, float(max(1, page_size)) / 30.0)
        lowered = query.lower()
        if "*" in query or "%" in query:
            complexity += 0.4
        if any(token in lowered for token in ("like", "select", "where", "join")):
            complexity += 0.35
        return base * complexity

    def _internal_api_search(
        self,
        query_params: dict[str, str],
        *,
        narrative: dict[str, Any] | None = None,
    ) -> str:
        query = str(query_params.get("q", query_params.get("query", ""))).strip() or "*"
        page = self._int_value(query_params.get("page"), default=1, minimum=1, maximum=100_000)
        page_size = self._int_value(query_params.get("page_size"), default=25, minimum=1, maximum=500)
        page_size = min(page_size, self._query_tarpit_max_page_size)
        narrative_service = self._narrative_focus_label(narrative, kind="service", default="billing")
        narrative_dataset = self._narrative_focus_label(narrative, kind="dataset", default="customer_orders")
        narrative_ticket = self._narrative_focus_label(narrative, kind="ticket", default="OPS-1042")

        delay = self._query_tarpit_delay_seconds(query=query, page=page, page_size=page_size)
        if delay > 0:
            time.sleep(delay)

        total_estimate = self._query_tarpit_estimated_total + min(2_500, len(query) * 90)
        start_index = max(0, (page - 1) * page_size)
        if start_index >= total_estimate:
            result_count = 0
        else:
            result_count = min(page_size, total_estimate - start_index)

        rows: list[dict[str, object]] = []
        for offset in range(result_count):
            record_id = start_index + offset + 1
            rows.append(
                {
                    "record_id": record_id,
                    "account_id": f"ACCT-{record_id:06d}",
                    "email": f"user{record_id}@acme.local",
                    "status": "active" if (record_id % 4) else "pending",
                    "risk_score": (record_id % 97) + 1,
                    "service": narrative_service,
                    "dataset": narrative_dataset,
                }
            )

        next_page = page + 1 if start_index + result_count < total_estimate else None
        payload = {
            "status": "ok",
            "query": query,
            "narrative": {
                "service": narrative_service,
                "dataset": narrative_dataset,
                "ticket": narrative_ticket,
            },
            "page": page,
            "page_size": page_size,
            "total_estimate": total_estimate,
            "next_page": next_page,
            "results": rows,
        }
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True)

    def _internal_api_users(
        self,
        query_params: dict[str, str],
        *,
        narrative: dict[str, Any] | None = None,
    ) -> str:
        query = str(query_params.get("q", query_params.get("query", ""))).strip().lower()
        role_filter_raw = str(query_params.get("role", "")).strip().lower()
        status_filter_raw = str(query_params.get("status", "")).strip().lower()
        page = self._int_value(query_params.get("page"), default=1, minimum=1, maximum=100_000)
        page_size = self._int_value(query_params.get("page_size"), default=20, minimum=1, maximum=500)
        page_size = min(page_size, self._query_tarpit_max_page_size)

        query_seed = " ".join(part for part in (query, role_filter_raw, status_filter_raw) if part) or "*"
        delay = self._query_tarpit_delay_seconds(query=query_seed, page=page, page_size=page_size)
        if delay > 0:
            time.sleep(delay)

        allowed_roles = {"admin", "analyst", "ops", "support"}
        allowed_statuses = {"active", "locked", "disabled"}
        role_filter = role_filter_raw if role_filter_raw in allowed_roles else ""
        status_filter = status_filter_raw if status_filter_raw in allowed_statuses else ""

        total_estimate = 320 + min(900, len(query_seed) * 22)
        if role_filter:
            total_estimate = max(page_size, total_estimate - 75)
        if status_filter:
            total_estimate = max(page_size, total_estimate - 55)

        start_index = max(0, (page - 1) * page_size)
        if start_index >= total_estimate:
            result_count = 0
        else:
            result_count = min(page_size, total_estimate - start_index)

        role_cycle = ["admin", "analyst", "ops", "support"]
        status_cycle = ["active", "active", "locked", "disabled"]
        users: list[dict[str, object]] = []
        for offset in range(result_count):
            row_id = start_index + offset + 1
            role = role_filter or role_cycle[(row_id - 1) % len(role_cycle)]
            status = status_filter or status_cycle[(row_id - 1) % len(status_cycle)]
            username = f"{role}{(row_id % 47) + 1:02d}"
            email = f"{username}@acme.local"
            if query and query not in username and query not in email and query not in role:
                username = f"{query.replace(' ', '_')[:16] or role}{(row_id % 47) + 1:02d}"
                email = f"{username}@acme.local"
            users.append(
                {
                    "user_id": f"USR-{row_id:05d}",
                    "username": username,
                    "email": email,
                    "role": role,
                    "status": status,
                    "last_login": (
                        f"2026-02-{((row_id - 1) % 28) + 1:02d}T{(row_id % 24):02d}:{(row_id * 7) % 60:02d}:11Z"
                    ),
                    "mfa_enabled": bool(row_id % 3),
                    "owner_service": self._narrative_focus_label(narrative, kind="service", default="ops-portal"),
                }
            )

        next_page = page + 1 if start_index + result_count < total_estimate else None
        payload = {
            "status": "ok",
            "filters": {
                "query": query,
                "role": role_filter or None,
                "status": status_filter or None,
            },
            "page": page,
            "page_size": page_size,
            "total_estimate": total_estimate,
            "next_page": next_page,
            "users": users,
        }
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True)

    def _internal_api_login_audit(
        self,
        query_params: dict[str, str],
        *,
        narrative: dict[str, Any] | None = None,
    ) -> str:
        username_filter = str(query_params.get("username", query_params.get("user", ""))).strip()
        status_filter_raw = str(query_params.get("status", "all")).strip().lower()
        limit = self._int_value(query_params.get("limit"), default=25, minimum=1, maximum=500)
        limit = min(limit, self._query_tarpit_max_page_size)
        cursor = self._int_value(query_params.get("cursor"), default=0, minimum=0, maximum=1_000_000)

        query_seed = " ".join(part for part in (username_filter.lower(), status_filter_raw) if part) or "*"
        delay = self._query_tarpit_delay_seconds(
            query=query_seed,
            page=(cursor // max(1, limit)) + 1,
            page_size=limit,
        )
        if delay > 0:
            time.sleep(delay)

        status_filter = status_filter_raw if status_filter_raw in {"success", "failure"} else "all"
        total_estimate = 1800
        rows: list[dict[str, object]] = []
        for offset in range(limit):
            sequence = cursor + offset + 1
            if sequence > total_estimate:
                break
            outcome = "failure" if (sequence % 3 == 0) else "success"
            if status_filter != "all":
                outcome = status_filter
            username = username_filter or f"ops{(sequence % 19) + 1:02d}"
            rows.append(
                {
                    "event_id": f"AUTH-{sequence:07d}",
                    "username": username,
                    "status": outcome,
                    "source_ip": f"203.0.113.{(sequence % 220) + 10}",
                    "path": ["/wp-login.php", "/admin", "/k8s/dashboard"][sequence % 3],
                    "user_agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        f"AppleWebKit/537.36 ClownProbe/{(sequence % 5) + 1}.0"
                    ),
                    "ticket": self._narrative_focus_label(narrative, kind="ticket", default="OPS-1042"),
                    "timestamp": (
                        f"2026-02-{((sequence - 1) % 28) + 1:02d}T{(sequence % 24):02d}:{(sequence * 11) % 60:02d}:42Z"
                    ),
                }
            )

        next_cursor = cursor + len(rows)
        payload = {
            "status": "ok",
            "filters": {
                "username": username_filter or None,
                "status": status_filter,
            },
            "cursor": cursor,
            "limit": limit,
            "next_cursor": next_cursor if next_cursor < total_estimate else None,
            "total_estimate": total_estimate,
            "records": rows,
        }
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True)

    @staticmethod
    def _auth_failed_view(*, username: str, route: str) -> str:
        safe_username = html.escape(username, quote=True)
        safe_route = html.escape(route, quote=True)
        return f"""<!doctype html>
<html><head><title>Admin Portal</title></head>
<body style='font-family:Helvetica,sans-serif;background:#f9fafb;padding:24px'>
  <div style='max-width:420px;background:#fff;border:1px solid #ddd;padding:20px'>
    <h2>Internal Portal</h2>
    <p style='color:#b42318'>Invalid credentials for {safe_username}. Try again.</p>
    <form method='post' action='{safe_route}'>
      <label>Username</label><input name='username' />
      <label>Password</label><input type='password' name='password' />
      <button type='submit'>Sign In</button>
    </form>
  </div>
</body></html>"""

    def _wordpress_login(self, *, narrative: dict[str, Any] | None = None) -> str:
        narrative_project = self._narrative_focus_label(narrative, kind="service", default="core-cms")
        return f"""<!doctype html>
<html><head><title>WordPress \u203a Log In</title></head>
<body style='font-family:Arial,sans-serif;background:#f0f0f1;padding:32px'>
  <div style='max-width:360px;margin:0 auto;background:#fff;border:1px solid #dcdcde;padding:24px'>
    <h1 style='margin-top:0'>WordPress</h1>
    <p style='margin-top:0;color:#555'>Site profile: {narrative_project}</p>
    <form method='post' action='/wp-login.php'>
      <label>Username or Email Address</label><input name='log' style='width:100%;margin:8px 0' />
      <label>Password</label><input type='password' name='pwd' style='width:100%;margin:8px 0' />
      <button type='submit'>Log In</button>
    </form>
  </div>
</body></html>"""

    @staticmethod
    def _phpmyadmin_login() -> str:
        return """<!doctype html>
<html><head><title>phpMyAdmin</title></head>
<body style='font-family:Verdana,sans-serif;background:#eef2f8;padding:24px'>
  <h2>phpMyAdmin</h2>
  <form method='post' action='/phpmyadmin'>
    <label>Username</label><input name='pma_username' />
    <label>Password</label><input type='password' name='pma_password' />
    <button type='submit'>Log in</button>
  </form>
</body></html>"""

    def _generic_admin_login(self, route: str, *, narrative: dict[str, Any] | None = None) -> str:
        narrative_ticket = self._narrative_focus_label(narrative, kind="ticket", default="OPS-1042")
        safe_route = html.escape(route, quote=True)
        return f"""<!doctype html>
<html><head><title>Admin Portal</title></head>
<body style='font-family:Helvetica,sans-serif;background:#f9fafb;padding:24px'>
  <div style='max-width:420px;background:#fff;border:1px solid #ddd;padding:20px'>
    <h2>Internal Portal</h2>
    <p>Path: {safe_route}</p>
    <p>Pending ticket: {narrative_ticket}</p>
    <form method='post' action='{safe_route}'>
      <label>Username</label><input name='username' />
      <label>Password</label><input type='password' name='password' />
      <button type='submit'>Sign In</button>
    </form>
  </div>
</body></html>"""

    def _dashboard_view(
        self,
        *,
        username: str,
        route: str,
        narrative: dict[str, Any] | None = None,
        lure_arm: str = "",
    ) -> str:
        narrative_service = self._narrative_focus_label(narrative, kind="service", default="ops-portal")
        narrative_dataset = self._narrative_focus_label(narrative, kind="dataset", default="incident_timeline")
        safe_username = html.escape(username, quote=True)
        safe_route = html.escape(route, quote=True)
        safe_lure_arm = html.escape(lure_arm, quote=True)
        lure_line = f"<li>Lure profile: {safe_lure_arm}</li>" if safe_lure_arm else ""
        return f"""<!doctype html>
<html><head><title>Admin Dashboard</title></head>
<body style='font-family:Arial,sans-serif;background:#fff;padding:24px'>
  <h1>Welcome back, {safe_username}</h1>
  <p>Authenticated via {safe_route}</p>
  <ul>
    <li>Server Health: nominal</li>
    <li>Active service: {narrative_service}</li>
    <li>Data profile: {narrative_dataset}</li>
    {lure_line}
    <li>Queued backups: 2</li>
    <li>Recent login anomalies: 1</li>
  </ul>
</body></html>"""

    @staticmethod
    def _s3_bucket_listing() -> str:
        return """<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Buckets>
    <Bucket><Name>acme-prod-backups</Name></Bucket>
    <Bucket><Name>customer-import-staging</Name></Bucket>
    <Bucket><Name>finance-quarterly-exports</Name></Bucket>
  </Buckets>
</ListAllMyBucketsResult>"""

    def _internal_api_orders(self, *, narrative: dict[str, Any] | None = None, lure_arm: str = "") -> str:
        narrative_dataset = self._narrative_focus_label(narrative, kind="dataset", default="customer_orders")
        payload = {
            "status": "ok",
            "dataset": narrative_dataset,
            "lure_profile": lure_arm,
            "orders": [
                {"id": "ORD-10238", "email": "jessica.adams@acme.local", "total": 482.11, "state": "paid"},
                {"id": "ORD-10239", "email": "mike.yu@acme.local", "total": 119.04, "state": "pending"},
            ],
        }
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True)

    @staticmethod
    def _k8s_dashboard_login() -> str:
        return """<!doctype html>
<html><head><title>Kubernetes Dashboard</title></head>
<body style='font-family:Arial,sans-serif;background:#f8fafc;padding:30px'>
  <div style='max-width:420px;margin:auto;background:#fff;border:1px solid #dbe2ea;padding:24px'>
    <h2>Kubernetes Dashboard</h2>
    <form method='post' action='/k8s/dashboard'>
      <label>Username</label><input name='username' style='width:100%;margin:8px 0' />
      <label>Password</label><input type='password' name='password' style='width:100%;margin:8px 0' />
      <button type='submit'>Sign in</button>
    </form>
  </div>
</body></html>"""

    @staticmethod
    def _not_found() -> str:
        return "<html><body><h1>404 Not Found</h1></body></html>"
