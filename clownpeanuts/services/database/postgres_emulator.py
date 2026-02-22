"""PostgreSQL-protocol honeypot emulator with credential and query capture."""

from __future__ import annotations

from datetime import UTC, datetime
import socket
import socketserver
import struct
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


_SSL_REQUEST_CODE = 80877103
_PROTOCOL_VERSION_3 = 196608


class Emulator(ServiceEmulator):
    _MAX_MESSAGE_SIZE_BYTES = 1_048_576
    _MAX_PREPARED_STATEMENTS = 1000

    def __init__(self) -> None:
        super().__init__()
        self.logger = get_logger("clownpeanuts.services.database.postgres")
        self._server: _ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._bound_host: str | None = None
        self._bound_port: int | None = None
        self._socket_timeout_seconds = 45.0
        self._server_version = "15.4-clownpeanuts"
        self._max_concurrent_connections = 256
        self._pid_counter = 42000
        self._pid_lock = threading.Lock()
        self._tarpit = AdaptiveThrottle(service_name=self.name)

    @property
    def name(self) -> str:
        return "postgres_db"

    @property
    def default_ports(self) -> list[int]:
        return [5432, 15432]

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
                message="postgres emulator started",
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
                message="postgres emulator stopped",
                service=self.name,
                action="service_stop",
                event_type="end",
            )

    async def handle_connection(self, conn: dict[str, Any]) -> dict[str, Any]:
        username = str(conn.get("username", "postgres"))
        password = str(conn.get("password", "postgres"))
        database = str(conn.get("database", username))
        query = str(conn.get("query", "SELECT 1"))
        source_ip = str(conn.get("source_ip", "127.0.0.1"))
        source_port = int(conn.get("source_port", 0))
        session_id = str(conn.get("session_id", f"postgres-{uuid4().hex}"))

        if self.runtime:
            self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
            self._record_auth(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                username=username,
                database=database,
                password=password,
            )
            self._record_query(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                query=query,
            )

        return {
            "service": self.name,
            "session_id": session_id,
            "username": username,
            "database": database,
            "query": query,
            "status": "ok",
        }

    def inject_activity(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.runtime is None:
            return {
                "accepted": False,
                "service": self.name,
                "reason": "runtime not initialized",
            }
        activity_type = str(payload.get("type", "database_query")).strip().lower()
        if activity_type not in {"database_query", "sql_query", "query"}:
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
        session_id = str(payload.get("session_id", f"postgres-injected-{uuid4().hex[:12]}")).strip()
        if not session_id:
            session_id = f"postgres-injected-{uuid4().hex[:12]}"
        username = str(payload.get("username", "app")).strip() or "app"
        password = str(payload.get("password", "injected-password")).strip() or "injected-password"
        database = str(payload.get("database", "postgres")).strip() or "postgres"
        self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
        self._record_auth(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            database=database,
            password=password,
        )

        queries_raw = payload.get("queries")
        queries: list[str] = []
        if isinstance(queries_raw, list):
            queries.extend([str(item).strip() for item in queries_raw if str(item).strip()])
        query_value = str(payload.get("query", "")).strip()
        if query_value:
            queries.append(query_value)
        details = payload.get("payload")
        if isinstance(details, dict):
            nested_queries = details.get("queries")
            if isinstance(nested_queries, list):
                queries.extend([str(item).strip() for item in nested_queries if str(item).strip()])
            nested_query = str(details.get("query", "")).strip()
            if nested_query:
                queries.append(nested_query)
        if not queries:
            queries = ["SELECT 1"]

        for query in queries[:120]:
            self._record_query(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                query=query,
            )
        return {
            "accepted": True,
            "service": self.name,
            "activity_type": activity_type,
            "session_id": session_id,
            "query_count": len(queries[:120]),
        }

    @property
    def bound_endpoint(self) -> tuple[str, int] | None:
        if self._bound_host is None or self._bound_port is None:
            return None
        return (self._bound_host, self._bound_port)

    def _build_handler(self) -> type[socketserver.BaseRequestHandler]:
        emulator = self

        class PostgresHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                emulator._handle_client(self.request, self.client_address)

        return PostgresHandler

    def _handle_client(self, conn: socket.socket, client_address: tuple[str, int]) -> None:
        conn.settimeout(self._socket_timeout_seconds)
        source_ip, source_port = client_address
        session_id = f"postgres-{source_ip}-{uuid4().hex[:12]}"
        if self.runtime:
            self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
            self.runtime.event_logger.emit(
                message="postgres connection opened",
                service=self.name,
                action="connection_open",
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                event_type="access",
                outcome="success",
            )

        startup = self._read_startup_packet(conn)
        if startup is None:
            return
        startup_params = self._parse_startup_params(startup)
        username = startup_params.get("user", "postgres")
        database = startup_params.get("database", username)

        self._send_message(conn, b"R", struct.pack("!I", 3))  # AuthenticationCleartextPassword
        password = self._read_password_message(conn)
        if password is None:
            return

        self._record_auth(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            database=database,
            password=password,
        )
        self._tarpit.maybe_delay(
            runtime=self.runtime,
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            trigger="postgres_auth_response",
        )

        self._send_message(conn, b"R", struct.pack("!I", 0))  # AuthenticationOk
        self._send_message(conn, b"S", self._cstring("server_version") + self._cstring(self._server_version))
        self._send_message(conn, b"S", self._cstring("client_encoding") + self._cstring("UTF8"))
        self._send_message(conn, b"S", self._cstring("DateStyle") + self._cstring("ISO, MDY"))
        pid = self._next_pid()
        self._send_message(conn, b"K", struct.pack("!II", pid, 912341))
        self._send_ready(conn)
        prepared_statements: dict[str, str] = {}
        bound_portals: dict[str, str] = {}

        while True:
            message = self._read_message(conn)
            if message is None:
                return
            message_type, payload = message
            if message_type == b"X":  # Terminate
                return
            if message_type == b"Q":
                query = payload[:-1].decode("utf-8", errors="replace") if payload else ""
                self._record_query(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    query=query,
                )
                self._tarpit.maybe_delay(
                    runtime=self.runtime,
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    trigger="postgres_query_response",
                )
                self._respond_query(
                    conn,
                    query=query,
                    session_id=session_id,
                    source_ip=source_ip,
                    current_database=database,
                )
                continue
            if message_type == b"P":  # Parse
                parsed = self._parse_parse_message(payload)
                if parsed is None:
                    self._send_error(conn, "malformed parse message")
                    continue
                statement_name, prepared_query = parsed
                if (
                    statement_name not in prepared_statements
                    and len(prepared_statements) >= self._MAX_PREPARED_STATEMENTS
                ):
                    self._send_error(conn, "too many prepared statements")
                    continue
                prepared_statements[statement_name] = prepared_query
                self._send_message(conn, b"1", b"")  # ParseComplete
                continue
            if message_type == b"B":  # Bind
                parsed = self._parse_bind_message(payload)
                if parsed is None:
                    self._send_error(conn, "malformed bind message")
                    continue
                portal_name, statement_name = parsed
                prepared_query = prepared_statements.get(statement_name)
                if prepared_query is None:
                    self._send_error(conn, f"unknown prepared statement '{statement_name}'")
                    continue
                bound_portals[portal_name] = prepared_query
                self._send_message(conn, b"2", b"")  # BindComplete
                continue
            if message_type == b"D":  # Describe
                self._send_message(conn, b"n", b"")  # NoData
                continue
            if message_type == b"E":  # Execute
                parsed = self._parse_execute_message(payload)
                if parsed is None:
                    self._send_error(conn, "malformed execute message")
                    continue
                portal_name, _max_rows = parsed
                prepared_query = bound_portals.get(portal_name, bound_portals.get("", ""))
                if not prepared_query:
                    self._send_error(conn, f"unknown portal '{portal_name}'")
                    continue
                self._record_query(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    query=f"EXECUTE {portal_name or '<unnamed>'}: {prepared_query}",
                )
                self._tarpit.maybe_delay(
                    runtime=self.runtime,
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    trigger="postgres_query_response",
                )
                self._respond_query(
                    conn,
                    query=prepared_query,
                    session_id=session_id,
                    source_ip=source_ip,
                    current_database=database,
                    send_ready=False,
                )
                continue
            if message_type == b"S":  # Sync
                self._send_ready(conn)
                continue
            if message_type == b"C":  # Close
                parsed = self._parse_close_message(payload)
                if parsed is None:
                    self._send_error(conn, "malformed close message")
                    continue
                close_kind, close_name = parsed
                if close_kind == "S":
                    prepared_statements.pop(close_name, None)
                if close_kind == "P":
                    bound_portals.pop(close_name, None)
                self._send_message(conn, b"3", b"")  # CloseComplete
                continue
            if message_type == b"H":  # Flush
                continue
            self._tarpit.maybe_delay(
                runtime=self.runtime,
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                trigger="postgres_error_response",
            )
            self._send_error(conn, "unsupported message type")
            self._send_ready(conn)

    def _respond_query(
        self,
        conn: socket.socket,
        *,
        query: str,
        session_id: str,
        source_ip: str,
        current_database: str = "postgres",
        send_ready: bool = True,
    ) -> None:
        lower = query.strip().lower()
        normalized = " ".join(lower.rstrip(";").split())
        selected_lure_arm = self._select_lure_arm(
            session_id=session_id,
            source_ip=source_ip,
            query=normalized or query,
        )
        rabbit_value = "1"
        narrative_db = "appdb"
        narrative_tables = ["users", "orders", "audit_events", "feature_flags"]
        if self.runtime and self.runtime.rabbit_hole:
            command = normalized.split(" ", 1)[0] if normalized else "query"
            result = self.runtime.rabbit_hole.respond_database_command(
                service=self.name,
                session_id=session_id,
                source_ip=source_ip,
                command=command,
                document={"query": query},
                tenant_id=self.runtime.tenant_id,
            )
            rabbit_value = self._rabbit_row_value(result)
            narrative_context = self.runtime.rabbit_hole.resolve_narrative_context(
                session_id=session_id,
                source_ip=source_ip,
                tenant_id=self.runtime.tenant_id,
                service=self.name,
                action=command,
                hints={"query": query},
            )
            narrative_db, narrative_tables = self._narrative_identifiers(narrative_context)

        if normalized in {"show server_version", "select version()"}:
            self._send_result_set(
                conn=conn,
                columns=["version"],
                rows=[[self._server_version]],
                command_tag="SELECT 1",
                send_ready=send_ready,
            )
            return

        if normalized == "show search_path":
            self._send_result_set(
                conn=conn,
                columns=["search_path"],
                rows=[['"$user", public']],
                command_tag="SHOW",
                send_ready=send_ready,
            )
            return

        if normalized == "show timezone":
            self._send_result_set(
                conn=conn,
                columns=["TimeZone"],
                rows=[["UTC"]],
                command_tag="SHOW",
                send_ready=send_ready,
            )
            return

        if normalized == "show wal_level":
            self._send_result_set(
                conn=conn,
                columns=["wal_level"],
                rows=[["replica"]],
                command_tag="SHOW",
                send_ready=send_ready,
            )
            return

        if normalized == "show max_wal_senders":
            self._send_result_set(
                conn=conn,
                columns=["max_wal_senders"],
                rows=[["10"]],
                command_tag="SHOW",
                send_ready=send_ready,
            )
            return

        if normalized == "show application_name":
            self._send_result_set(
                conn=conn,
                columns=["application_name"],
                rows=[["psql"]],
                command_tag="SHOW",
                send_ready=send_ready,
            )
            return

        if normalized in {"select current_user", "select session_user"}:
            self._send_result_set(
                conn=conn,
                columns=["current_user"],
                rows=[["postgres"]],
                command_tag="SELECT 1",
                send_ready=send_ready,
            )
            return

        if normalized in {"select current_schema()", "select current_schema"}:
            self._send_result_set(
                conn=conn,
                columns=["current_schema"],
                rows=[["public"]],
                command_tag="SELECT 1",
                send_ready=send_ready,
            )
            return

        if normalized in {"select current_database()", "select current_database"}:
            self._send_result_set(
                conn=conn,
                columns=["current_database"],
                rows=[[current_database or "postgres"]],
                command_tag="SELECT 1",
                send_ready=send_ready,
            )
            return

        if normalized in {"select inet_server_addr()", "select inet_server_addr"}:
            self._send_result_set(
                conn=conn,
                columns=["inet_server_addr"],
                rows=[["10.41.12.17"]],
                command_tag="SELECT 1",
                send_ready=send_ready,
            )
            return

        if normalized in {"select inet_server_port()", "select inet_server_port"}:
            self._send_result_set(
                conn=conn,
                columns=["inet_server_port"],
                rows=[["5432"]],
                command_tag="SELECT 1",
                send_ready=send_ready,
            )
            return

        if normalized in {"select pg_is_in_recovery()", "select pg_is_in_recovery"}:
            self._send_result_set(
                conn=conn,
                columns=["pg_is_in_recovery"],
                rows=[["f"]],
                command_tag="SELECT 1",
                send_ready=send_ready,
            )
            return

        if "current_setting('server_version_num')" in normalized:
            self._send_result_set(
                conn=conn,
                columns=["current_setting"],
                rows=[["150004"]],
                command_tag="SELECT 1",
                send_ready=send_ready,
            )
            return

        if normalized in {"select now()", "select current_timestamp"}:
            now_value = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S%z")
            self._send_result_set(
                conn=conn,
                columns=["now"],
                rows=[[now_value]],
                command_tag="SELECT 1",
                send_ready=send_ready,
            )
            return

        if normalized in {"select usename from pg_user", "select rolname from pg_roles"}:
            column_name = "usename" if "pg_user" in normalized else "rolname"
            self._send_result_set(
                conn=conn,
                columns=[column_name],
                rows=[["postgres"], ["app_rw"], ["app_ro"]],
                command_tag="SELECT 3",
                send_ready=send_ready,
            )
            return

        if "from pg_roles" in normalized and any(token in normalized for token in ("rolsuper", "rolcanlogin", "rolname")):
            self._send_result_set(
                conn=conn,
                columns=["rolname", "rolsuper", "rolcanlogin"],
                rows=[
                    ["postgres", "t", "t"],
                    ["app_rw", "f", "t"],
                    ["app_ro", "f", "t"],
                    ["replication", "f", "f"],
                ],
                command_tag="SELECT 4",
                send_ready=send_ready,
            )
            return

        if "from pg_namespace" in normalized:
            self._send_result_set(
                conn=conn,
                columns=["nspname"],
                rows=[["pg_catalog"], ["information_schema"], ["public"], ["audit"]],
                command_tag="SELECT 4",
                send_ready=send_ready,
            )
            return

        if "from pg_extension" in normalized:
            self._send_result_set(
                conn=conn,
                columns=["extname", "extversion"],
                rows=[["plpgsql", "1.0"], ["pg_stat_statements", "1.10"]],
                command_tag="SELECT 2",
                send_ready=send_ready,
            )
            return

        if "from pg_settings" in normalized:
            self._send_result_set(
                conn=conn,
                columns=["name", "setting", "unit"],
                rows=[
                    ["max_connections", "200", ""],
                    ["shared_buffers", "16384", "8kB"],
                    ["log_statement", "ddl", ""],
                ],
                command_tag="SELECT 3",
                send_ready=send_ready,
            )
            return

        if normalized == "select datname from pg_database":
            candidates = ["postgres", "template1", "template0", current_database or "postgres", narrative_db]
            if selected_lure_arm == "postgres-query-bait":
                candidates.append("archive_shadow")
            rows: list[list[str]] = []
            seen: set[str] = set()
            for candidate in candidates:
                if candidate in seen:
                    continue
                seen.add(candidate)
                rows.append([candidate])
            self._send_result_set(
                conn=conn,
                columns=["datname"],
                rows=rows,
                command_tag="SELECT 4",
                send_ready=send_ready,
            )
            return

        if "from pg_catalog.pg_tables" in normalized or "from pg_tables" in normalized:
            if "schemaname" in normalized and "tablename" in normalized:
                rows = [["public", item] for item in narrative_tables]
                columns = ["schemaname", "tablename"]
            else:
                rows = [[item] for item in narrative_tables]
                columns = ["tablename"]
            self._send_result_set(
                conn=conn,
                columns=columns,
                rows=rows,
                command_tag=f"SELECT {len(rows)}",
                send_ready=send_ready,
            )
            return

        if "from information_schema.tables" in normalized:
            self._send_result_set(
                conn=conn,
                columns=["table_name"],
                rows=[[item] for item in narrative_tables],
                command_tag="SELECT 4",
                send_ready=send_ready,
            )
            return

        if "from information_schema.columns" in normalized:
            table_filter = self._extract_filter_value(normalized=normalized, key="table_name")
            relation = self._clean_identifier(table_filter or (narrative_tables[0] if narrative_tables else "users"))
            rows = [
                ["public", relation, column_name, data_type]
                for column_name, data_type in self._relation_columns(relation_name=relation)
            ]
            self._send_result_set(
                conn=conn,
                columns=["table_schema", "table_name", "column_name", "data_type"],
                rows=rows,
                command_tag=f"SELECT {len(rows)}",
                send_ready=send_ready,
            )
            return

        if "from pg_indexes" in normalized or "from pg_catalog.pg_indexes" in normalized:
            table_filter = self._extract_filter_value(normalized=normalized, key="tablename")
            relation = self._clean_identifier(table_filter or (narrative_tables[0] if narrative_tables else "users"))
            rows = [
                [f"{relation}_pkey", f"CREATE INDEX {relation}_pkey ON {relation} USING btree (id)"],
                [f"{relation}_updated_idx", f"CREATE INDEX {relation}_updated_idx ON {relation} USING btree (updated_at)"],
            ]
            self._send_result_set(
                conn=conn,
                columns=["indexname", "indexdef"],
                rows=rows,
                command_tag="SELECT 2",
                send_ready=send_ready,
            )
            return

        if "from pg_stat_activity" in normalized or "from pg_catalog.pg_stat_activity" in normalized:
            rows = [
                [
                    "42101",
                    "postgres",
                    "psql",
                    source_ip,
                    "active",
                    "2026-02-20 10:12:44+00",
                    "select * from users limit 50",
                ],
                [
                    "42102",
                    "app_rw",
                    "jdbc",
                    "10.41.12.18",
                    "idle",
                    "2026-02-20 10:11:08+00",
                    "commit",
                ],
            ]
            self._send_result_set(
                conn=conn,
                columns=["pid", "usename", "application_name", "client_addr", "state", "query_start", "query"],
                rows=rows,
                command_tag=f"SELECT {len(rows)}",
                send_ready=send_ready,
            )
            return

        if "from pg_locks" in normalized or "from pg_catalog.pg_locks" in normalized:
            rows = [
                ["relation", "16384", "24620", "AccessShareLock", "t", "42101"],
                ["relation", "16384", "24635", "RowExclusiveLock", "t", "42102"],
                ["virtualxid", "0", "0", "ExclusiveLock", "t", "42102"],
            ]
            self._send_result_set(
                conn=conn,
                columns=["locktype", "database", "relation", "mode", "granted", "pid"],
                rows=rows,
                command_tag=f"SELECT {len(rows)}",
                send_ready=send_ready,
            )
            return

        if "from pg_stat_database" in normalized or "from pg_catalog.pg_stat_database" in normalized:
            rows = [
                [
                    current_database or narrative_db,
                    "9",
                    "1820",
                    "108",
                    "37124",
                    "2452",
                    "84219",
                    "42610",
                ],
                ["template1", "1", "74", "2", "812", "161", "2720", "1982"],
            ]
            self._send_result_set(
                conn=conn,
                columns=[
                    "datname",
                    "numbackends",
                    "xact_commit",
                    "xact_rollback",
                    "blks_read",
                    "blks_hit",
                    "tup_returned",
                    "tup_fetched",
                ],
                rows=rows,
                command_tag=f"SELECT {len(rows)}",
                send_ready=send_ready,
            )
            return

        if "from pg_stat_user_tables" in normalized or "from pg_catalog.pg_stat_user_tables" in normalized:
            rows: list[list[str]] = []
            for index, relation in enumerate(narrative_tables, start=1):
                seq_scan = 120 + (index * 17)
                idx_scan = 420 + (index * 31)
                n_tup_ins = 2400 + (index * 213)
                n_tup_upd = 180 + (index * 19)
                n_live_tup = self._relation_row_count(relation_name=relation)
                rows.append(
                    [
                        relation,
                        str(seq_scan),
                        str(idx_scan),
                        str(n_tup_ins),
                        str(n_tup_upd),
                        str(n_live_tup),
                    ]
                )
            self._send_result_set(
                conn=conn,
                columns=["relname", "seq_scan", "idx_scan", "n_tup_ins", "n_tup_upd", "n_live_tup"],
                rows=rows,
                command_tag=f"SELECT {len(rows)}",
                send_ready=send_ready,
            )
            return

        if "from pg_stat_replication" in normalized or "from pg_catalog.pg_stat_replication" in normalized:
            rows = [
                [
                    "42110",
                    "10.41.12.21",
                    "replica01",
                    "streaming",
                    "0/16C0F3A8",
                    "0/16C0F3A8",
                    "0/16C0F3A8",
                    "0",
                ],
                [
                    "42111",
                    "10.41.12.22",
                    "replica02",
                    "streaming",
                    "0/16C0F3A8",
                    "0/16C0F3A8",
                    "0/16C0EFA0",
                    "2",
                ],
            ]
            self._send_result_set(
                conn=conn,
                columns=["pid", "client_addr", "application_name", "state", "sent_lsn", "write_lsn", "flush_lsn", "lag_bytes"],
                rows=rows,
                command_tag=f"SELECT {len(rows)}",
                send_ready=send_ready,
            )
            return

        if normalized.startswith("select count(*) from "):
            remainder = normalized.removeprefix("select count(*) from ").strip()
            relation = self._clean_identifier(remainder.split()[0] if remainder else "")
            self._send_result_set(
                conn=conn,
                columns=["count"],
                rows=[[str(self._relation_row_count(relation_name=relation))]],
                command_tag="SELECT 1",
                send_ready=send_ready,
            )
            return

        if normalized.startswith("select"):
            self._send_result_set(
                conn=conn,
                columns=["result"],
                rows=[[rabbit_value]],
                command_tag="SELECT 1",
                send_ready=send_ready,
            )
            return

        self._send_command_complete(conn, tag="UPDATE 1")
        if send_ready:
            self._send_ready(conn)

    @staticmethod
    def _rabbit_row_value(result: dict[str, Any]) -> str:
        cursor = result.get("cursor")
        if isinstance(cursor, dict):
            first_batch = cursor.get("firstBatch")
            if isinstance(first_batch, list) and first_batch:
                first = first_batch[0]
                if isinstance(first, dict) and first:
                    key = sorted(first.keys())[0]
                    return str(first.get(key, "1"))
        if "note" in result:
            return str(result["note"])
        if "plan" in result:
            return str(result["plan"])
        return "1"

    @staticmethod
    def _narrative_identifiers(narrative_context: dict[str, Any]) -> tuple[str, list[str]]:
        focus = narrative_context.get("focus", {})
        if not isinstance(focus, dict):
            return ("appdb", ["users", "orders", "audit_events", "feature_flags"])

        service = focus.get("service", {})
        dataset = focus.get("dataset", {})
        service_label = str(service.get("label", "")).strip() if isinstance(service, dict) else ""
        dataset_label = str(dataset.get("label", "")).strip() if isinstance(dataset, dict) else ""

        db_name = Emulator._normalize_identifier(service_label, default="appdb")
        dataset_base = Emulator._normalize_identifier(dataset_label, default="users")
        service_base = Emulator._normalize_identifier(service_label, default="ops")
        tables = [
            dataset_base,
            f"{dataset_base}_history",
            f"{service_base}_audit",
            f"{service_base}_flags",
        ]
        deduped: list[str] = []
        seen: set[str] = set()
        for item in tables:
            if item in seen:
                continue
            seen.add(item)
            deduped.append(item)
        return (db_name, deduped)

    @staticmethod
    def _normalize_identifier(value: str, *, default: str) -> str:
        lowered = value.strip().lower()
        normalized_chars = [char if char.isalnum() else "_" for char in lowered]
        normalized = "".join(normalized_chars).strip("_")
        while "__" in normalized:
            normalized = normalized.replace("__", "_")
        if not normalized:
            normalized = default
        if normalized[0].isdigit():
            normalized = f"n_{normalized}"
        return normalized[:48]

    @staticmethod
    def _clean_identifier(value: str) -> str:
        cleaned = value.strip().strip("`'\"")
        if "." in cleaned:
            cleaned = cleaned.rsplit(".", 1)[-1]
        for suffix in (",", ";", ")"):
            if cleaned.endswith(suffix):
                cleaned = cleaned[:-1]
        return cleaned

    @staticmethod
    def _relation_row_count(*, relation_name: str) -> int:
        normalized = relation_name.strip().lower()
        if normalized in {"users", "app_users"}:
            return 211
        if "order" in normalized:
            return 1897
        if "audit" in normalized or normalized.endswith("_history"):
            return 51872
        if normalized.endswith("_flags"):
            return 37
        return 64

    @staticmethod
    def _relation_columns(*, relation_name: str) -> list[tuple[str, str]]:
        normalized = relation_name.strip().lower()
        if normalized in {"users", "app_users"}:
            return [
                ("id", "bigint"),
                ("email", "text"),
                ("password_hash", "text"),
                ("updated_at", "timestamp with time zone"),
            ]
        if "order" in normalized:
            return [
                ("id", "bigint"),
                ("user_id", "bigint"),
                ("status", "text"),
                ("updated_at", "timestamp with time zone"),
            ]
        if "audit" in normalized or normalized.endswith("_history"):
            return [
                ("id", "bigint"),
                ("event_type", "text"),
                ("actor", "text"),
                ("created_at", "timestamp with time zone"),
            ]
        if normalized.endswith("_flags"):
            return [
                ("id", "bigint"),
                ("flag_key", "text"),
                ("enabled", "boolean"),
                ("updated_at", "timestamp with time zone"),
            ]
        return [
            ("id", "bigint"),
            ("value", "text"),
            ("updated_at", "timestamp with time zone"),
        ]

    @staticmethod
    def _extract_filter_value(*, normalized: str, key: str) -> str:
        marker = f"{key}="
        index = normalized.find(marker)
        if index < 0:
            return ""
        remainder = normalized[index + len(marker) :].lstrip()
        if not remainder:
            return ""
        if remainder[0] in {"'", '"'}:
            quote = remainder[0]
            end = remainder.find(quote, 1)
            if end > 1:
                return remainder[1:end]
            return remainder[1:]
        token = remainder.split()[0]
        for separator in (",", ")", ";"):
            token = token.split(separator, 1)[0]
        return token.strip().strip("'\"")

    def _record_auth(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        username: str,
        database: str,
        password: str,
    ) -> None:
        if not self.runtime:
            return
        payload = {
            "source_ip": source_ip,
            "protocol": "postgresql",
            "username": username,
            "database": database,
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
            message="postgres auth attempt",
            service=self.name,
            action="auth_attempt",
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            event_type="authentication",
            outcome="success",
            payload=payload,
        )

    def _record_query(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        query: str,
    ) -> None:
        if not self.runtime:
            return
        payload = {
            "source_ip": source_ip,
            "protocol": "postgresql",
            "query": query,
        }
        self.runtime.session_manager.record_event(
            session_id=session_id,
            service=self.name,
            action="command",
            payload=payload,
        )
        self.runtime.event_logger.emit(
            message="postgres query",
            service=self.name,
            action="command",
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            event_type="info",
            outcome="success",
            payload=payload,
        )

    def _select_lure_arm(
        self,
        *,
        session_id: str,
        source_ip: str,
        query: str,
    ) -> str:
        if not self.runtime or not callable(self.runtime.bandit_select):
            return ""
        context_key = f"postgres:{self._query_category(query)}"
        candidates = ["postgres-baseline", "postgres-query-bait", "postgres-credential-bait"]
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
            "query": query,
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
            message="postgres lure arm selection",
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
    def _query_category(query: str) -> str:
        normalized = query.strip().lower()
        if normalized.startswith("select"):
            return "select"
        if normalized.startswith("show"):
            return "enum"
        if "information_schema" in normalized:
            return "schema"
        return "generic"

    def _next_pid(self) -> int:
        with self._pid_lock:
            self._pid_counter += 1
            return self._pid_counter

    def _read_startup_packet(self, conn: socket.socket) -> bytes | None:
        while True:
            header = self._recv_exact(conn, 4)
            if header is None:
                return None
            length = int.from_bytes(header, "big")
            if length < 8:
                return None
            if length > self._MAX_MESSAGE_SIZE_BYTES:
                return None
            payload = self._recv_exact(conn, length - 4)
            if payload is None:
                return None
            request_code = int.from_bytes(payload[0:4], "big")
            if request_code == _SSL_REQUEST_CODE:
                try:
                    conn.sendall(b"N")
                except OSError:
                    return None
                continue
            if request_code != _PROTOCOL_VERSION_3:
                self._send_error(conn, "unsupported protocol")
                return None
            return payload

    def _read_password_message(self, conn: socket.socket) -> str | None:
        message = self._read_message(conn)
        if message is None:
            return None
        message_type, payload = message
        if message_type != b"p":
            return None
        return payload.rstrip(b"\x00").decode("utf-8", errors="replace")

    def _read_message(self, conn: socket.socket) -> tuple[bytes, bytes] | None:
        msg_type = self._recv_exact(conn, 1)
        if msg_type is None:
            return None
        length_raw = self._recv_exact(conn, 4)
        if length_raw is None:
            return None
        length = int.from_bytes(length_raw, "big")
        if length < 4:
            return None
        if length > self._MAX_MESSAGE_SIZE_BYTES:
            return None
        payload = self._recv_exact(conn, length - 4)
        if payload is None:
            return None
        return (msg_type, payload)

    @staticmethod
    def _send_message(conn: socket.socket, msg_type: bytes, payload: bytes) -> bool:
        packet = msg_type + struct.pack("!I", len(payload) + 4) + payload
        try:
            conn.sendall(packet)
            return True
        except OSError:
            return False

    def _send_ready(self, conn: socket.socket) -> None:
        self._send_message(conn, b"Z", b"I")

    def _send_error(self, conn: socket.socket, message: str) -> None:
        payload = b"SERROR\x00CXX000\x00M" + message.encode("utf-8", errors="replace") + b"\x00\x00"
        self._send_message(conn, b"E", payload)

    def _send_row_description(self, conn: socket.socket, *, columns: list[str] | None = None) -> None:
        selected = columns or ["result"]
        field_bytes = bytearray()
        for column in selected:
            field_bytes.extend(
                self._cstring(column)
                + struct.pack("!I", 0)
                + struct.pack("!H", 0)
                + struct.pack("!I", 25)
                + struct.pack("!H", 0xFFFF)
                + struct.pack("!I", 0xFFFFFFFF)
                + struct.pack("!H", 0)
            )
        payload = struct.pack("!H", len(selected)) + bytes(field_bytes)
        self._send_message(conn, b"T", payload)

    def _send_data_row(self, conn: socket.socket, *, values: list[str]) -> None:
        payload = bytearray(struct.pack("!H", len(values)))
        for value in values:
            encoded = value.encode("utf-8")
            payload.extend(struct.pack("!I", len(encoded)))
            payload.extend(encoded)
        self._send_message(conn, b"D", bytes(payload))

    def _send_command_complete(self, conn: socket.socket, *, tag: str) -> None:
        self._send_message(conn, b"C", self._cstring(tag))

    def _send_result_set(
        self,
        *,
        conn: socket.socket,
        columns: list[str],
        rows: list[list[str]],
        command_tag: str,
        send_ready: bool = True,
    ) -> None:
        self._send_row_description(conn, columns=columns)
        for row in rows:
            self._send_data_row(conn, values=row)
        self._send_command_complete(conn, tag=command_tag)
        if send_ready:
            self._send_ready(conn)

    @staticmethod
    def _parse_startup_params(payload: bytes) -> dict[str, str]:
        params: dict[str, str] = {}
        parts = payload[4:].split(b"\x00")
        for idx in range(0, len(parts) - 1, 2):
            key_raw = parts[idx]
            value_raw = parts[idx + 1]
            if not key_raw:
                break
            key = key_raw.decode("utf-8", errors="replace")
            value = value_raw.decode("utf-8", errors="replace")
            params[key] = value
        return params

    @staticmethod
    def _parse_parse_message(payload: bytes) -> tuple[str, str] | None:
        statement_name_and_pos = Emulator._read_cstring_at(payload, 0)
        if statement_name_and_pos is None:
            return None
        statement_name, pos = statement_name_and_pos
        query_and_pos = Emulator._read_cstring_at(payload, pos)
        if query_and_pos is None:
            return None
        prepared_query, _ = query_and_pos
        return (statement_name, prepared_query)

    @staticmethod
    def _parse_bind_message(payload: bytes) -> tuple[str, str] | None:
        portal_and_pos = Emulator._read_cstring_at(payload, 0)
        if portal_and_pos is None:
            return None
        portal_name, pos = portal_and_pos
        statement_and_pos = Emulator._read_cstring_at(payload, pos)
        if statement_and_pos is None:
            return None
        statement_name, _ = statement_and_pos
        return (portal_name, statement_name)

    @staticmethod
    def _parse_execute_message(payload: bytes) -> tuple[str, int] | None:
        portal_and_pos = Emulator._read_cstring_at(payload, 0)
        if portal_and_pos is None:
            return None
        portal_name, pos = portal_and_pos
        if pos + 4 > len(payload):
            return None
        max_rows = int.from_bytes(payload[pos : pos + 4], "big")
        return (portal_name, max_rows)

    @staticmethod
    def _parse_close_message(payload: bytes) -> tuple[str, str] | None:
        if not payload:
            return None
        close_kind = chr(payload[0])
        name_and_pos = Emulator._read_cstring_at(payload, 1)
        if name_and_pos is None:
            return None
        close_name, _ = name_and_pos
        return (close_kind, close_name)

    @staticmethod
    def _read_cstring_at(buffer: bytes, start: int) -> tuple[str, int] | None:
        if start >= len(buffer):
            return None
        end = buffer.find(b"\x00", start)
        if end < 0:
            return None
        value = buffer[start:end].decode("utf-8", errors="replace")
        return (value, end + 1)

    @staticmethod
    def _recv_exact(conn: socket.socket, size: int) -> bytes | None:
        if size < 0 or size > Emulator._MAX_MESSAGE_SIZE_BYTES:
            return None
        data = bytearray()
        try:
            while len(data) < size:
                chunk = conn.recv(size - len(data))
                if not chunk:
                    return None
                data.extend(chunk)
        except (TimeoutError, OSError):
            return None
        return bytes(data)

    @staticmethod
    def _cstring(value: str) -> bytes:
        return value.encode("utf-8") + b"\x00"
