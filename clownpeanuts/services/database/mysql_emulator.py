"""MySQL-protocol honeypot emulator with credential and query capture."""

from __future__ import annotations

from datetime import UTC, datetime
import os
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


_CLIENT_PROTOCOL_41 = 0x00000200
_CLIENT_SECURE_CONNECTION = 0x00008000
_CLIENT_PLUGIN_AUTH = 0x00080000
_CLIENT_CONNECT_WITH_DB = 0x00000008
_CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
_CLIENT_SSL = 0x00000800


class Emulator(ServiceEmulator):
    _MAX_PACKET_PAYLOAD_BYTES = 1_048_576
    _MAX_PREPARED_STATEMENTS = 1000

    def __init__(self) -> None:
        super().__init__()
        self.logger = get_logger("clownpeanuts.services.database.mysql")
        self._server: _ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._bound_host: str | None = None
        self._bound_port: int | None = None
        self._socket_timeout_seconds = 45.0
        self._server_version = "8.0.36-clownpeanuts"
        self._max_concurrent_connections = 256
        self._connection_id = 1000
        self._conn_lock = threading.Lock()
        self._tarpit = AdaptiveThrottle(service_name=self.name)

    @property
    def name(self) -> str:
        return "mysql_db"

    @property
    def default_ports(self) -> list[int]:
        return [3306, 13306]

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
                message="mysql emulator started",
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
                message="mysql emulator stopped",
                service=self.name,
                action="service_stop",
                event_type="end",
            )

    async def handle_connection(self, conn: dict[str, Any]) -> dict[str, Any]:
        username = str(conn.get("username", "root"))
        password = str(conn.get("password", "password"))
        query = str(conn.get("query", "SELECT 1"))
        source_ip = str(conn.get("source_ip", "127.0.0.1"))
        source_port = int(conn.get("source_port", 0))
        session_id = str(conn.get("session_id", f"mysql-{uuid4().hex}"))

        if self.runtime:
            self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
            self._record_auth(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                username=username,
                database_name="",
                auth_response=password.encode("utf-8"),
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
        session_id = str(payload.get("session_id", f"mysql-injected-{uuid4().hex[:12]}")).strip()
        if not session_id:
            session_id = f"mysql-injected-{uuid4().hex[:12]}"
        username = str(payload.get("username", "app")).strip() or "app"
        password = str(payload.get("password", "injected-password")).strip() or "injected-password"
        database_name = str(payload.get("database", "wordpress")).strip() or "wordpress"
        self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
        self._record_auth(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            database_name=database_name,
            auth_response=password.encode("utf-8", errors="replace"),
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

        class MySQLHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                emulator._handle_client(self.request, self.client_address)

        return MySQLHandler

    def _handle_client(self, conn: socket.socket, client_address: tuple[str, int]) -> None:
        conn.settimeout(self._socket_timeout_seconds)
        source_ip, source_port = client_address
        session_id = f"mysql-{source_ip}-{uuid4().hex[:12]}"
        if self.runtime:
            self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
            self.runtime.event_logger.emit(
                message="mysql connection opened",
                service=self.name,
                action="connection_open",
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                event_type="access",
                outcome="success",
            )

        connection_id = self._next_connection_id()
        auth_seed = os.urandom(20)
        server_caps = (
            _CLIENT_PROTOCOL_41
            | _CLIENT_SECURE_CONNECTION
            | _CLIENT_PLUGIN_AUTH
            | _CLIENT_CONNECT_WITH_DB
            | _CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
        )
        handshake = self._build_handshake_packet(connection_id=connection_id, capabilities=server_caps, seed=auth_seed)
        if not self._send_packet(conn, sequence=0, payload=handshake):
            return

        login = self._read_packet(conn)
        if login is None:
            return
        _, login_payload = login
        credentials = self._parse_login_packet(login_payload)
        if credentials is None:
            self._send_packet(conn, sequence=2, payload=self._err_packet("malformed login packet"))
            return
        username, database, auth_response, capabilities = credentials

        if capabilities & _CLIENT_SSL:
            self._send_packet(conn, sequence=2, payload=self._err_packet("ssl mode unsupported"))
            return

        self._record_auth(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            database_name=database or "",
            auth_response=auth_response,
        )
        current_database = database or "wordpress"
        prepared_statements: dict[int, str] = {}
        next_statement_id = 1
        self._tarpit.maybe_delay(
            runtime=self.runtime,
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            trigger="mysql_auth_response",
        )
        self._send_packet(conn, sequence=2, payload=self._ok_packet())

        while True:
            packet = self._read_packet(conn)
            if packet is None:
                return
            _, payload = packet
            if not payload:
                return
            command = payload[0]
            if command == 0x01:  # COM_QUIT
                self._record_query(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    query="QUIT",
                )
                return

            if command == 0x03:  # COM_QUERY
                query = payload[1:].decode("utf-8", errors="replace")
                normalized_query = " ".join(query.strip().lower().rstrip(";").split())
                if normalized_query.startswith("use "):
                    selected_database = normalized_query.split(" ", 1)[1].strip()
                    if selected_database:
                        current_database = selected_database
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
                    trigger="mysql_query_response",
                )
                self._respond_query(
                    conn,
                    query=query,
                    session_id=session_id,
                    source_ip=source_ip,
                    current_database=current_database,
                )
                continue

            if command == 0x02:  # COM_INIT_DB
                selected_database = payload[1:].decode("utf-8", errors="replace").strip()
                if selected_database:
                    current_database = selected_database
                self._record_query(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    query=f"USE {selected_database or current_database}",
                )
                self._send_packet(conn, sequence=1, payload=self._ok_packet())
                continue

            if command == 0x0E:  # COM_PING
                self._record_query(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    query="PING",
                )
                self._send_packet(conn, sequence=1, payload=self._ok_packet())
                continue

            if command == 0x16:  # COM_STMT_PREPARE
                prepared_query = payload[1:].decode("utf-8", errors="replace")
                if len(prepared_statements) >= self._MAX_PREPARED_STATEMENTS:
                    self._record_query(
                        session_id=session_id,
                        source_ip=source_ip,
                        source_port=source_port,
                        query="PREPARE rejected: too many prepared statements",
                    )
                    self._send_packet(conn, sequence=1, payload=self._err_packet("too many prepared statements"))
                    continue
                statement_id = next_statement_id
                next_statement_id += 1
                prepared_statements[statement_id] = prepared_query
                self._record_query(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    query=f"PREPARE stmt-{statement_id}: {prepared_query}",
                )
                self._send_stmt_prepare_ok(conn=conn, statement_id=statement_id)
                continue

            if command == 0x17:  # COM_STMT_EXECUTE
                if len(payload) < 5:
                    self._send_packet(conn, sequence=1, payload=self._err_packet("malformed stmt execute packet"))
                    continue
                statement_id = int.from_bytes(payload[1:5], "little")
                prepared_query = prepared_statements.get(statement_id)
                if prepared_query is None:
                    self._send_packet(conn, sequence=1, payload=self._err_packet("unknown statement id"))
                    continue
                self._record_query(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    query=f"EXECUTE stmt-{statement_id}: {prepared_query}",
                )
                self._respond_query(
                    conn,
                    query=prepared_query,
                    session_id=session_id,
                    source_ip=source_ip,
                    current_database=current_database,
                )
                continue

            if command == 0x19:  # COM_STMT_CLOSE
                if len(payload) >= 5:
                    statement_id = int.from_bytes(payload[1:5], "little")
                    prepared_statements.pop(statement_id, None)
                    self._record_query(
                        session_id=session_id,
                        source_ip=source_ip,
                        source_port=source_port,
                        query=f"CLOSE stmt-{statement_id}",
                    )
                continue

            if command == 0x1A:  # COM_STMT_RESET
                self._record_query(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    query="STMT_RESET",
                )
                self._send_packet(conn, sequence=1, payload=self._ok_packet())
                continue

            self._record_query(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                query=f"COMMAND_{command}",
            )
            self._tarpit.maybe_delay(
                runtime=self.runtime,
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                trigger="mysql_command_response",
            )
            self._send_packet(conn, sequence=1, payload=self._ok_packet())

    def _respond_query(
        self,
        conn: socket.socket,
        *,
        query: str,
        session_id: str,
        source_ip: str,
        current_database: str,
    ) -> None:
        lower = query.strip().lower()
        normalized = " ".join(lower.rstrip(";").split())
        selected_lure_arm = self._select_lure_arm(
            session_id=session_id,
            source_ip=source_ip,
            query=normalized or query,
        )
        rabbit_result: dict[str, Any] | None = None
        narrative_db = "wordpress"
        narrative_tables = ["users", "orders", "wp_options", "wp_posts"]
        if self.runtime and self.runtime.rabbit_hole:
            command = normalized.split(" ", 1)[0] if normalized else "query"
            rabbit_result = self.runtime.rabbit_hole.respond_database_command(
                service=self.name,
                session_id=session_id,
                source_ip=source_ip,
                command=command,
                document={"query": query},
                tenant_id=self.runtime.tenant_id,
            )
            narrative_context = self.runtime.rabbit_hole.resolve_narrative_context(
                session_id=session_id,
                source_ip=source_ip,
                tenant_id=self.runtime.tenant_id,
                service=self.name,
                action=command,
                hints={"query": query},
            )
            narrative_db, narrative_tables = self._narrative_identifiers(narrative_context)

        if normalized == "show databases":
            candidates = ["information_schema", "mysql", "performance_schema", "wordpress", narrative_db]
            if selected_lure_arm == "mysql-query-bait":
                candidates.append("archive_shadow")
            databases: list[list[str]] = []
            seen: set[str] = set()
            for candidate in candidates:
                if candidate in seen:
                    continue
                seen.add(candidate)
                databases.append([candidate])
            self._send_result_set(
                conn=conn,
                columns=["Database"],
                rows=databases,
            )
            return

        if normalized.startswith("show tables"):
            effective_database = current_database or "wordpress"
            rows = self._tables_for_database(database=effective_database)
            if effective_database.strip().lower() == narrative_db:
                rows = [[table] for table in narrative_tables]
            self._send_result_set(
                conn=conn,
                columns=[f"Tables_in_{effective_database}"],
                rows=rows,
            )
            return

        if normalized.startswith("show full tables"):
            effective_database = current_database or "wordpress"
            table_rows = self._tables_for_database(database=effective_database)
            if effective_database.strip().lower() == narrative_db:
                table_rows = [[table] for table in narrative_tables]
            rows = [[table_name, "BASE TABLE"] for table_name, *_ in table_rows]
            self._send_result_set(
                conn=conn,
                columns=[f"Tables_in_{effective_database}", "Table_type"],
                rows=rows,
            )
            return

        if normalized == "show processlist":
            effective_database = current_database or "wordpress"
            self._send_result_set(
                conn=conn,
                columns=["Id", "User", "Host", "db", "Command", "Time", "State", "Info"],
                rows=[
                    ["41", "root", "127.0.0.1:53812", effective_database, "Query", "0", "executing", "SHOW PROCESSLIST"],
                    ["42", "app_rw", "10.41.12.17:42110", effective_database, "Sleep", "12", "", ""],
                ],
            )
            return

        if normalized in {"select @@version", "select version()"}:
            self._send_result_set(conn=conn, columns=["version"], rows=[[self._server_version]])
            return

        if normalized in {"select @@hostname", "select @@hostname as hostname"}:
            self._send_result_set(conn=conn, columns=["hostname"], rows=[["db01-clownpeanuts"]])
            return

        if normalized in {"select user()", "select current_user()"}:
            self._send_result_set(conn=conn, columns=["user"], rows=[["root@localhost"]])
            return

        if normalized in {"select database()", "select current_database()"}:
            self._send_result_set(conn=conn, columns=["database"], rows=[[current_database or "wordpress"]])
            return

        if normalized in {"select now()", "select current_timestamp()"}:
            now_value = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
            self._send_result_set(conn=conn, columns=["now"], rows=[[now_value]])
            return

        if normalized.startswith("show variables like ") and "version" in normalized:
            self._send_result_set(
                conn=conn,
                columns=["Variable_name", "Value"],
                rows=[
                    ["version", self._server_version],
                    ["version_comment", "MySQL Community Server - GPL"],
                    ["version_compile_os", "Linux"],
                ],
            )
            return

        if normalized.startswith("show status like ") and "threads_connected" in normalized:
            self._send_result_set(
                conn=conn,
                columns=["Variable_name", "Value"],
                rows=[["Threads_connected", "3"]],
            )
            return

        if normalized == "show engine innodb status":
            self._send_result_set(
                conn=conn,
                columns=["Type", "Name", "Status"],
                rows=[
                    [
                        "InnoDB",
                        "",
                        (
                            "BACKGROUND THREAD\n"
                            "srv_master_thread loops: 5231 srv_active, 0 srv_shutdown, 11932 srv_idle\n"
                            "SEMAPHORES\n"
                            "OS WAIT ARRAY INFO: reservation count 4184\n"
                            "TRANSACTIONS\n"
                            "Trx id counter 1729442\n"
                        ),
                    ]
                ],
            )
            return

        if normalized == "show master status":
            self._send_result_set(
                conn=conn,
                columns=["File", "Position", "Binlog_Do_DB", "Binlog_Ignore_DB", "Executed_Gtid_Set"],
                rows=[["mysql-bin.000247", "62158342", "", "", ""]],
            )
            return

        if normalized == "show binary logs":
            self._send_result_set(
                conn=conn,
                columns=["Log_name", "File_size", "Encrypted"],
                rows=[
                    ["mysql-bin.000245", "60123912", "No"],
                    ["mysql-bin.000246", "61388321", "No"],
                    ["mysql-bin.000247", "62158342", "No"],
                ],
            )
            return

        if normalized in {"show slave status", "show replica status"}:
            self._send_result_set(
                conn=conn,
                columns=[
                    "Slave_IO_State",
                    "Master_Host",
                    "Master_User",
                    "Slave_IO_Running",
                    "Slave_SQL_Running",
                    "Seconds_Behind_Master",
                ],
                rows=[["Waiting for source to send event", "10.41.12.21", "replica", "Yes", "Yes", "0"]],
            )
            return

        if normalized.startswith("describe ") or normalized.startswith("desc "):
            parts = normalized.split()
            target_table = parts[1] if len(parts) > 1 else (narrative_tables[0] if narrative_tables else "users")
            target_table = self._clean_identifier(target_table)
            self._send_result_set(
                conn=conn,
                columns=["Field", "Type", "Null", "Key", "Default", "Extra"],
                rows=self._table_description_rows(table_name=target_table),
            )
            return

        if normalized.startswith("show columns from ") or normalized.startswith("show fields from "):
            tokens = normalized.split()
            target_table = self._clean_identifier(tokens[3] if len(tokens) > 3 else (narrative_tables[0] if narrative_tables else "users"))
            self._send_result_set(
                conn=conn,
                columns=["Field", "Type", "Null", "Key", "Default", "Extra"],
                rows=self._table_description_rows(table_name=target_table),
            )
            return

        if normalized.startswith("show index from ") or normalized.startswith("show keys from "):
            tokens = normalized.split()
            target_table = self._clean_identifier(tokens[3] if len(tokens) > 3 else (narrative_tables[0] if narrative_tables else "users"))
            self._send_result_set(
                conn=conn,
                columns=["Table", "Non_unique", "Key_name", "Seq_in_index", "Column_name", "Index_type"],
                rows=self._table_index_rows(table_name=target_table),
            )
            return

        if normalized.startswith("show create table "):
            tokens = normalized.split()
            target_table = self._clean_identifier(tokens[3] if len(tokens) > 3 else (narrative_tables[0] if narrative_tables else "users"))
            self._send_result_set(
                conn=conn,
                columns=["Table", "Create Table"],
                rows=[[target_table, self._table_create_statement(table_name=target_table)]],
            )
            return

        if normalized == "show grants" or normalized.startswith("show grants for "):
            principal = "root@localhost"
            if normalized.startswith("show grants for "):
                raw_principal = query.strip()[len("show grants for ") :].strip().rstrip(";")
                if raw_principal:
                    principal = raw_principal.replace("`", "").replace("'", "").replace('"', "")
            if "@" not in principal:
                principal = f"{principal}@localhost"
            user, host = principal.split("@", 1)
            self._send_result_set(
                conn=conn,
                columns=[f"Grants for {user}@{host}"],
                rows=[
                    [f"GRANT ALL PRIVILEGES ON *.* TO '{user}'@'{host}' WITH GRANT OPTION"],
                    [f"GRANT PROXY ON ''@'' TO '{user}'@'{host}' WITH GRANT OPTION"],
                ],
            )
            return

        if "from information_schema.tables" in normalized:
            requested_schema = self._schema_from_information_schema_query(
                normalized=normalized,
                current_database=current_database or "wordpress",
                narrative_database=narrative_db,
            )
            rows = self._tables_for_database(database=requested_schema)
            if requested_schema == narrative_db:
                rows = [[table] for table in narrative_tables]
            self._send_result_set(conn=conn, columns=["TABLE_NAME"], rows=rows)
            return

        if "from information_schema.columns" in normalized:
            table_filter = self._extract_filter_value(normalized=normalized, key="table_name")
            target_table = self._clean_identifier(table_filter or (narrative_tables[0] if narrative_tables else "users"))
            rows = [
                [target_table, field, data_type]
                for field, data_type, *_ in self._table_description_rows(table_name=target_table)
            ]
            self._send_result_set(conn=conn, columns=["TABLE_NAME", "COLUMN_NAME", "DATA_TYPE"], rows=rows)
            return

        if "from information_schema.statistics" in normalized:
            table_filter = self._extract_filter_value(normalized=normalized, key="table_name")
            target_table = self._clean_identifier(table_filter or (narrative_tables[0] if narrative_tables else "users"))
            rows = [
                [table_name, key_name, non_unique, seq_in_index, column_name]
                for table_name, non_unique, key_name, seq_in_index, column_name, _ in self._table_index_rows(
                    table_name=target_table
                )
            ]
            self._send_result_set(conn=conn, columns=["TABLE_NAME", "INDEX_NAME", "NON_UNIQUE", "SEQ_IN_INDEX", "COLUMN_NAME"], rows=rows)
            return

        if normalized.startswith("select count(*) from "):
            remainder = normalized.removeprefix("select count(*) from ").strip()
            target_table = self._clean_identifier(remainder.split()[0] if remainder else "")
            self._send_result_set(
                conn=conn,
                columns=["count(*)"],
                rows=[[str(self._table_row_count(table_name=target_table))]],
            )
            return

        if normalized.startswith("select"):
            row_value = "1"
            if rabbit_result is not None:
                row_value = self._rabbit_row_value(rabbit_result)
            self._send_result_set(conn=conn, columns=["result"], rows=[[row_value]])
            return

        if normalized.startswith("use "):
            selected = normalized.split(" ", 1)[1].strip()
            if selected:
                current_database = selected
            self._send_packet(conn, sequence=1, payload=self._ok_packet())
            return

        self._send_packet(conn, sequence=1, payload=self._ok_packet())

    @staticmethod
    def _narrative_identifiers(narrative_context: dict[str, Any]) -> tuple[str, list[str]]:
        focus = narrative_context.get("focus", {})
        if not isinstance(focus, dict):
            return ("wordpress", ["users", "orders", "wp_options", "wp_posts"])

        service = focus.get("service", {})
        dataset = focus.get("dataset", {})
        service_label = str(service.get("label", "")).strip() if isinstance(service, dict) else ""
        dataset_label = str(dataset.get("label", "")).strip() if isinstance(dataset, dict) else ""

        db_name = Emulator._normalize_identifier(service_label, default="wordpress")
        dataset_base = Emulator._normalize_identifier(dataset_label, default="users")
        service_base = Emulator._normalize_identifier(service_label, default="orders")
        tables = [
            dataset_base,
            f"{dataset_base}_events",
            f"{service_base}_audit",
            f"{service_base}_config",
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

    def _send_result_set(self, *, conn: socket.socket, columns: list[str], rows: list[list[str]]) -> None:
        sequence = 1
        self._send_packet(conn, sequence=sequence, payload=self._lenenc_int(len(columns)))
        sequence += 1
        for column in columns:
            self._send_packet(conn, sequence=sequence, payload=self._column_definition(name=column))
            sequence += 1
        self._send_packet(conn, sequence=sequence, payload=b"\xfe\x00\x00\x02\x00")
        sequence += 1
        for row in rows:
            self._send_packet(conn, sequence=sequence, payload=self._row_packet(row))
            sequence += 1
        self._send_packet(conn, sequence=sequence, payload=b"\xfe\x00\x00\x02\x00")

    def _send_stmt_prepare_ok(self, *, conn: socket.socket, statement_id: int) -> None:
        payload = bytearray()
        payload.append(0x00)
        payload.extend(statement_id.to_bytes(4, "little"))
        payload.extend((0).to_bytes(2, "little"))  # num_columns
        payload.extend((0).to_bytes(2, "little"))  # num_params
        payload.append(0x00)
        payload.extend((0).to_bytes(2, "little"))  # warning_count
        self._send_packet(conn, sequence=1, payload=bytes(payload))

    @staticmethod
    def _tables_for_database(*, database: str) -> list[list[str]]:
        normalized = database.strip().lower()
        if normalized == "mysql":
            return [["user"], ["db"], ["tables_priv"], ["help_topic"]]
        if normalized == "information_schema":
            return [["tables"], ["columns"], ["schemata"], ["statistics"]]
        if normalized == "performance_schema":
            return [["events_statements_summary_by_digest"], ["threads"], ["accounts"]]
        return [["users"], ["orders"], ["wp_options"], ["wp_posts"]]

    @staticmethod
    def _extract_filter_value(*, normalized: str, key: str) -> str | None:
        compact = normalized.replace(" ", "")
        for quote in ("'", '"', "`"):
            marker = f"{key}={quote}"
            start = compact.find(marker)
            if start < 0:
                continue
            tail = compact[start + len(marker) :]
            end = tail.find(quote)
            if end <= 0:
                continue
            return tail[:end]
        return None

    def _schema_from_information_schema_query(
        self,
        *,
        normalized: str,
        current_database: str,
        narrative_database: str,
    ) -> str:
        compact = normalized.replace(" ", "")
        if "table_schema=database()" in compact:
            return current_database.strip().lower() or "wordpress"
        explicit_schema = self._extract_filter_value(normalized=normalized, key="table_schema")
        if explicit_schema:
            return self._clean_identifier(explicit_schema) or "wordpress"
        if current_database.strip():
            return current_database.strip().lower()
        return narrative_database

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
    def _table_description_rows(*, table_name: str) -> list[list[str]]:
        normalized = table_name.strip().lower()
        if normalized in {"users", "wp_users"}:
            return [
                ["id", "bigint unsigned", "NO", "PRI", "", "auto_increment"],
                ["username", "varchar(191)", "NO", "UNI", "", ""],
                ["email", "varchar(255)", "NO", "UNI", "", ""],
                ["password_hash", "varchar(255)", "NO", "", "", ""],
                ["last_login_at", "timestamp", "YES", "", "NULL", ""],
            ]
        if "order" in normalized:
            return [
                ["id", "bigint unsigned", "NO", "PRI", "", "auto_increment"],
                ["order_ref", "varchar(64)", "NO", "UNI", "", ""],
                ["status", "varchar(32)", "NO", "", "pending", ""],
                ["total_cents", "int unsigned", "NO", "", "0", ""],
                ["created_at", "timestamp", "NO", "", "CURRENT_TIMESTAMP", ""],
            ]
        if "audit" in normalized:
            return [
                ["id", "bigint unsigned", "NO", "PRI", "", "auto_increment"],
                ["actor", "varchar(128)", "NO", "", "", ""],
                ["action", "varchar(128)", "NO", "", "", ""],
                ["target", "varchar(128)", "YES", "", "NULL", ""],
                ["created_at", "timestamp", "NO", "", "CURRENT_TIMESTAMP", ""],
            ]
        return [
            ["id", "bigint unsigned", "NO", "PRI", "", "auto_increment"],
            [f"{normalized or 'record'}_key", "varchar(255)", "NO", "UNI", "", ""],
            [f"{normalized or 'record'}_value", "varchar(255)", "YES", "", "NULL", ""],
            ["created_at", "timestamp", "NO", "", "CURRENT_TIMESTAMP", ""],
        ]

    @staticmethod
    def _table_row_count(*, table_name: str) -> int:
        normalized = table_name.strip().lower()
        if normalized in {"users", "wp_users"}:
            return 128
        if "order" in normalized:
            return 1542
        if "audit" in normalized:
            return 48293
        if normalized in {"wp_posts", "posts"}:
            return 937
        if normalized in {"wp_options", "options"}:
            return 614
        return 42

    @staticmethod
    def _table_index_rows(*, table_name: str) -> list[list[str]]:
        normalized = table_name.strip().lower() or "users"
        if normalized in {"users", "wp_users"}:
            return [
                [normalized, "0", "PRIMARY", "1", "id", "BTREE"],
                [normalized, "0", "username_uniq", "1", "username", "BTREE"],
                [normalized, "0", "email_uniq", "1", "email", "BTREE"],
            ]
        if "order" in normalized:
            return [
                [normalized, "0", "PRIMARY", "1", "id", "BTREE"],
                [normalized, "0", "order_ref_uniq", "1", "order_ref", "BTREE"],
                [normalized, "1", "status_idx", "1", "status", "BTREE"],
            ]
        if "audit" in normalized:
            return [
                [normalized, "0", "PRIMARY", "1", "id", "BTREE"],
                [normalized, "1", "actor_idx", "1", "actor", "BTREE"],
                [normalized, "1", "created_at_idx", "1", "created_at", "BTREE"],
            ]
        return [
            [normalized, "0", "PRIMARY", "1", "id", "BTREE"],
            [normalized, "0", f"{normalized}_key_uniq", "1", f"{normalized}_key", "BTREE"],
            [normalized, "1", f"{normalized}_created_idx", "1", "created_at", "BTREE"],
        ]

    def _table_create_statement(self, *, table_name: str) -> str:
        normalized = self._clean_identifier(table_name) or "users"
        columns = self._table_description_rows(table_name=normalized)
        indexes = self._table_index_rows(table_name=normalized)

        column_lines: list[str] = []
        for field, data_type, nullable, _key, default, extra in columns:
            parts = [f"`{field}`", data_type]
            parts.append("NOT NULL" if nullable.strip().upper() == "NO" else "NULL")
            default_value = str(default).strip()
            if default_value:
                upper_default = default_value.upper()
                if upper_default == "NULL":
                    parts.append("DEFAULT NULL")
                elif upper_default == "CURRENT_TIMESTAMP":
                    parts.append("DEFAULT CURRENT_TIMESTAMP")
                elif upper_default.isdigit():
                    parts.append(f"DEFAULT {default_value}")
                else:
                    parts.append(f"DEFAULT '{default_value}'")
            extra_value = str(extra).strip()
            if extra_value:
                parts.append(extra_value.upper())
            column_lines.append("  " + " ".join(parts))

        grouped_indexes: dict[str, tuple[str, list[tuple[int, str]]]] = {}
        for _table, non_unique, key_name, seq_in_index, column_name, _index_type in indexes:
            seq_value = int(seq_in_index or "1")
            if key_name not in grouped_indexes:
                grouped_indexes[key_name] = (non_unique, [(seq_value, column_name)])
            else:
                existing_non_unique, existing_columns = grouped_indexes[key_name]
                existing_columns.append((seq_value, column_name))
                grouped_indexes[key_name] = (existing_non_unique, existing_columns)

        index_lines: list[str] = []
        for key_name, (non_unique, key_columns) in grouped_indexes.items():
            ordered_columns = [name for _seq, name in sorted(key_columns, key=lambda item: item[0])]
            rendered_columns = ", ".join(f"`{name}`" for name in ordered_columns)
            if key_name == "PRIMARY":
                index_lines.append(f"  PRIMARY KEY ({rendered_columns})")
            elif non_unique == "0":
                index_lines.append(f"  UNIQUE KEY `{key_name}` ({rendered_columns})")
            else:
                index_lines.append(f"  KEY `{key_name}` ({rendered_columns})")

        definition = ",\n".join([*column_lines, *index_lines])
        return (
            f"CREATE TABLE `{normalized}` (\n"
            f"{definition}\n"
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        )

    def _record_auth(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        username: str,
        database_name: str,
        auth_response: bytes,
    ) -> None:
        if not self.runtime:
            return
        payload = {
            "source_ip": source_ip,
            "protocol": "mysql",
            "username": username,
            "database": database_name,
            "auth_response_hex": auth_response.hex(),
            "outcome": "success",
        }
        self.runtime.session_manager.record_event(
            session_id=session_id,
            service=self.name,
            action="auth_attempt",
            payload=payload,
        )
        self.runtime.event_logger.emit(
            message="mysql auth attempt",
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
            "protocol": "mysql",
            "query": query,
        }
        self.runtime.session_manager.record_event(
            session_id=session_id,
            service=self.name,
            action="command",
            payload=payload,
        )
        self.runtime.event_logger.emit(
            message="mysql query",
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
        context_key = f"mysql:{self._query_category(query)}"
        candidates = ["mysql-baseline", "mysql-query-bait", "mysql-credential-bait"]
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
            message="mysql lure arm selection",
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
        if normalized.startswith("describe") or normalized.startswith("desc"):
            return "schema"
        if normalized.startswith("use "):
            return "database"
        return "generic"

    def _next_connection_id(self) -> int:
        with self._conn_lock:
            self._connection_id += 1
            return self._connection_id

    def _build_handshake_packet(self, *, connection_id: int, capabilities: int, seed: bytes) -> bytes:
        payload = bytearray()
        payload.append(0x0A)
        payload.extend(self._server_version.encode("utf-8"))
        payload.append(0x00)
        payload.extend(struct.pack("<I", connection_id))
        payload.extend(seed[:8])
        payload.append(0x00)
        payload.extend(struct.pack("<H", capabilities & 0xFFFF))
        payload.append(0x21)
        payload.extend(struct.pack("<H", 0x0002))
        payload.extend(struct.pack("<H", (capabilities >> 16) & 0xFFFF))
        payload.append(len(seed) + 1)
        payload.extend(b"\x00" * 10)
        payload.extend(seed[8:])
        payload.append(0x00)
        payload.extend(b"mysql_native_password\x00")
        return bytes(payload)

    def _parse_login_packet(self, payload: bytes) -> tuple[str, str, bytes, int] | None:
        if len(payload) < 32:
            return None

        capabilities = int.from_bytes(payload[0:4], "little")
        pos = 32
        if pos >= len(payload):
            return None

        username_end = payload.find(b"\x00", pos)
        if username_end < 0:
            return None
        username = payload[pos:username_end].decode("utf-8", errors="replace")
        pos = username_end + 1

        auth_response = b""
        if capabilities & _CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
            length, consumed = self._read_lenenc(payload, pos)
            if length is None:
                return None
            pos += consumed
            auth_response = payload[pos : pos + length]
            pos += length
        elif capabilities & _CLIENT_SECURE_CONNECTION:
            if pos >= len(payload):
                return None
            length = payload[pos]
            pos += 1
            auth_response = payload[pos : pos + length]
            pos += length
        else:
            auth_end = payload.find(b"\x00", pos)
            if auth_end < 0:
                return None
            auth_response = payload[pos:auth_end]
            pos = auth_end + 1

        database = ""
        if capabilities & _CLIENT_CONNECT_WITH_DB and pos < len(payload):
            db_end = payload.find(b"\x00", pos)
            if db_end > pos:
                database = payload[pos:db_end].decode("utf-8", errors="replace")
        return (username, database, auth_response, capabilities)

    @staticmethod
    def _read_lenenc(buffer: bytes, pos: int) -> tuple[int | None, int]:
        if pos >= len(buffer):
            return (None, 0)
        first = buffer[pos]
        if first < 0xFB:
            return (first, 1)
        if first == 0xFC and pos + 2 < len(buffer):
            return (int.from_bytes(buffer[pos + 1 : pos + 3], "little"), 3)
        if first == 0xFD and pos + 3 < len(buffer):
            return (int.from_bytes(buffer[pos + 1 : pos + 4], "little"), 4)
        if first == 0xFE and pos + 8 < len(buffer):
            return (int.from_bytes(buffer[pos + 1 : pos + 9], "little"), 9)
        return (None, 0)

    @staticmethod
    def _send_packet(conn: socket.socket, *, sequence: int, payload: bytes) -> bool:
        length = len(payload).to_bytes(3, "little")
        packet = length + bytes([sequence & 0xFF]) + payload
        try:
            conn.sendall(packet)
            return True
        except OSError:
            return False

    @staticmethod
    def _read_packet(conn: socket.socket) -> tuple[int, bytes] | None:
        header = Emulator._recv_exact(conn, 4)
        if not header:
            return None
        length = int.from_bytes(header[0:3], "little")
        if length > Emulator._MAX_PACKET_PAYLOAD_BYTES:
            return None
        sequence = header[3]
        payload = Emulator._recv_exact(conn, length)
        if payload is None:
            return None
        return (sequence, payload)

    @staticmethod
    def _recv_exact(conn: socket.socket, size: int) -> bytes | None:
        if size < 0 or size > Emulator._MAX_PACKET_PAYLOAD_BYTES:
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
    def _ok_packet() -> bytes:
        return b"\x00\x00\x00\x02\x00\x00\x00"

    @staticmethod
    def _err_packet(message: str) -> bytes:
        encoded = message.encode("utf-8", errors="replace")
        return b"\xff\x48\x04#HY000" + encoded

    @staticmethod
    def _lenenc_int(value: int) -> bytes:
        if value < 0xFB:
            return bytes([value])
        if value <= 0xFFFF:
            return b"\xFC" + value.to_bytes(2, "little")
        if value <= 0xFFFFFF:
            return b"\xFD" + value.to_bytes(3, "little")
        return b"\xFE" + value.to_bytes(8, "little")

    @staticmethod
    def _lenenc_str(value: str) -> bytes:
        encoded = value.encode("utf-8")
        return Emulator._lenenc_int(len(encoded)) + encoded

    @staticmethod
    def _column_definition(*, name: str) -> bytes:
        payload = bytearray()
        payload.extend(Emulator._lenenc_str("def"))
        payload.extend(Emulator._lenenc_str(""))
        payload.extend(Emulator._lenenc_str(""))
        payload.extend(Emulator._lenenc_str(""))
        payload.extend(Emulator._lenenc_str(name))
        payload.extend(Emulator._lenenc_str(name))
        payload.extend(b"\x0c")
        payload.extend((33).to_bytes(2, "little"))
        payload.extend((1024).to_bytes(4, "little"))
        payload.extend(b"\xfd")
        payload.extend((0).to_bytes(2, "little"))
        payload.extend(b"\x00")
        payload.extend(b"\x00\x00")
        return bytes(payload)

    @staticmethod
    def _row_packet(values: list[str]) -> bytes:
        payload = bytearray()
        for value in values:
            payload.extend(Emulator._lenenc_str(value))
        return bytes(payload)
