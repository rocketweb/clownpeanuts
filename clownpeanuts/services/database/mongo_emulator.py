"""MongoDB-protocol honeypot emulator with credential and query capture."""

from __future__ import annotations

import base64
import re
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


_OP_REPLY = 1
_OP_QUERY = 2004
_OP_MSG = 2013
_SSL_REQUEST_CODE = 80877103


class Emulator(ServiceEmulator):
    _MAX_MESSAGE_SIZE_BYTES = 8 * 1024 * 1024

    def __init__(self) -> None:
        super().__init__()
        self.logger = get_logger("clownpeanuts.services.database.mongo")
        self._server: _ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._bound_host: str | None = None
        self._bound_port: int | None = None
        self._socket_timeout_seconds = 45.0
        self._server_version = "6.0.12-clownpeanuts"
        self._max_concurrent_connections = 256
        self._response_id = 9000
        self._counter_lock = threading.Lock()
        self._tarpit = AdaptiveThrottle(service_name=self.name)

    @property
    def name(self) -> str:
        return "mongo_db"

    @property
    def default_ports(self) -> list[int]:
        return [27017, 27018]

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
                message="mongo emulator started",
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
                message="mongo emulator stopped",
                service=self.name,
                action="service_stop",
                event_type="end",
            )

    async def handle_connection(self, conn: dict[str, Any]) -> dict[str, Any]:
        command = str(conn.get("command", "ping"))
        source_ip = str(conn.get("source_ip", "127.0.0.1"))
        source_port = int(conn.get("source_port", 0))
        session_id = str(conn.get("session_id", f"mongo-{uuid4().hex}"))
        if self.runtime:
            self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
            self._record_command(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                command=command,
                document={"synthetic": True},
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
        activity_type = str(payload.get("type", "database_query")).strip().lower()
        if activity_type not in {"database_query", "mongo_command", "query"}:
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
        session_id = str(payload.get("session_id", f"mongo-injected-{uuid4().hex[:12]}")).strip()
        if not session_id:
            session_id = f"mongo-injected-{uuid4().hex[:12]}"

        command = str(payload.get("command", "find")).strip() or "find"
        document = payload.get("document")
        if not isinstance(document, dict):
            details = payload.get("payload")
            document = dict(details) if isinstance(details, dict) else {"synthetic": True}

        self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
        self._record_command(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            command=command,
            document=document,
        )
        self._maybe_record_auth(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            command=command,
            document=document,
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

        class MongoHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                emulator._handle_client(self.request, self.client_address)

        return MongoHandler

    def _handle_client(self, conn: socket.socket, client_address: tuple[str, int]) -> None:
        conn.settimeout(self._socket_timeout_seconds)
        source_ip, source_port = client_address
        session_id = f"mongo-{source_ip}-{uuid4().hex[:12]}"
        if self.runtime:
            self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
            self.runtime.event_logger.emit(
                message="mongo connection opened",
                service=self.name,
                action="connection_open",
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                event_type="access",
                outcome="success",
            )

        while True:
            frame = self._read_frame(conn)
            if frame is None:
                return
            request_id, opcode, payload = frame
            if opcode == _OP_MSG:
                command_doc = self._parse_op_msg(payload)
                if command_doc is None:
                    return
                command_name = self._extract_command_name(command_doc)
                self._record_command(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    command=command_name,
                    document=command_doc,
                )
                self._maybe_record_auth(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    command=command_name,
                    document=command_doc,
                )
                self._tarpit.maybe_delay(
                    runtime=self.runtime,
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    trigger="mongo_op_msg_response",
                )
                response_doc = self._response_for_command(
                    command_name,
                    command_doc,
                    session_id=session_id,
                    source_ip=source_ip,
                )
                response = self._build_op_msg(request_id=request_id, document=response_doc)
                if not self._send(conn, response):
                    return
                continue

            if opcode == _OP_QUERY:
                query_doc = self._parse_op_query(payload)
                if query_doc is None:
                    return
                command_name = self._extract_command_name(query_doc)
                self._record_command(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    command=command_name,
                    document=query_doc,
                )
                self._maybe_record_auth(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    command=command_name,
                    document=query_doc,
                )
                self._tarpit.maybe_delay(
                    runtime=self.runtime,
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    trigger="mongo_op_query_response",
                )
                response_doc = self._response_for_command(
                    command_name,
                    query_doc,
                    session_id=session_id,
                    source_ip=source_ip,
                )
                response = self._build_op_reply(request_id=request_id, document=response_doc)
                if not self._send(conn, response):
                    return
                continue

            error_doc = {"ok": 0.0, "errmsg": f"unsupported opCode {opcode}"}
            self._tarpit.maybe_delay(
                runtime=self.runtime,
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                trigger="mongo_error_response",
            )
            if not self._send(conn, self._build_op_msg(request_id=request_id, document=error_doc)):
                return

    def _response_for_command(
        self,
        command_name: str,
        command_doc: dict[str, Any],
        *,
        session_id: str | None = None,
        source_ip: str | None = None,
    ) -> dict[str, Any]:
        lower = command_name.lower()
        if lower in {"hello", "ismaster", "isMaster"}:
            return {
                "ok": 1.0,
                "isWritablePrimary": True,
                "helloOk": True,
                "maxWireVersion": 17,
                "minWireVersion": 0,
                "logicalSessionTimeoutMinutes": 30,
                "connectionId": self._next_response_id(),
                "setName": "rs0",
                "hosts": ["db01.internal:27017", "db02.internal:27017"],
            }
        if lower == "ping":
            return {"ok": 1.0}
        if lower == "buildinfo":
            return {
                "ok": 1.0,
                "version": self._server_version,
                "gitVersion": "4b95f8f5f4f4c9f2",
                "modules": [],
            }
        if lower == "listdatabases":
            return {
                "ok": 1.0,
                "totalSize": 162201600,
                "databases": [
                    {"name": "admin", "sizeOnDisk": 8388608, "empty": False},
                    {"name": "app", "sizeOnDisk": 153812992, "empty": False},
                ],
            }
        if lower == "listcollections":
            database_name = str(command_doc.get("$db", "app"))
            collections = self._collections_for_database(database_name=database_name)
            first_batch = [
                {
                    "name": name,
                    "type": "collection",
                    "options": {},
                    "info": {"readOnly": False, "uuid": f"{database_name}-{index + 1:02d}"},
                }
                for index, name in enumerate(collections)
            ]
            return {
                "ok": 1.0,
                "cursor": {
                    "id": 0,
                    "ns": f"{database_name}.$cmd.listCollections",
                    "firstBatch": first_batch,
                },
            }
        if lower == "find":
            database_name = str(command_doc.get("$db", "app"))
            collection_name = str(command_doc.get("find", "users"))
            namespace = f"{database_name}.{collection_name}"
            return {
                "ok": 1.0,
                "cursor": {
                    "id": 0,
                    "ns": namespace,
                    "firstBatch": self._find_results(collection_name=collection_name),
                },
            }
        if lower == "aggregate":
            database_name = str(command_doc.get("$db", "app"))
            collection_name = str(command_doc.get("aggregate", "events"))
            namespace = f"{database_name}.{collection_name}"
            summary = [{"_id": "login", "count": 118}, {"_id": "password_reset", "count": 9}]
            return {"ok": 1.0, "cursor": {"id": 0, "ns": namespace, "firstBatch": summary}}
        if lower in {"count", "countdocuments"}:
            collection_name = str(command_doc.get(command_name, command_doc.get("find", "users")))
            return {"ok": 1.0, "n": self._collection_row_count(collection_name=collection_name)}
        if lower == "collstats":
            database_name = str(command_doc.get("$db", "app"))
            collection_name = str(command_doc.get("collStats", "users"))
            objects = self._collection_row_count(collection_name=collection_name)
            avg_obj_size = 512
            size = objects * avg_obj_size
            return {
                "ok": 1.0,
                "ns": f"{database_name}.{collection_name}",
                "count": objects,
                "size": size,
                "avgObjSize": avg_obj_size,
                "storageSize": size * 2,
                "nindexes": 2,
                "totalIndexSize": 16384,
            }
        if lower == "dbstats":
            database_name = str(command_doc.get("$db", "app"))
            collections = self._collections_for_database(database_name=database_name)
            objects = sum(self._collection_row_count(collection_name=name) for name in collections)
            avg_obj_size = 512
            return {
                "ok": 1.0,
                "db": database_name,
                "collections": len(collections),
                "objects": objects,
                "avgObjSize": avg_obj_size,
                "dataSize": objects * avg_obj_size,
                "storageSize": objects * avg_obj_size * 2,
                "indexes": len(collections) * 2,
                "indexSize": len(collections) * 16384,
            }
        if lower == "serverstatus":
            return {
                "ok": 1.0,
                "host": "db01.internal",
                "version": self._server_version,
                "process": "mongod",
                "uptime": 42851,
                "connections": {"current": 18, "available": 838842, "totalCreated": 1251},
                "opcounters": {
                    "insert": 4211,
                    "query": 15924,
                    "update": 3802,
                    "delete": 97,
                    "command": 50112,
                },
            }
        if lower == "getcmdlineopts":
            return {
                "ok": 1.0,
                "argv": ["mongod", "--config", "/etc/mongod.conf"],
                "parsed": {
                    "net": {"bindIp": "0.0.0.0", "port": 27017},
                    "storage": {"dbPath": "/var/lib/mongodb", "journal": {"enabled": True}},
                    "systemLog": {"destination": "file", "path": "/var/log/mongodb/mongod.log"},
                },
            }
        if lower == "replsetgetstatus":
            return {
                "ok": 1.0,
                "set": "rs0",
                "date": "2026-02-20T12:00:00Z",
                "myState": 1,
                "members": [
                    {"_id": 0, "name": "db01.internal:27017", "state": 1, "stateStr": "PRIMARY", "health": 1},
                    {"_id": 1, "name": "db02.internal:27017", "state": 2, "stateStr": "SECONDARY", "health": 1},
                ],
            }
        if lower == "replsetgetconfig":
            return {
                "ok": 1.0,
                "config": {
                    "_id": "rs0",
                    "version": 17,
                    "term": 6,
                    "protocolVersion": 1,
                    "members": [
                        {"_id": 0, "host": "db01.internal:27017", "priority": 2, "votes": 1},
                        {"_id": 1, "host": "db02.internal:27017", "priority": 1, "votes": 1},
                    ],
                    "settings": {
                        "chainingAllowed": True,
                        "electionTimeoutMillis": 10000,
                        "heartbeatIntervalMillis": 2000,
                    },
                },
            }
        if lower == "connectionstatus":
            return {
                "ok": 1.0,
                "authInfo": {
                    "authenticatedUsers": [{"user": "admin", "db": "admin"}],
                    "authenticatedUserRoles": [{"role": "root", "db": "admin"}],
                },
            }
        if lower == "currentop":
            return {
                "ok": 1.0,
                "inprog": [
                    {
                        "opid": 100101,
                        "active": True,
                        "secs_running": 2,
                        "ns": "app.users",
                        "op": "query",
                        "command": {"find": "users", "filter": {"role": "admin"}},
                        "client": f"{source_ip or '203.0.113.10'}:53422",
                    },
                    {
                        "opid": 100102,
                        "active": False,
                        "secs_running": 0,
                        "ns": "app.events",
                        "op": "command",
                        "command": {"aggregate": "events"},
                        "client": "10.10.2.17:41208",
                    },
                ],
            }
        if lower == "getlog":
            requested = str(command_doc.get("getLog", "global")).strip()
            if requested == "*":
                return {"ok": 1.0, "names": ["global", "startupWarnings", "diagnosticLog"]}
            return {
                "ok": 1.0,
                "totalLinesWritten": 1452,
                "log": [
                    "2026-02-20T10:12:44.325+0000 I NETWORK [listener] connection accepted from 10.10.2.17:41208 #421",
                    "2026-02-20T10:12:44.511+0000 I COMMAND [conn421] command app.users command: find { find: \"users\", filter: { role: \"admin\" } }",
                    "2026-02-20T10:13:01.108+0000 I COMMAND [conn421] command admin.$cmd command: serverStatus { serverStatus: 1 }",
                ],
            }
        if lower == "whatsmyuri":
            return {"ok": 1.0, "you": f"{source_ip or '203.0.113.10'}:53422"}
        if lower == "hostinfo":
            return {
                "ok": 1.0,
                "system": {
                    "hostname": "db01.internal",
                    "cpuAddrSize": 64,
                    "numCores": 4,
                    "memSizeMB": 16384,
                },
                "os": {
                    "type": "Linux",
                    "name": "Ubuntu",
                    "version": "22.04",
                },
            }
        if lower == "listindexes":
            database_name = str(command_doc.get("$db", "app"))
            collection_name = str(command_doc.get("listIndexes", "users")).strip() or "users"
            namespace = f"{database_name}.{collection_name}"
            return {
                "ok": 1.0,
                "cursor": {
                    "id": 0,
                    "ns": f"{database_name}.$cmd.listIndexes",
                    "firstBatch": self._collection_index_specs(collection_name=collection_name, namespace=namespace),
                },
            }
        if lower == "getparameter":
            catalog: dict[str, Any] = {
                "featureCompatibilityVersion": {"version": "7.0"},
                "authenticationMechanisms": "SCRAM-SHA-1,SCRAM-SHA-256",
                "maxIncomingConnections": 65536,
                "logLevel": 0,
            }
            raw_request = command_doc.get("getParameter", 1)
            requested: list[str] = []
            if isinstance(raw_request, str):
                explicit = raw_request.strip()
                if explicit and explicit != "*":
                    requested.append(explicit)
            if isinstance(raw_request, str) and raw_request.strip() == "*":
                requested = sorted(catalog.keys())
            else:
                for key, value in command_doc.items():
                    if str(key) in {"getParameter", "$db"}:
                        continue
                    if bool(value):
                        requested.append(str(key))
            deduped = []
            seen: set[str] = set()
            for item in requested:
                if item in seen:
                    continue
                seen.add(item)
                deduped.append(item)
            if not deduped:
                deduped = ["featureCompatibilityVersion"]
            response: dict[str, Any] = {"ok": 1.0}
            for item in deduped:
                if item in catalog:
                    response[item] = catalog[item]
            if len(response) == 1:
                response["featureCompatibilityVersion"] = catalog["featureCompatibilityVersion"]
            return response
        if lower == "listcommands":
            return {
                "ok": 1.0,
                "commands": {
                    "ping": {"help": "check connection liveness", "requiresAuth": False},
                    "buildInfo": {"help": "return server build metadata", "requiresAuth": False},
                    "serverStatus": {"help": "return server runtime metrics", "requiresAuth": True},
                    "listDatabases": {"help": "list available databases", "requiresAuth": True},
                    "listCollections": {"help": "list collections in current database", "requiresAuth": True},
                    "listIndexes": {"help": "list indexes for a collection", "requiresAuth": True},
                    "usersInfo": {"help": "return user documents", "requiresAuth": True},
                    "rolesInfo": {"help": "return role documents", "requiresAuth": True},
                    "getParameter": {"help": "read server parameters", "requiresAuth": True},
                },
            }
        if lower == "usersinfo":
            requested = command_doc.get("usersInfo", 1)
            if isinstance(requested, dict):
                target_user = str(requested.get("user", "admin")).strip() or "admin"
                target_db = str(requested.get("db", "admin")).strip() or "admin"
            else:
                target_user = "admin"
                target_db = "admin"
            return {
                "ok": 1.0,
                "users": [
                    {
                        "_id": f"{target_db}.{target_user}",
                        "user": target_user,
                        "db": target_db,
                        "roles": [{"role": "root", "db": "admin"}],
                    }
                ],
            }
        if lower == "rolesinfo":
            requested = command_doc.get("rolesInfo", 1)
            role_name = "readWrite"
            role_db = "app"
            if isinstance(requested, dict):
                role_name = str(requested.get("role", role_name)).strip() or role_name
                role_db = str(requested.get("db", role_db)).strip() or role_db
            return {
                "ok": 1.0,
                "roles": [
                    {
                        "role": role_name,
                        "db": role_db,
                        "isBuiltin": role_name in {"root", "readWrite", "read"},
                        "roles": [{"role": "read", "db": role_db}],
                        "inheritedPrivileges": [
                            {
                                "resource": {"db": role_db, "collection": ""},
                                "actions": ["find", "insert", "update", "remove"],
                            }
                        ],
                    }
                ],
            }
        if lower == "saslstart":
            return {
                "ok": 1.0,
                "conversationId": 1,
                "done": False,
                "payload": b"r=servernonce,s=U0FMVA==,i=4096",
            }
        if lower == "saslcontinue":
            return {
                "ok": 1.0,
                "conversationId": int(command_doc.get("conversationId", 1)),
                "done": True,
                "payload": b"v=fakesignature==",
            }
        if lower == "authenticate":
            return {"ok": 1.0}
        if lower == "getnonce":
            return {"ok": 1.0, "nonce": "41d5bb53ef1f4f91a28dcd93b13e"}
        if self.runtime and self.runtime.rabbit_hole and session_id and source_ip:
            return self.runtime.rabbit_hole.respond_database_command(
                service=self.name,
                session_id=session_id,
                source_ip=source_ip,
                command=command_name,
                document=command_doc,
                tenant_id=self.runtime.tenant_id,
            )
        return {"ok": 1.0, "note": f"command '{command_name}' handled by honeypot"}

    @staticmethod
    def _collections_for_database(*, database_name: str) -> list[str]:
        normalized = database_name.strip().lower()
        if normalized == "admin":
            return ["system.version", "system.users", "audit"]
        if normalized == "config":
            return ["settings", "chunks", "collections"]
        return ["users", "orders", "events", "feature_flags"]

    @staticmethod
    def _collection_row_count(*, collection_name: str) -> int:
        normalized = collection_name.strip().lower()
        if normalized in {"users", "system.users"}:
            return 143
        if "order" in normalized:
            return 1674
        if "event" in normalized or "audit" in normalized:
            return 54219
        if "flag" in normalized:
            return 34
        return 64

    @staticmethod
    def _find_results(*, collection_name: str) -> list[dict[str, Any]]:
        normalized = collection_name.strip().lower()
        if normalized in {"users", "system.users"}:
            return [
                {"_id": "u-1001", "username": "admin", "role": "admin", "status": "active"},
                {"_id": "u-1022", "username": "deploy-bot", "role": "service", "status": "active"},
            ]
        if "order" in normalized:
            return [
                {"_id": "ord-77841", "status": "processing", "totalCents": 12400},
                {"_id": "ord-77842", "status": "shipped", "totalCents": 8900},
            ]
        if "event" in normalized:
            return [
                {"_id": "evt-1", "type": "login", "severity": "info"},
                {"_id": "evt-2", "type": "password_reset", "severity": "warn"},
            ]
        return [{"_id": "doc-1", "note": f"sample row for {collection_name or 'collection'}"}]

    @staticmethod
    def _collection_index_specs(*, collection_name: str, namespace: str) -> list[dict[str, Any]]:
        normalized = collection_name.strip().lower()
        indexes: list[dict[str, Any]] = [{"v": 2, "key": {"_id": 1}, "name": "_id_", "ns": namespace}]
        if normalized in {"users", "system.users"}:
            indexes.append({"v": 2, "key": {"username": 1}, "name": "username_1", "ns": namespace, "unique": True})
            indexes.append({"v": 2, "key": {"email": 1}, "name": "email_1", "ns": namespace, "unique": True})
            return indexes
        if "order" in normalized:
            indexes.append({"v": 2, "key": {"status": 1}, "name": "status_1", "ns": namespace})
            indexes.append({"v": 2, "key": {"createdAt": -1}, "name": "createdAt_-1", "ns": namespace})
            return indexes
        if "event" in normalized or "audit" in normalized:
            indexes.append({"v": 2, "key": {"type": 1}, "name": "type_1", "ns": namespace})
            indexes.append({"v": 2, "key": {"ts": -1}, "name": "ts_-1", "ns": namespace})
            return indexes
        key_name = f"{normalized or 'field'}_key"
        indexes.append({"v": 2, "key": {key_name: 1}, "name": f"{key_name}_1", "ns": namespace})
        return indexes

    def _record_command(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        command: str,
        document: dict[str, Any],
    ) -> None:
        if not self.runtime:
            return
        payload = {
            "source_ip": source_ip,
            "protocol": "mongodb",
            "command": command,
            "document": self._for_log(document),
        }
        self.runtime.session_manager.record_event(
            session_id=session_id,
            service=self.name,
            action="command",
            payload=payload,
        )
        self.runtime.event_logger.emit(
            message="mongo command",
            service=self.name,
            action="command",
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            event_type="info",
            outcome="success",
            payload=payload,
        )

    def _maybe_record_auth(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        command: str,
        document: dict[str, Any],
    ) -> None:
        lower = command.lower()
        if lower not in {"saslstart", "saslcontinue", "authenticate", "getnonce"}:
            return

        username = ""
        password = str(document.get("pwd", ""))
        payload_value = document.get("payload")
        scram_preview = ""
        if isinstance(payload_value, (bytes, bytearray)):
            raw = bytes(payload_value)
            try:
                scram_preview = raw.decode("utf-8", errors="replace")
            except Exception:
                scram_preview = raw.hex()
            username = self._extract_scram_username(scram_preview)
        elif isinstance(payload_value, str):
            scram_preview = payload_value
            username = self._extract_scram_username(scram_preview)

        if not username:
            username = str(document.get("user", document.get("username", "")))
        if lower == "authenticate" and not username:
            username = str(document.get("userSource", ""))

        if not username and not password and not scram_preview:
            return

        if self.runtime:
            payload = {
                "source_ip": source_ip,
                "protocol": "mongodb",
                "command": command,
                "username": username,
                "password": password,
                "scram_payload": scram_preview[:256],
                "outcome": "success",
            }
            self.runtime.session_manager.record_event(
                session_id=session_id,
                service=self.name,
                action="auth_attempt",
                payload=payload,
            )
            self.runtime.event_logger.emit(
                message="mongo auth attempt",
                service=self.name,
                action="auth_attempt",
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                event_type="authentication",
                outcome="success",
                payload=payload,
            )

    @staticmethod
    def _extract_scram_username(value: str) -> str:
        matches = re.findall(r"n=([^,]+)", value)
        if not matches:
            return ""
        for candidate in reversed(matches):
            if candidate and candidate not in {"", "n"}:
                return candidate
        return matches[-1]

    def _read_frame(self, conn: socket.socket) -> tuple[int, int, bytes] | None:
        header = self._recv_exact(conn, 16)
        if header is None:
            return None
        message_length, request_id, _response_to, opcode = struct.unpack("<iiii", header)
        if message_length < 16 or message_length > self._MAX_MESSAGE_SIZE_BYTES:
            return None
        payload = self._recv_exact(conn, message_length - 16)
        if payload is None:
            return None
        return (request_id, opcode, payload)

    def _parse_op_msg(self, payload: bytes) -> dict[str, Any] | None:
        if len(payload) < 5:
            return None
        offset = 4  # flags
        while offset < len(payload):
            section_type = payload[offset]
            offset += 1
            if section_type == 0:
                doc, _ = self._decode_document(payload, offset)
                return doc
            if section_type == 1:
                if offset + 4 > len(payload):
                    return None
                size = int.from_bytes(payload[offset : offset + 4], "little")
                if size <= 0:
                    return None
                offset += size
                continue
            return None
        return None

    def _parse_op_query(self, payload: bytes) -> dict[str, Any] | None:
        if len(payload) < 12:
            return None
        offset = 4  # flags
        coll_end = payload.find(b"\x00", offset)
        if coll_end < 0:
            return None
        offset = coll_end + 1
        if offset + 8 > len(payload):
            return None
        offset += 8  # skip numberToSkip and numberToReturn
        doc, _ = self._decode_document(payload, offset)
        return doc

    @staticmethod
    def _extract_command_name(document: dict[str, Any]) -> str:
        for key in document:
            if key.startswith("$"):
                continue
            return key
        return "unknown"

    def _build_op_msg(self, *, request_id: int, document: dict[str, Any]) -> bytes:
        body = struct.pack("<I", 0) + b"\x00" + self._encode_document(document)
        response_id = self._next_response_id()
        header = struct.pack("<iiii", 16 + len(body), response_id, request_id, _OP_MSG)
        return header + body

    def _build_op_reply(self, *, request_id: int, document: dict[str, Any]) -> bytes:
        docs = self._encode_document(document)
        body = struct.pack("<iqii", 0, 0, 0, 1) + docs
        response_id = self._next_response_id()
        header = struct.pack("<iiii", 16 + len(body), response_id, request_id, _OP_REPLY)
        return header + body

    @staticmethod
    def _send(conn: socket.socket, data: bytes) -> bool:
        try:
            conn.sendall(data)
            return True
        except OSError:
            return False

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

    def _next_response_id(self) -> int:
        with self._counter_lock:
            self._response_id += 1
            return self._response_id

    def _decode_document(self, data: bytes, offset: int = 0) -> tuple[dict[str, Any], int]:
        if offset + 4 > len(data):
            return ({}, len(data))
        length = int.from_bytes(data[offset : offset + 4], "little")
        end = offset + length
        if length < 5 or end > len(data):
            return ({}, len(data))
        pos = offset + 4
        result: dict[str, Any] = {}
        while pos < end - 1:
            element_type = data[pos]
            pos += 1
            key, pos = self._decode_cstring(data, pos)
            value, pos = self._decode_value(data, pos, element_type)
            result[key] = value
        return (result, end)

    @staticmethod
    def _decode_cstring(data: bytes, offset: int) -> tuple[str, int]:
        end = data.find(b"\x00", offset)
        if end < 0:
            return ("", len(data))
        value = data[offset:end].decode("utf-8", errors="replace")
        return (value, end + 1)

    def _decode_value(self, data: bytes, offset: int, element_type: int) -> tuple[Any, int]:
        if element_type == 0x01 and offset + 8 <= len(data):
            return (struct.unpack_from("<d", data, offset)[0], offset + 8)
        if element_type == 0x02 and offset + 4 <= len(data):
            length = int.from_bytes(data[offset : offset + 4], "little")
            start = offset + 4
            end = start + max(0, length - 1)
            return (data[start:end].decode("utf-8", errors="replace"), start + length)
        if element_type == 0x03:
            return self._decode_document(data, offset)
        if element_type == 0x04:
            doc, new_offset = self._decode_document(data, offset)
            items = [value for _, value in sorted(doc.items(), key=lambda item: int(item[0])) if _]
            return (items, new_offset)
        if element_type == 0x05 and offset + 5 <= len(data):
            length = int.from_bytes(data[offset : offset + 4], "little")
            start = offset + 5
            end = start + length
            return (data[start:end], end)
        if element_type == 0x08 and offset + 1 <= len(data):
            return (data[offset] != 0, offset + 1)
        if element_type == 0x10 and offset + 4 <= len(data):
            return (int.from_bytes(data[offset : offset + 4], "little", signed=True), offset + 4)
        if element_type == 0x12 and offset + 8 <= len(data):
            return (int.from_bytes(data[offset : offset + 8], "little", signed=True), offset + 8)
        if element_type == 0x0A:
            return (None, offset)
        return ("", len(data))

    def _encode_document(self, document: dict[str, Any]) -> bytes:
        body = bytearray()
        for key, value in document.items():
            body.extend(self._encode_element(key, value))
        total_length = len(body) + 5
        return total_length.to_bytes(4, "little") + body + b"\x00"

    def _encode_element(self, key: str, value: Any) -> bytes:
        key_bytes = key.encode("utf-8", errors="replace") + b"\x00"
        if isinstance(value, bool):
            return b"\x08" + key_bytes + (b"\x01" if value else b"\x00")
        if isinstance(value, int):
            if -(2**31) <= value <= (2**31 - 1):
                return b"\x10" + key_bytes + value.to_bytes(4, "little", signed=True)
            return b"\x12" + key_bytes + value.to_bytes(8, "little", signed=True)
        if isinstance(value, float):
            return b"\x01" + key_bytes + struct.pack("<d", value)
        if isinstance(value, str):
            encoded = value.encode("utf-8", errors="replace")
            length = len(encoded) + 1
            return b"\x02" + key_bytes + length.to_bytes(4, "little") + encoded + b"\x00"
        if isinstance(value, (bytes, bytearray)):
            raw = bytes(value)
            return b"\x05" + key_bytes + len(raw).to_bytes(4, "little") + b"\x00" + raw
        if isinstance(value, dict):
            return b"\x03" + key_bytes + self._encode_document(value)
        if isinstance(value, list):
            array_doc = {str(index): item for index, item in enumerate(value)}
            return b"\x04" + key_bytes + self._encode_document(array_doc)
        if value is None:
            return b"\x0A" + key_bytes
        return self._encode_element(key, str(value))

    def _for_log(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self._for_log(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._for_log(item) for item in value]
        if isinstance(value, (bytes, bytearray)):
            raw = bytes(value)
            preview = raw[:128]
            encoded = base64.b64encode(preview).decode("ascii")
            return {"$binary_b64": encoded, "len": len(raw)}
        return value
