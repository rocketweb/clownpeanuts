import asyncio
from collections.abc import Callable
import http.client
import json
import socket
import struct
import time
from typing import Any
from urllib.parse import urlencode

from clownpeanuts.config.schema import BanditConfig, BanditSafetyCapsConfig, EngineConfig, NarrativeConfig, ServiceConfig
from clownpeanuts.core.logging import EventLogger, get_logger
from clownpeanuts.core.session import SessionManager
from clownpeanuts.engine.rabbit_hole import RabbitHoleEngine
from clownpeanuts.intel.lure_bandit import LureBandit
from clownpeanuts.services.base import ServiceRuntime
from clownpeanuts.services.database.memcached_emulator import Emulator as MemcachedDbEmulator
from clownpeanuts.services.database.mongo_emulator import Emulator as MongoDbEmulator
from clownpeanuts.services.database.mysql_emulator import Emulator as MySQLDbEmulator
from clownpeanuts.services.database.postgres_emulator import Emulator as PostgresDbEmulator
from clownpeanuts.services.database.redis_emulator import Emulator as RedisDbEmulator
from clownpeanuts.services.http.emulator import Emulator as HttpEmulator
from clownpeanuts.services.ssh.emulator import Emulator as SshEmulator


def _recv_until(sock: socket.socket, marker: bytes, timeout_seconds: float = 3.0) -> bytes:
    deadline = time.time() + timeout_seconds
    chunks = bytearray()
    while time.time() < deadline:
        try:
            data = sock.recv(4096)
        except TimeoutError:
            break
        if not data:
            break
        chunks.extend(data)
        if marker in chunks:
            break
    return bytes(chunks)


def _runtime() -> ServiceRuntime:
    session_manager = SessionManager()
    event_logger = EventLogger(logger=get_logger("clownpeanuts.test.events"), service_name="test")
    return ServiceRuntime(session_manager=session_manager, event_logger=event_logger, event_bus=None)


def _runtime_with_narrative() -> ServiceRuntime:
    runtime = _runtime()
    runtime.rabbit_hole = RabbitHoleEngine(
        EngineConfig(),
        narrative_config=NarrativeConfig(enabled=True, world_seed="test-narrative", entity_count=80, per_tenant_worlds=True),
    )
    return runtime


def _runtime_with_narrative_and_bandit() -> ServiceRuntime:
    runtime = _runtime_with_narrative()
    bandit = LureBandit(
        BanditConfig(
            enabled=True,
            algorithm="thompson",
            exploration_floor=0.0,
            safety_caps=BanditSafetyCapsConfig(max_arm_exposure_percent=1.0, cooldown_seconds=0.0, denylist=[]),
        )
    )

    def _select(context_key: str, candidates: list[str]) -> dict[str, object]:
        decision = bandit.select_arm(context_key=context_key, candidates=candidates, now_epoch=1000.0)
        return {
            "context_key": decision.context_key,
            "selected_arm": decision.selected_arm,
            "algorithm": decision.algorithm,
            "exploration_floor": decision.exploration_floor,
            "exploration_applied": decision.exploration_applied,
            "override_applied": decision.override_applied,
            "override_expires_at": decision.override_expires_at,
            "eligible_arms": decision.eligible_arms,
            "blocked_arms": decision.blocked_arms,
            "arm_scores": decision.arm_scores,
            "total_selections": decision.total_selections,
        }

    runtime.bandit_select = _select
    return runtime


def test_ssh_emulator_listens_and_captures_events() -> None:
    emulator = SshEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="ssh",
        module="clownpeanuts.services.ssh.emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={"auth_failures_before_success": 0},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=2.0) as conn:
            banner = _recv_until(conn, b"\n")
            assert b"SSH-2.0-OpenSSH" in banner
            conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
            prompt_1 = _recv_until(conn, b"login as: ")
            assert b"login as:" in prompt_1
            conn.sendall(b"root\n")
            prompt_2 = _recv_until(conn, b"password: ")
            assert b"password:" in prompt_2
            conn.sendall(b"toor\n")
            shell_prompt = _recv_until(conn, b"$ ")
            assert b"$ " in shell_prompt
            conn.sendall(b"whoami\n")
            response = _recv_until(conn, b"$ ")
            assert b"root" in response
            conn.sendall(b"exit\n")

        snapshot = emulator.runtime.session_manager.snapshot() if emulator.runtime else {}
        assert snapshot["credential_events"] >= 1
        assert snapshot["command_events"] >= 1
    finally:
        asyncio.run(emulator.stop())


def test_ssh_emulator_stateful_shell_navigation() -> None:
    emulator = SshEmulator()
    emulator.set_runtime(_runtime())

    result = asyncio.run(
        emulator.handle_connection(
            {
                "session_id": "ssh-shell-state",
                "source_ip": "198.51.100.22",
                "source_port": 58222,
                "username": "root",
                "password": "toor",
                "attempts": [("root", "toor")],
                "commands": [
                    "pwd",
                    "cd /var/www/html",
                    "pwd",
                    "ls -la",
                    "hostnamectl",
                    "history",
                ],
            }
        )
    )

    outputs = [item["output"] for item in result["commands"]]
    assert outputs[0] == "/home/root"
    assert outputs[1] == ""
    assert outputs[2] == "/var/www/html"
    assert outputs[3]
    assert "Operating System: Ubuntu 22.04.4 LTS" in outputs[4]
    assert "/var/www/html" in outputs[5]


def test_ssh_emulator_uses_narrative_context_for_host_and_notes() -> None:
    emulator = SshEmulator()
    emulator.set_runtime(_runtime_with_narrative())

    result = asyncio.run(
        emulator.handle_connection(
            {
                "session_id": "ssh-narrative",
                "source_ip": "198.51.100.33",
                "source_port": 59333,
                "username": "root",
                "password": "toor",
                "attempts": [("root", "toor")],
                "commands": [
                    "hostname",
                    "cat notes.txt",
                ],
            }
        )
    )

    hostname_output = result["commands"][0]["output"]
    notes_output = result["commands"][1]["output"]
    assert hostname_output != "ip-172-31-44-9"
    assert "-" in hostname_output
    assert "ticket:" in notes_output


def test_ssh_emulator_realistic_admin_enumeration_commands() -> None:
    emulator = SshEmulator()
    emulator.set_runtime(_runtime())

    result = asyncio.run(
        emulator.handle_connection(
            {
                "session_id": "ssh-admin-realism",
                "source_ip": "198.51.100.71",
                "source_port": 61271,
                "username": "root",
                "password": "toor",
                "attempts": [("root", "toor")],
                "commands": [
                    "sudo -l",
                    "systemctl status ssh",
                    "journalctl -u ssh --no-pager -n 20",
                    "last -n 5",
                    "ip route",
                ],
            }
        )
    )

    outputs = [item["output"] for item in result["commands"]]
    assert "User root may run the following commands" in outputs[0]
    assert "ssh.service - OpenBSD Secure Shell server" in outputs[1]
    assert "Accepted password for root" in outputs[2]
    assert "system boot" in outputs[3]
    assert "default via 172.31.0.1" in outputs[4]


def test_ssh_emulator_extended_runtime_enumeration_realism() -> None:
    emulator = SshEmulator()
    emulator.set_runtime(_runtime())

    result = asyncio.run(
        emulator.handle_connection(
            {
                "session_id": "ssh-runtime-realism",
                "source_ip": "198.51.100.72",
                "source_port": 61272,
                "username": "root",
                "password": "toor",
                "attempts": [("root", "toor")],
                "commands": [
                    "ip a",
                    "lsblk -f",
                    "cat /etc/ssh/sshd_config",
                    "grep -n PasswordAuthentication /etc/ssh/sshd_config",
                    "tail -n 20 /var/log/auth.log",
                ],
            }
        )
    )

    outputs = [item["output"] for item in result["commands"]]
    assert "inet 172.31.44.9/20" in outputs[0]
    assert "nvme0n1p1" in outputs[1]
    assert "PasswordAuthentication yes" in outputs[2]
    assert "PasswordAuthentication yes" in outputs[3]
    assert "session opened for user root" in outputs[4]


def test_http_emulator_wp_login_capture() -> None:
    emulator = HttpEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="http-admin",
        module="clownpeanuts.services.http.emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        host, port = endpoint

        conn = http.client.HTTPConnection(host, port, timeout=3.0)
        conn.request("GET", "/wp-login.php")
        response = conn.getresponse()
        body = response.read().decode("utf-8")
        assert response.status == 200
        assert "WordPress" in body
        cookie = response.headers.get("Set-Cookie")

        payload = urlencode({"log": "admin", "pwd": "hunter2"})
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookie:
            headers["Cookie"] = cookie
        conn.request("POST", "/wp-login.php", body=payload, headers=headers)
        response = conn.getresponse()
        body = response.read().decode("utf-8")
        assert response.status == 200
        assert "Welcome back" in body
        conn.close()

        deadline = time.time() + 1.0
        snapshot = emulator.runtime.session_manager.snapshot() if emulator.runtime else {}
        while snapshot.get("credential_events", 0) < 1 and time.time() < deadline:
            time.sleep(0.05)
            snapshot = emulator.runtime.session_manager.snapshot() if emulator.runtime else {}
        assert snapshot["credential_events"] >= 1
    finally:
        asyncio.run(emulator.stop())


def test_http_emulator_renders_narrative_clues_in_login_and_dashboard() -> None:
    emulator = HttpEmulator()
    emulator.set_runtime(_runtime_with_narrative())

    result_get = asyncio.run(
        emulator.handle_connection(
            {
                "method": "GET",
                "path": "/wp-login.php",
                "source_ip": "198.51.100.44",
                "source_port": 60444,
                "session_id": "http-narrative",
            }
        )
    )
    assert result_get["status"] == 200
    assert "Site profile:" in result_get["body"]

    result_post = asyncio.run(
        emulator.handle_connection(
            {
                "method": "POST",
                "path": "/wp-login.php",
                "source_ip": "198.51.100.44",
                "source_port": 60444,
                "session_id": "http-narrative",
                "payload": {"log": "admin", "pwd": "hunter2"},
            }
        )
    )
    assert result_post["status"] == 200
    assert "Active service:" in result_post["body"]


def test_emulators_emit_lure_arm_selection_events_when_bandit_is_available() -> None:
    runtime = _runtime_with_narrative_and_bandit()
    ssh = SshEmulator()
    ssh.set_runtime(runtime)
    http = HttpEmulator()
    http.set_runtime(runtime)

    ssh_result = asyncio.run(
        ssh.handle_connection(
            {
                "session_id": "lure-arm-events",
                "source_ip": "198.51.100.62",
                "source_port": 61262,
                "username": "root",
                "password": "toor",
                "attempts": [("root", "guess"), ("root", "toor")],
                "commands": ["cat notes.txt"],
            }
        )
    )
    assert "lure profile:" in ssh_result["commands"][0]["output"]

    http_result = asyncio.run(
        http.handle_connection(
            {
                "method": "GET",
                "path": "/internal/api/orders",
                "source_ip": "198.51.100.62",
                "source_port": 61263,
                "session_id": "lure-arm-events",
            }
        )
    )
    assert http_result["status"] == 200
    http_payload = json.loads(http_result["body"])
    assert str(http_payload.get("lure_profile", "")).startswith("http-")

    replay = runtime.session_manager.export_session("lure-arm-events", events_limit=200)
    assert replay is not None
    actions = [str(event.get("action", "")) for event in replay["events"]]
    assert "lure_arm_selection" in actions
    selection_services = {
        str(event.get("service", ""))
        for event in replay["events"]
        if str(event.get("action", "")) == "lure_arm_selection"
    }
    assert "ssh" in selection_services
    assert "http_admin" in selection_services


def test_http_emulator_auth_delay_progression() -> None:
    emulator = HttpEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="http-admin",
        module="clownpeanuts.services.http.emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={
            "auth_failures_before_success": 2,
            "auth_delay_pattern_ms": [1, 1, 1],
            "auth_delay_jitter_ratio": 0.0,
        },
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        host, port = endpoint

        conn = http.client.HTTPConnection(host, port, timeout=3.0)
        conn.request("GET", "/wp-login.php")
        response = conn.getresponse()
        response.read()
        cookie = response.headers.get("Set-Cookie")
        assert response.status == 200

        payload = urlencode({"log": "admin", "pwd": "hunter2"})
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookie:
            headers["Cookie"] = cookie

        conn.request("POST", "/wp-login.php", body=payload, headers=headers)
        response = conn.getresponse()
        body = response.read().decode("utf-8")
        assert response.status == 401
        assert "Invalid credentials" in body

        conn.request("POST", "/wp-login.php", body=payload, headers=headers)
        response = conn.getresponse()
        body = response.read().decode("utf-8")
        assert response.status == 401
        assert "Invalid credentials" in body

        conn.request("POST", "/wp-login.php", body=payload, headers=headers)
        response = conn.getresponse()
        body = response.read().decode("utf-8")
        assert response.status == 200
        assert "Welcome back" in body
        conn.close()

        deadline = time.time() + 1.0
        snapshot = emulator.runtime.session_manager.snapshot() if emulator.runtime else {}
        while snapshot.get("credential_events", 0) < 3 and time.time() < deadline:
            time.sleep(0.05)
            snapshot = emulator.runtime.session_manager.snapshot() if emulator.runtime else {}
        assert snapshot["credential_events"] >= 3
    finally:
        asyncio.run(emulator.stop())


def test_http_emulator_backup_tarpit_stream() -> None:
    emulator = HttpEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="http-admin",
        module="clownpeanuts.services.http.emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={
            "tarpit_enabled": True,
            "backup_stream_chunks": 3,
            "backup_chunk_size_bytes": 128,
            "slowdrip_min_delay_ms": 1,
            "slowdrip_max_delay_ms": 2,
        },
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        host, port = endpoint

        conn = http.client.HTTPConnection(host, port, timeout=3.0)
        conn.request("GET", "/backup.sql.gz")
        response = conn.getresponse()
        body = response.read()
        conn.close()

        assert response.status == 200
        assert response.getheader("Content-Type") == "application/octet-stream"
        assert len(body) >= 128 * 3

        snapshot = emulator.runtime.session_manager.snapshot() if emulator.runtime else {}
        assert snapshot["events"] >= 2
    finally:
        asyncio.run(emulator.stop())


def test_http_emulator_infinite_exfil_stream_trap() -> None:
    emulator = HttpEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="http-admin",
        module="clownpeanuts.services.http.emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={
            "tarpit_enabled": True,
            "infinite_exfil_enabled": True,
            "infinite_exfil_path": "/backup/live.sql.gz",
            "infinite_exfil_chunk_size_bytes": 96,
            "infinite_exfil_max_chunks": 5,
            "slowdrip_min_delay_ms": 1,
            "slowdrip_max_delay_ms": 2,
        },
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        host, port = endpoint

        conn = http.client.HTTPConnection(host, port, timeout=3.0)
        conn.request("GET", "/backup/live.sql.gz")
        response = conn.getresponse()
        body = response.read()
        conn.close()

        assert response.status == 200
        assert response.getheader("Content-Type") == "application/octet-stream"
        assert len(body) >= (96 * 5)

        deadline = time.time() + 1.0
        snapshot = emulator.runtime.session_manager.snapshot() if emulator.runtime else {}
        while snapshot.get("events", 0) < 2 and time.time() < deadline:
            time.sleep(0.05)
            snapshot = emulator.runtime.session_manager.snapshot() if emulator.runtime else {}
        assert snapshot["events"] >= 2
    finally:
        asyncio.run(emulator.stop())


def test_http_emulator_cloud_mimic_endpoints() -> None:
    emulator = HttpEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="http-admin",
        module="clownpeanuts.services.http.emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        host, port = endpoint

        conn = http.client.HTTPConnection(host, port, timeout=3.0)
        conn.request("GET", "/s3/")
        response = conn.getresponse()
        xml = response.read().decode("utf-8")
        assert response.status == 200
        assert "ListAllMyBucketsResult" in xml

        conn.request("GET", "/api/internal/orders")
        response = conn.getresponse()
        body = response.read().decode("utf-8")
        conn.close()

        assert response.status == 200
        assert "\"orders\"" in body
    finally:
        asyncio.run(emulator.stop())


def test_http_emulator_query_tarpit_search_endpoint() -> None:
    emulator = HttpEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="http-admin",
        module="clownpeanuts.services.http.emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={
            "query_tarpit_enabled": True,
            "query_tarpit_min_delay_ms": 1,
            "query_tarpit_max_delay_ms": 1,
            "query_tarpit_jitter_ratio": 0.0,
            "query_tarpit_max_page_size": 5,
            "query_tarpit_estimated_total": 30,
        },
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        host, port = endpoint

        conn = http.client.HTTPConnection(host, port, timeout=3.0)
        conn.request("GET", "/api/internal/search?q=invoice&page=2&page_size=9")
        response = conn.getresponse()
        body = response.read().decode("utf-8")
        conn.close()

        assert response.status == 200
        assert response.getheader("Content-Type") == "application/json; charset=utf-8"
        payload = json.loads(body)
        assert payload["status"] == "ok"
        assert payload["query"] == "invoice"
        assert payload["page"] == 2
        assert payload["page_size"] == 5
        assert payload["total_estimate"] >= 30
        assert len(payload["results"]) <= 5
    finally:
        asyncio.run(emulator.stop())


def test_http_emulator_internal_users_and_login_audit_endpoints() -> None:
    emulator = HttpEmulator()
    emulator.set_runtime(_runtime_with_narrative())
    config = ServiceConfig(
        name="http-admin",
        module="clownpeanuts.services.http.emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={
            "query_tarpit_enabled": True,
            "query_tarpit_min_delay_ms": 1,
            "query_tarpit_max_delay_ms": 1,
            "query_tarpit_jitter_ratio": 0.0,
            "query_tarpit_max_page_size": 7,
        },
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        host, port = endpoint

        conn = http.client.HTTPConnection(host, port, timeout=3.0)
        conn.request("GET", "/api/internal/users?q=ops&role=admin&page=2&page_size=9")
        users_response = conn.getresponse()
        users_body = users_response.read().decode("utf-8")
        assert users_response.status == 200
        assert users_response.getheader("Content-Type") == "application/json; charset=utf-8"
        users_payload = json.loads(users_body)
        assert users_payload["status"] == "ok"
        assert users_payload["page"] == 2
        assert users_payload["page_size"] == 7
        assert users_payload["filters"]["role"] == "admin"
        assert len(users_payload["users"]) <= 7
        if users_payload["users"]:
            assert users_payload["users"][0]["role"] == "admin"
            assert users_payload["users"][0]["owner_service"]

        conn.request("GET", "/api/internal/login-audit?username=admin&status=failure&limit=12&cursor=3")
        audit_response = conn.getresponse()
        audit_body = audit_response.read().decode("utf-8")
        conn.close()

        assert audit_response.status == 200
        assert audit_response.getheader("Content-Type") == "application/json; charset=utf-8"
        audit_payload = json.loads(audit_body)
        assert audit_payload["status"] == "ok"
        assert audit_payload["filters"]["username"] == "admin"
        assert audit_payload["filters"]["status"] == "failure"
        assert audit_payload["limit"] == 7
        assert len(audit_payload["records"]) <= 7
        if audit_payload["records"]:
            assert audit_payload["records"][0]["username"] == "admin"
            assert audit_payload["records"][0]["status"] == "failure"
            assert audit_payload["records"][0]["ticket"]
    finally:
        asyncio.run(emulator.stop())


def test_redis_db_emulator_commands() -> None:
    emulator = RedisDbEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="redis-db",
        module="clownpeanuts.services.database.redis_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    def send_resp(sock: socket.socket, parts: list[str]) -> bytes:
        payload = [f"*{len(parts)}\r\n".encode("utf-8")]
        for part in parts:
            encoded = part.encode("utf-8")
            payload.append(f"${len(encoded)}\r\n".encode("utf-8"))
            payload.append(encoded + b"\r\n")
        sock.sendall(b"".join(payload))
        sock.settimeout(0.4)
        chunks = bytearray()
        try:
            while True:
                chunks.extend(sock.recv(4096))
                if not chunks:
                    break
                if len(chunks) >= 3 and chunks.endswith(b"\r\n"):
                    break
        except TimeoutError:
            pass
        return bytes(chunks)

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            resp = send_resp(conn, ["PING"])
            assert b"+PONG" in resp

            resp = send_resp(conn, ["AUTH", "default", "hunter2"])
            assert b"+OK" in resp

            resp = send_resp(conn, ["SET", "apikey", "abc123"])
            assert b"+OK" in resp

            resp = send_resp(conn, ["GET", "apikey"])
            assert b"abc123" in resp

            resp = send_resp(conn, ["MSET", "token_a", "aaa", "token_b", "bbb"])
            assert b"+OK" in resp

            resp = send_resp(conn, ["MGET", "token_a", "missing", "token_b"])
            assert resp.startswith(b"*3\r\n")
            assert b"$3\r\naaa\r\n" in resp
            assert b"$-1\r\n" in resp
            assert b"$3\r\nbbb\r\n" in resp

            resp = send_resp(conn, ["HSET", "profile", "username", "admin", "role", "operator"])
            assert b":2" in resp

            resp = send_resp(conn, ["HLEN", "profile"])
            assert b":2" in resp

            resp = send_resp(conn, ["HGET", "profile", "username"])
            assert b"admin" in resp

            resp = send_resp(conn, ["HKEYS", "profile"])
            assert resp.startswith(b"*2\r\n")
            assert b"username" in resp
            assert b"role" in resp

            resp = send_resp(conn, ["HGETALL", "profile"])
            assert resp.startswith(b"*4\r\n")
            assert b"username" in resp
            assert b"admin" in resp
            assert b"role" in resp
            assert b"operator" in resp

            resp = send_resp(conn, ["TYPE", "profile"])
            assert b"+hash" in resp

            resp = send_resp(conn, ["GET", "profile"])
            assert b"-WRONGTYPE" in resp

            resp = send_resp(conn, ["HSET", "apikey", "field", "value"])
            assert b"-WRONGTYPE" in resp

            resp = send_resp(conn, ["LPUSH", "queue", "a", "b"])
            assert b":2" in resp

            resp = send_resp(conn, ["RPUSH", "queue", "c"])
            assert b":3" in resp

            resp = send_resp(conn, ["TYPE", "queue"])
            assert b"+list" in resp

            resp = send_resp(conn, ["LLEN", "queue"])
            assert b":3" in resp

            resp = send_resp(conn, ["LRANGE", "queue", "0", "-1"])
            assert resp.startswith(b"*3\r\n")
            assert b"$1\r\nb\r\n" in resp
            assert b"$1\r\na\r\n" in resp
            assert b"$1\r\nc\r\n" in resp

            resp = send_resp(conn, ["LPOP", "queue"])
            assert b"$1\r\nb\r\n" in resp

            resp = send_resp(conn, ["RPOP", "queue"])
            assert b"$1\r\nc\r\n" in resp

            resp = send_resp(conn, ["LRANGE", "queue", "0", "-1"])
            assert resp.startswith(b"*1\r\n")
            assert b"$1\r\na\r\n" in resp

            resp = send_resp(conn, ["LINDEX", "queue", "0"])
            assert b"$1\r\na\r\n" in resp

            resp = send_resp(conn, ["LINDEX", "queue", "-1"])
            assert b"$1\r\na\r\n" in resp

            resp = send_resp(conn, ["LINDEX", "queue", "99"])
            assert b"$-1\r\n" in resp

            resp = send_resp(conn, ["LSET", "queue", "0", "z"])
            assert b"+OK" in resp

            resp = send_resp(conn, ["LINDEX", "queue", "0"])
            assert b"$1\r\nz\r\n" in resp

            resp = send_resp(conn, ["LSET", "queue", "-1", "y"])
            assert b"+OK" in resp

            resp = send_resp(conn, ["LINDEX", "queue", "-1"])
            assert b"$1\r\ny\r\n" in resp

            resp = send_resp(conn, ["LSET", "queue", "5", "oops"])
            assert b"-ERR index out of range" in resp

            resp = send_resp(conn, ["LSET", "missing_list", "0", "x"])
            assert b"-ERR no such key" in resp

            resp = send_resp(conn, ["LTRIM", "queue", "0", "0"])
            assert b"+OK" in resp

            resp = send_resp(conn, ["LRANGE", "queue", "0", "-1"])
            assert resp.startswith(b"*1\r\n")
            assert b"$1\r\ny\r\n" in resp

            resp = send_resp(conn, ["LTRIM", "queue", "1", "0"])
            assert b"+OK" in resp

            resp = send_resp(conn, ["TYPE", "queue"])
            assert b"+none" in resp

            resp = send_resp(conn, ["RPUSH", "remq", "a", "b", "a", "c", "a"])
            assert b":5" in resp

            resp = send_resp(conn, ["LREM", "remq", "2", "a"])
            assert b":2\r\n" in resp

            resp = send_resp(conn, ["LRANGE", "remq", "0", "-1"])
            assert resp.startswith(b"*3\r\n")
            assert b"$1\r\nb\r\n" in resp
            assert b"$1\r\nc\r\n" in resp
            assert b"$1\r\na\r\n" in resp

            resp = send_resp(conn, ["LREM", "remq", "-1", "a"])
            assert b":1\r\n" in resp

            resp = send_resp(conn, ["LRANGE", "remq", "0", "-1"])
            assert resp.startswith(b"*2\r\n")
            assert b"$1\r\nb\r\n" in resp
            assert b"$1\r\nc\r\n" in resp

            resp = send_resp(conn, ["LREM", "remq", "0", "z"])
            assert b":0\r\n" in resp

            resp = send_resp(conn, ["LREM", "missing-remq", "1", "a"])
            assert b":0\r\n" in resp

            resp = send_resp(conn, ["RPUSH", "cycle", "1", "2", "3"])
            assert b":3" in resp

            resp = send_resp(conn, ["RPOPLPUSH", "cycle", "cycle"])
            assert b"$1\r\n3\r\n" in resp

            resp = send_resp(conn, ["LRANGE", "cycle", "0", "-1"])
            assert resp.startswith(b"*3\r\n")
            assert b"$1\r\n3\r\n" in resp
            assert b"$1\r\n1\r\n" in resp
            assert b"$1\r\n2\r\n" in resp

            resp = send_resp(conn, ["RPUSH", "moveq", "1", "2", "3"])
            assert b":3" in resp

            resp = send_resp(conn, ["LMOVE", "moveq", "move_dst", "LEFT", "RIGHT"])
            assert b"$1\r\n1\r\n" in resp

            resp = send_resp(conn, ["LRANGE", "moveq", "0", "-1"])
            assert resp.startswith(b"*2\r\n")
            assert b"$1\r\n2\r\n" in resp
            assert b"$1\r\n3\r\n" in resp

            resp = send_resp(conn, ["LRANGE", "move_dst", "0", "-1"])
            assert resp.startswith(b"*1\r\n")
            assert b"$1\r\n1\r\n" in resp

            resp = send_resp(conn, ["LMOVE", "moveq", "moveq", "RIGHT", "LEFT"])
            assert b"$1\r\n3\r\n" in resp

            resp = send_resp(conn, ["LRANGE", "moveq", "0", "-1"])
            assert resp.startswith(b"*2\r\n")
            assert b"$1\r\n3\r\n" in resp
            assert b"$1\r\n2\r\n" in resp

            resp = send_resp(conn, ["LMOVE", "missing_moveq", "move_dst", "LEFT", "RIGHT"])
            assert b"$-1\r\n" in resp

            resp = send_resp(conn, ["LMOVE", "moveq", "profile", "LEFT", "RIGHT"])
            assert b"-WRONGTYPE" in resp

            resp = send_resp(conn, ["LMOVE", "profile", "move_dst", "LEFT", "RIGHT"])
            assert b"-WRONGTYPE" in resp

            resp = send_resp(conn, ["LMOVE", "moveq", "move_dst", "UP", "LEFT"])
            assert b"-ERR syntax error" in resp

            resp = send_resp(conn, ["RPUSH", "insertq", "a", "b", "c"])
            assert b":3" in resp

            resp = send_resp(conn, ["LINSERT", "insertq", "BEFORE", "b", "x"])
            assert b":4\r\n" in resp

            resp = send_resp(conn, ["LINSERT", "insertq", "AFTER", "b", "y"])
            assert b":5\r\n" in resp

            resp = send_resp(conn, ["LRANGE", "insertq", "0", "-1"])
            assert resp.startswith(b"*5\r\n")
            assert b"$1\r\na\r\n" in resp
            assert b"$1\r\nx\r\n" in resp
            assert b"$1\r\nb\r\n" in resp
            assert b"$1\r\ny\r\n" in resp
            assert b"$1\r\nc\r\n" in resp

            resp = send_resp(conn, ["LINSERT", "insertq", "BEFORE", "missing", "z"])
            assert b":-1\r\n" in resp

            resp = send_resp(conn, ["LINSERT", "missing_insertq", "BEFORE", "a", "z"])
            assert b":0\r\n" in resp

            resp = send_resp(conn, ["LINSERT", "insertq", "MIDDLE", "a", "z"])
            assert b"-ERR syntax error" in resp

            resp = send_resp(conn, ["RPUSH", "posq", "a", "b", "a", "c", "a", "b"])
            assert b":6" in resp

            resp = send_resp(conn, ["LPOS", "posq", "a"])
            assert b":0\r\n" in resp

            resp = send_resp(conn, ["LPOS", "posq", "a", "RANK", "2"])
            assert b":2\r\n" in resp

            resp = send_resp(conn, ["LPOS", "posq", "a", "RANK", "-1"])
            assert b":4\r\n" in resp

            resp = send_resp(conn, ["LPOS", "posq", "a", "RANK", "2", "COUNT", "2"])
            assert resp.startswith(b"*2\r\n")
            assert b":2\r\n" in resp
            assert b":4\r\n" in resp

            resp = send_resp(conn, ["LPOS", "posq", "a", "RANK", "-1", "COUNT", "2"])
            assert resp.startswith(b"*2\r\n")
            assert b":4\r\n" in resp
            assert b":2\r\n" in resp

            resp = send_resp(conn, ["LPOS", "posq", "a", "COUNT", "0"])
            assert resp.startswith(b"*3\r\n")
            assert b":0\r\n" in resp
            assert b":2\r\n" in resp
            assert b":4\r\n" in resp

            resp = send_resp(conn, ["LPOS", "posq", "a", "MAXLEN", "2", "RANK", "2"])
            assert b"$-1\r\n" in resp

            resp = send_resp(conn, ["LPOS", "posq", "z"])
            assert b"$-1\r\n" in resp

            resp = send_resp(conn, ["LPOS", "missing-posq", "a"])
            assert b"$-1\r\n" in resp

            resp = send_resp(conn, ["LPOS", "missing-posq", "a", "COUNT", "2"])
            assert resp == b"*0\r\n"

            resp = send_resp(conn, ["LPOS", "posq", "a", "RANK", "0"])
            assert b"-ERR RANK can't be zero" in resp

            resp = send_resp(conn, ["LPOS", "posq", "a", "COUNT", "-1"])
            assert b"-ERR COUNT can't be negative" in resp

            resp = send_resp(conn, ["LPOS", "posq", "a", "MAXLEN", "-1"])
            assert b"-ERR MAXLEN can't be negative" in resp

            resp = send_resp(conn, ["LPOS", "posq", "a", "RANK"])
            assert b"-ERR syntax error" in resp

            resp = send_resp(conn, ["SET", "plain_list_dst", "value"])
            assert b"+OK" in resp

            resp = send_resp(conn, ["RPOPLPUSH", "cycle", "plain_list_dst"])
            assert b"-WRONGTYPE" in resp

            resp = send_resp(conn, ["LINDEX", "profile", "0"])
            assert b"-WRONGTYPE" in resp

            resp = send_resp(conn, ["LSET", "profile", "0", "oops"])
            assert b"-WRONGTYPE" in resp

            resp = send_resp(conn, ["LTRIM", "profile", "0", "1"])
            assert b"-WRONGTYPE" in resp

            resp = send_resp(conn, ["LREM", "profile", "1", "oops"])
            assert b"-WRONGTYPE" in resp

            resp = send_resp(conn, ["LINSERT", "profile", "BEFORE", "username", "oops"])
            assert b"-WRONGTYPE" in resp

            resp = send_resp(conn, ["LPOS", "profile", "username"])
            assert b"-WRONGTYPE" in resp

            resp = send_resp(conn, ["LPUSH", "profile", "oops"])
            assert b"-WRONGTYPE" in resp

            resp = send_resp(conn, ["SADD", "operators", "alice", "bob", "bob"])
            assert b":2" in resp

            resp = send_resp(conn, ["SCARD", "operators"])
            assert b":2" in resp

            resp = send_resp(conn, ["SISMEMBER", "operators", "alice"])
            assert b":1" in resp

            resp = send_resp(conn, ["SMEMBERS", "operators"])
            assert resp.startswith(b"*2\r\n")
            assert b"alice" in resp
            assert b"bob" in resp

            resp = send_resp(conn, ["SREM", "operators", "bob"])
            assert b":1" in resp

            resp = send_resp(conn, ["SADD", "operators", "bob"])
            assert b":1" in resp

            resp = send_resp(conn, ["SRANDMEMBER", "operators"])
            assert resp.startswith(b"$")
            assert b"alice" in resp or b"bob" in resp

            resp = send_resp(conn, ["SRANDMEMBER", "operators", "2"])
            assert resp.startswith(b"*2\r\n")
            assert b"alice" in resp
            assert b"bob" in resp

            resp = send_resp(conn, ["SPOP", "operators"])
            assert resp.startswith(b"$")

            resp = send_resp(conn, ["SCARD", "operators"])
            assert b":1" in resp

            resp = send_resp(conn, ["SPOP", "operators", "5"])
            assert resp.startswith(b"*1\r\n")

            resp = send_resp(conn, ["TYPE", "operators"])
            assert b"+none" in resp

            resp = send_resp(conn, ["SADD", "src", "east", "west"])
            assert b":2" in resp

            resp = send_resp(conn, ["SMOVE", "src", "dst", "east"])
            assert b":1" in resp

            resp = send_resp(conn, ["SISMEMBER", "dst", "east"])
            assert b":1" in resp

            resp = send_resp(conn, ["SISMEMBER", "src", "east"])
            assert b":0" in resp

            resp = send_resp(conn, ["SMOVE", "src", "dst", "missing"])
            assert b":0" in resp

            resp = send_resp(conn, ["SET", "plain", "value"])
            assert b"+OK" in resp

            resp = send_resp(conn, ["SMOVE", "src", "plain", "west"])
            assert b"-WRONGTYPE" in resp

            resp = send_resp(conn, ["SADD", "set_a", "one", "two", "three"])
            assert b":3" in resp

            resp = send_resp(conn, ["SADD", "set_b", "two", "three", "four"])
            assert b":3" in resp

            resp = send_resp(conn, ["SUNION", "set_a", "set_b"])
            assert resp.startswith(b"*4\r\n")
            assert b"one" in resp
            assert b"four" in resp

            resp = send_resp(conn, ["SINTER", "set_a", "set_b"])
            assert resp.startswith(b"*2\r\n")
            assert b"two" in resp
            assert b"three" in resp

            resp = send_resp(conn, ["SINTERCARD", "2", "set_a", "set_b"])
            assert b":2" in resp

            resp = send_resp(conn, ["SINTERCARD", "2", "set_a", "set_b", "LIMIT", "1"])
            assert b":1" in resp

            resp = send_resp(conn, ["SDIFF", "set_a", "set_b"])
            assert resp.startswith(b"*1\r\n")
            assert b"one" in resp

            resp = send_resp(conn, ["SMISMEMBER", "set_a", "one", "four"])
            assert resp.startswith(b"*2\r\n")
            assert b":1\r\n" in resp
            assert b":0\r\n" in resp

            resp = send_resp(conn, ["SUNIONSTORE", "set_union", "set_a", "set_b"])
            assert b":4" in resp

            resp = send_resp(conn, ["TYPE", "set_union"])
            assert b"+set" in resp

            resp = send_resp(conn, ["SCARD", "set_union"])
            assert b":4" in resp

            resp = send_resp(conn, ["SINTERSTORE", "set_inter", "set_a", "set_b"])
            assert b":2" in resp

            resp = send_resp(conn, ["SMEMBERS", "set_inter"])
            assert resp.startswith(b"*2\r\n")
            assert b"two" in resp
            assert b"three" in resp

            resp = send_resp(conn, ["SDIFFSTORE", "set_diff", "set_a", "set_b"])
            assert b":1" in resp

            resp = send_resp(conn, ["SMEMBERS", "set_diff"])
            assert resp.startswith(b"*1\r\n")
            assert b"one" in resp

            resp = send_resp(conn, ["SET", "store_dest", "value"])
            assert b"+OK" in resp

            resp = send_resp(conn, ["SUNIONSTORE", "store_dest", "set_a", "set_b"])
            assert b":4" in resp

            resp = send_resp(conn, ["TYPE", "store_dest"])
            assert b"+set" in resp

            resp = send_resp(conn, ["SUNION", "set_a", "plain"])
            assert b"-WRONGTYPE" in resp

            resp = send_resp(conn, ["SUNIONSTORE", "set_bad", "plain", "set_a"])
            assert b"-WRONGTYPE" in resp

            resp = send_resp(conn, ["TYPE", "operators"])
            assert b"+none" in resp

            resp = send_resp(conn, ["GET", "operators"])
            assert b"$-1" in resp

            resp = send_resp(conn, ["SADD", "profile", "x"])
            assert b"-WRONGTYPE" in resp

            resp = send_resp(conn, ["SCAN", "0", "MATCH", "token_*", "COUNT", "1"])
            assert resp.startswith(b"*2\r\n")
            assert b"$1\r\n1\r\n" in resp
            assert b"token_" in resp

            resp = send_resp(conn, ["SCAN", "1", "MATCH", "token_*", "COUNT", "5"])
            assert resp.startswith(b"*2\r\n")
            assert b"$1\r\n0\r\n" in resp
            assert b"token_" in resp

            resp = send_resp(conn, ["INCR", "counter"])
            assert b":1" in resp

            resp = send_resp(conn, ["INCR", "counter"])
            assert b":2" in resp

            resp = send_resp(conn, ["SET", "ephemeral", "live"])
            assert b"+OK" in resp

            resp = send_resp(conn, ["TYPE", "ephemeral"])
            assert b"+string" in resp

            resp = send_resp(conn, ["PTTL", "ephemeral"])
            assert b":-1" in resp

            resp = send_resp(conn, ["TTL", "ephemeral"])
            assert b":-1" in resp

            resp = send_resp(conn, ["EXPIRE", "ephemeral", "10"])
            assert b":1" in resp

            resp = send_resp(conn, ["TTL", "ephemeral"])
            ttl_value = int(resp.decode("utf-8", errors="replace").strip().lstrip(":"))
            assert 0 <= ttl_value <= 10

            resp = send_resp(conn, ["PTTL", "ephemeral"])
            pttl_value = int(resp.decode("utf-8", errors="replace").strip().lstrip(":"))
            assert 0 <= pttl_value <= 10000

            resp = send_resp(conn, ["PERSIST", "ephemeral"])
            assert b":1" in resp

            resp = send_resp(conn, ["PTTL", "ephemeral"])
            assert b":-1" in resp

            resp = send_resp(conn, ["EXPIRE", "ephemeral", "0"])
            assert b":1" in resp

            resp = send_resp(conn, ["TYPE", "ephemeral"])
            assert b"+none" in resp

            resp = send_resp(conn, ["TTL", "ephemeral"])
            assert b":-2" in resp

            resp = send_resp(conn, ["QUIT"])
            assert b"+OK" in resp

        snapshot = emulator.runtime.session_manager.snapshot() if emulator.runtime else {}
        assert snapshot["credential_events"] >= 1
        assert snapshot["command_events"] >= 1
    finally:
        asyncio.run(emulator.stop())


def test_memcached_db_emulator_commands_and_auth() -> None:
    emulator = MemcachedDbEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="memcached-db",
        module="clownpeanuts.services.database.memcached_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    def send_line(sock: socket.socket, line: str, *, expect_end: bool = False) -> bytes:
        sock.sendall(line.encode("utf-8"))
        sock.settimeout(0.5)
        chunks = bytearray()
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.extend(chunk)
                if expect_end and b"END\r\n" in chunks:
                    break
                if not expect_end and chunks.endswith(b"\r\n"):
                    break
        except TimeoutError:
            pass
        return bytes(chunks)

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            resp = send_line(conn, "version\r\n")
            assert b"VERSION" in resp

            resp = send_line(conn, "auth list\r\n", expect_end=True)
            assert b"MECHS PLAIN" in resp

            resp = send_line(conn, "auth plain AGFkbWluAGh1bnRlcjI=\r\n")
            assert b"OK" in resp

            resp = send_line(conn, "stats settings\r\n", expect_end=True)
            assert b"STAT item_size_max 65536" in resp

            resp = send_line(conn, "set token 0 0 6\r\nabc123\r\n")
            assert b"STORED" in resp

            resp = send_line(conn, "get token\r\n", expect_end=True)
            assert b"VALUE token" in resp
            assert b"abc123" in resp

            resp = send_line(conn, "gets token\r\n", expect_end=True)
            first_line = resp.decode("utf-8", errors="replace").splitlines()[0]
            cas_token = first_line.split()[-1]
            assert cas_token.isdigit()

            resp = send_line(conn, f"cas token 0 0 3 {cas_token}\r\nxyz\r\n")
            assert b"STORED" in resp

            resp = send_line(conn, "append token 0 0 1\r\n!\r\n")
            assert b"STORED" in resp

            resp = send_line(conn, "prepend token 0 0 1\r\n^\r\n")
            assert b"STORED" in resp

            resp = send_line(conn, "get token\r\n", expect_end=True)
            assert b"^xyz!" in resp

            resp = send_line(conn, "set huge 0 0 999999\r\n")
            assert b"object too large for cache" in resp

            long_key = "x" * 5000
            resp = send_line(conn, f"get {long_key}\r\n")
            assert b"command line too long" in resp

        snapshot = emulator.runtime.session_manager.snapshot() if emulator.runtime else {}
        assert snapshot["credential_events"] >= 1
        assert snapshot["command_events"] >= 8
    finally:
        asyncio.run(emulator.stop())


def test_redis_db_emulator_enforces_total_store_budget() -> None:
    emulator = RedisDbEmulator()
    emulator._MAX_TOTAL_STORE_BYTES = 9
    config = ServiceConfig(
        name="redis-db",
        module="clownpeanuts.services.database.redis_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    def send_resp(sock: socket.socket, parts: list[str]) -> bytes:
        payload = [f"*{len(parts)}\r\n".encode("utf-8")]
        for part in parts:
            encoded = part.encode("utf-8")
            payload.append(f"${len(encoded)}\r\n".encode("utf-8"))
            payload.append(encoded + b"\r\n")
        sock.sendall(b"".join(payload))
        sock.settimeout(0.5)
        chunks = bytearray()
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.extend(chunk)
                if chunks.endswith(b"\r\n"):
                    break
        except TimeoutError:
            pass
        return bytes(chunks)

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            first = send_resp(conn, ["SET", "a", "12345"])
            assert b"+OK" in first
            second = send_resp(conn, ["SET", "b", "67890"])
            assert second.startswith(b"-OOM")
    finally:
        asyncio.run(emulator.stop())


def test_memcached_db_emulator_enforces_value_and_store_budgets() -> None:
    emulator = MemcachedDbEmulator()
    emulator._MAX_VALUE_BYTES = 8
    emulator._MAX_TOTAL_STORE_BYTES = 16
    config = ServiceConfig(
        name="memcached-db",
        module="clownpeanuts.services.database.memcached_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    def send_line(sock: socket.socket, line: str, *, expect_end: bool = False) -> bytes:
        sock.sendall(line.encode("utf-8"))
        sock.settimeout(0.5)
        chunks = bytearray()
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.extend(chunk)
                if expect_end and b"END\r\n" in chunks:
                    break
                if not expect_end and chunks.endswith(b"\r\n"):
                    break
        except TimeoutError:
            pass
        return bytes(chunks)

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            resp = send_line(conn, "set token 0 0 6\r\nabc123\r\n")
            assert b"STORED" in resp

            resp = send_line(conn, "append token 0 0 3\r\nXYZ\r\n")
            assert b"value too large" in resp

            resp = send_line(conn, "set k1 0 0 6\r\nAAAAAA\r\n")
            assert b"STORED" in resp

            resp = send_line(conn, "set k2 0 0 6\r\nBBBBBB\r\n")
            assert b"out of memory storing object" in resp
    finally:
        asyncio.run(emulator.stop())


def _mysql_recv_packet(sock: socket.socket) -> tuple[int, bytes]:
    header = bytearray()
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            raise RuntimeError("unexpected EOF while reading mysql header")
        header.extend(chunk)
    length = int.from_bytes(header[:3], "little")
    sequence = header[3]
    payload = bytearray()
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            raise RuntimeError("unexpected EOF while reading mysql payload")
        payload.extend(chunk)
    return (sequence, bytes(payload))


def _mysql_send_packet(sock: socket.socket, *, sequence: int, payload: bytes) -> None:
    sock.sendall(len(payload).to_bytes(3, "little") + bytes([sequence & 0xFF]) + payload)


def _mysql_recv_result_rows(sock: socket.socket) -> list[bytes]:
    _, column_count_payload = _mysql_recv_packet(sock)
    column_count = int(column_count_payload[0]) if column_count_payload else 0
    for _ in range(column_count):
        _mysql_recv_packet(sock)  # column definition
    _mysql_recv_packet(sock)  # eof
    rows: list[bytes] = []
    while True:
        _, payload = _mysql_recv_packet(sock)
        if payload.startswith(b"\xfe") and len(payload) <= 5:
            break
        rows.append(payload)
    return rows


def _pg_recv_message(sock: socket.socket) -> tuple[bytes, bytes]:
    msg_type = sock.recv(1)
    if not msg_type:
        raise RuntimeError("unexpected EOF while reading postgres message type")
    length_raw = sock.recv(4)
    if len(length_raw) < 4:
        raise RuntimeError("unexpected EOF while reading postgres message length")
    length = int.from_bytes(length_raw, "big")
    payload = bytearray()
    while len(payload) < length - 4:
        chunk = sock.recv(length - 4 - len(payload))
        if not chunk:
            raise RuntimeError("unexpected EOF while reading postgres payload")
        payload.extend(chunk)
    return (msg_type, bytes(payload))


def _pg_send_message(sock: socket.socket, msg_type: bytes, payload: bytes) -> None:
    sock.sendall(msg_type + struct.pack("!I", len(payload) + 4) + payload)


def _pg_query_rows(sock: socket.socket, query: str) -> list[bytes]:
    _pg_send_message(sock, b"Q", query.encode("utf-8") + b"\x00")
    rows: list[bytes] = []
    while True:
        msg_type, payload = _pg_recv_message(sock)
        if msg_type == b"D":
            rows.append(payload)
        if msg_type == b"Z":
            break
    return rows


def _mongo_recv_frame(sock: socket.socket) -> tuple[int, int, bytes]:
    header = bytearray()
    while len(header) < 16:
        chunk = sock.recv(16 - len(header))
        if not chunk:
            raise RuntimeError("unexpected EOF while reading mongo header")
        header.extend(chunk)
    message_length, request_id, _response_to, opcode = struct.unpack("<iiii", bytes(header))
    if message_length < 16:
        raise RuntimeError("invalid mongo message length")
    payload = bytearray()
    while len(payload) < message_length - 16:
        chunk = sock.recv(message_length - 16 - len(payload))
        if not chunk:
            raise RuntimeError("unexpected EOF while reading mongo payload")
        payload.extend(chunk)
    return (request_id, opcode, bytes(payload))


def _mongo_send_op_msg(
    sock: socket.socket,
    *,
    request_id: int,
    document: dict[str, Any],
    encode_document: Callable[[dict[str, Any]], bytes],
) -> None:
    bson = encode_document(document)
    body = struct.pack("<I", 0) + b"\x00" + bson
    header = struct.pack("<iiii", 16 + len(body), request_id, 0, 2013)
    sock.sendall(header + body)


def _mongo_decode_op_msg_document(
    payload: bytes,
    decode_document: Callable[[bytes, int], tuple[dict[str, Any], int]],
) -> dict[str, Any]:
    if len(payload) < 5 or payload[4] != 0:
        raise RuntimeError("invalid mongo op_msg payload")
    document, _ = decode_document(payload, 5)
    return document


def test_mysql_db_emulator_handshake_and_query() -> None:
    emulator = MySQLDbEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="mysql-db",
        module="clownpeanuts.services.database.mysql_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            conn.settimeout(2.0)
            _, handshake = _mysql_recv_packet(conn)
            assert handshake and handshake[0] == 0x0A

            capabilities = 0x00000200 | 0x00008000 | 0x00080000
            login = (
                capabilities.to_bytes(4, "little")
                + (1024 * 1024).to_bytes(4, "little")
                + b"\x21"
                + (b"\x00" * 23)
                + b"root\x00"
                + b"\x08"
                + b"hunter2!"
                + b"mysql_native_password\x00"
            )
            _mysql_send_packet(conn, sequence=1, payload=login)
            _, login_resp = _mysql_recv_packet(conn)
            assert login_resp.startswith(b"\x00")

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SELECT 1")
            _, query_resp = _mysql_recv_packet(conn)
            assert query_resp in {b"\x01", b"\x00\x00\x00\x02\x00\x00\x00"}

            _mysql_send_packet(conn, sequence=0, payload=b"\x01")

        snapshot = emulator.runtime.session_manager.snapshot() if emulator.runtime else {}
        assert snapshot["credential_events"] >= 1
        assert snapshot["command_events"] >= 1
    finally:
        asyncio.run(emulator.stop())


def test_mysql_db_emulator_supports_show_databases() -> None:
    emulator = MySQLDbEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="mysql-db",
        module="clownpeanuts.services.database.mysql_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            conn.settimeout(2.0)
            _mysql_recv_packet(conn)  # handshake

            capabilities = 0x00000200 | 0x00008000 | 0x00080000
            login = (
                capabilities.to_bytes(4, "little")
                + (1024 * 1024).to_bytes(4, "little")
                + b"\x21"
                + (b"\x00" * 23)
                + b"root\x00"
                + b"\x08"
                + b"hunter2!"
                + b"mysql_native_password\x00"
            )
            _mysql_send_packet(conn, sequence=1, payload=login)
            _mysql_recv_packet(conn)  # auth ok

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SHOW DATABASES")
            _, column_count = _mysql_recv_packet(conn)
            assert column_count == b"\x01"
            _, column_definition = _mysql_recv_packet(conn)
            assert b"Database" in column_definition
            _, eof = _mysql_recv_packet(conn)
            assert eof.startswith(b"\xfe")

            rows: list[bytes] = []
            while True:
                _, payload = _mysql_recv_packet(conn)
                if payload.startswith(b"\xfe") and len(payload) <= 5:
                    break
                rows.append(payload)
            assert any(b"wordpress" in row for row in rows)

            _mysql_send_packet(conn, sequence=0, payload=b"\x01")
    finally:
        asyncio.run(emulator.stop())


def test_mysql_db_emulator_supports_prepare_execute_and_use_db() -> None:
    emulator = MySQLDbEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="mysql-db",
        module="clownpeanuts.services.database.mysql_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            conn.settimeout(2.0)
            _mysql_recv_packet(conn)  # handshake

            capabilities = 0x00000200 | 0x00008000 | 0x00080000
            login = (
                capabilities.to_bytes(4, "little")
                + (1024 * 1024).to_bytes(4, "little")
                + b"\x21"
                + (b"\x00" * 23)
                + b"root\x00"
                + b"\x08"
                + b"hunter2!"
                + b"mysql_native_password\x00"
            )
            _mysql_send_packet(conn, sequence=1, payload=login)
            _mysql_recv_packet(conn)  # auth ok

            _mysql_send_packet(conn, sequence=0, payload=b"\x02staging")
            _, init_db_resp = _mysql_recv_packet(conn)
            assert init_db_resp.startswith(b"\x00")

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SELECT DATABASE()")
            _mysql_recv_packet(conn)  # column count
            _mysql_recv_packet(conn)  # column definition
            _mysql_recv_packet(conn)  # eof
            _, db_row = _mysql_recv_packet(conn)
            assert b"staging" in db_row
            _mysql_recv_packet(conn)  # eof

            _mysql_send_packet(conn, sequence=0, payload=b"\x16SELECT @@version")
            _, prepare_ok = _mysql_recv_packet(conn)
            assert prepare_ok and prepare_ok[0] == 0x00
            statement_id = int.from_bytes(prepare_ok[1:5], "little")
            assert statement_id >= 1

            execute_payload = b"\x17" + statement_id.to_bytes(4, "little") + b"\x00" + (1).to_bytes(4, "little")
            _mysql_send_packet(conn, sequence=0, payload=execute_payload)
            _, column_count = _mysql_recv_packet(conn)
            assert column_count == b"\x01"
            _mysql_recv_packet(conn)  # column definition
            _mysql_recv_packet(conn)  # eof
            _, result_row = _mysql_recv_packet(conn)
            assert b"clownpeanuts" in result_row
            _mysql_recv_packet(conn)  # eof

            close_payload = b"\x19" + statement_id.to_bytes(4, "little")
            _mysql_send_packet(conn, sequence=0, payload=close_payload)
            _mysql_send_packet(conn, sequence=0, payload=b"\x01")
    finally:
        asyncio.run(emulator.stop())


def test_mysql_db_emulator_caps_prepared_statement_inventory() -> None:
    emulator = MySQLDbEmulator()
    emulator._MAX_PREPARED_STATEMENTS = 2
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="mysql-db",
        module="clownpeanuts.services.database.mysql_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            conn.settimeout(2.0)
            _mysql_recv_packet(conn)  # handshake

            capabilities = 0x00000200 | 0x00008000 | 0x00080000
            login = (
                capabilities.to_bytes(4, "little")
                + (1024 * 1024).to_bytes(4, "little")
                + b"\x21"
                + (b"\x00" * 23)
                + b"root\x00"
                + b"\x08"
                + b"hunter2!"
                + b"mysql_native_password\x00"
            )
            _mysql_send_packet(conn, sequence=1, payload=login)
            _mysql_recv_packet(conn)  # auth ok

            _mysql_send_packet(conn, sequence=0, payload=b"\x16SELECT 1")
            _, prepare_ok_1 = _mysql_recv_packet(conn)
            assert prepare_ok_1 and prepare_ok_1[0] == 0x00

            _mysql_send_packet(conn, sequence=0, payload=b"\x16SELECT 2")
            _, prepare_ok_2 = _mysql_recv_packet(conn)
            assert prepare_ok_2 and prepare_ok_2[0] == 0x00

            _mysql_send_packet(conn, sequence=0, payload=b"\x16SELECT 3")
            _, prepare_err = _mysql_recv_packet(conn)
            assert prepare_err and prepare_err[0] == 0xFF
            assert b"too many prepared statements" in prepare_err

            _mysql_send_packet(conn, sequence=0, payload=b"\x01")
    finally:
        asyncio.run(emulator.stop())


def test_mysql_db_emulator_includes_narrative_database_variants() -> None:
    emulator = MySQLDbEmulator()
    emulator.set_runtime(_runtime_with_narrative())
    config = ServiceConfig(
        name="mysql-db",
        module="clownpeanuts.services.database.mysql_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            conn.settimeout(2.0)
            _mysql_recv_packet(conn)  # handshake

            capabilities = 0x00000200 | 0x00008000 | 0x00080000
            login = (
                capabilities.to_bytes(4, "little")
                + (1024 * 1024).to_bytes(4, "little")
                + b"\x21"
                + (b"\x00" * 23)
                + b"root\x00"
                + b"\x08"
                + b"hunter2!"
                + b"mysql_native_password\x00"
            )
            _mysql_send_packet(conn, sequence=1, payload=login)
            _mysql_recv_packet(conn)  # auth ok

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SHOW DATABASES")
            _mysql_recv_packet(conn)  # column count
            _mysql_recv_packet(conn)  # column definition
            _mysql_recv_packet(conn)  # eof

            rows: list[bytes] = []
            while True:
                _, payload = _mysql_recv_packet(conn)
                if payload.startswith(b"\xfe") and len(payload) <= 5:
                    break
                rows.append(payload)
            defaults = {b"information_schema", b"mysql", b"performance_schema", b"wordpress"}
            assert any(all(token not in row for token in defaults) for row in rows)

            _mysql_send_packet(conn, sequence=0, payload=b"\x01")
    finally:
        asyncio.run(emulator.stop())


def test_mysql_db_emulator_supports_information_schema_columns_and_counts() -> None:
    emulator = MySQLDbEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="mysql-db",
        module="clownpeanuts.services.database.mysql_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            conn.settimeout(2.0)
            _mysql_recv_packet(conn)  # handshake

            capabilities = 0x00000200 | 0x00008000 | 0x00080000
            login = (
                capabilities.to_bytes(4, "little")
                + (1024 * 1024).to_bytes(4, "little")
                + b"\x21"
                + (b"\x00" * 23)
                + b"root\x00"
                + b"\x08"
                + b"hunter2!"
                + b"mysql_native_password\x00"
            )
            _mysql_send_packet(conn, sequence=1, payload=login)
            _mysql_recv_packet(conn)  # auth ok

            _mysql_send_packet(
                conn,
                sequence=0,
                payload=b"\x03SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()",
            )
            table_rows = _mysql_recv_result_rows(conn)
            assert any(b"users" in row for row in table_rows)

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SHOW COLUMNS FROM users")
            column_rows = _mysql_recv_result_rows(conn)
            assert any(b"username" in row for row in column_rows)

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SHOW INDEX FROM users")
            index_rows = _mysql_recv_result_rows(conn)
            assert any(b"PRIMARY" in row for row in index_rows)
            assert any(b"username_uniq" in row for row in index_rows)

            _mysql_send_packet(
                conn,
                sequence=0,
                payload=b"\x03SELECT index_name, column_name FROM information_schema.statistics WHERE table_name='users'",
            )
            stats_rows = _mysql_recv_result_rows(conn)
            assert any(b"PRIMARY" in row for row in stats_rows)
            assert any(b"username" in row for row in stats_rows)

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SELECT COUNT(*) FROM orders")
            count_rows = _mysql_recv_result_rows(conn)
            assert any(b"1542" in row for row in count_rows)

            _mysql_send_packet(conn, sequence=0, payload=b"\x01")
    finally:
        asyncio.run(emulator.stop())


def test_mysql_db_emulator_supports_runtime_metadata_queries() -> None:
    emulator = MySQLDbEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="mysql-db",
        module="clownpeanuts.services.database.mysql_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            conn.settimeout(2.0)
            _mysql_recv_packet(conn)  # handshake

            capabilities = 0x00000200 | 0x00008000 | 0x00080000
            login = (
                capabilities.to_bytes(4, "little")
                + (1024 * 1024).to_bytes(4, "little")
                + b"\x21"
                + (b"\x00" * 23)
                + b"root\x00"
                + b"\x08"
                + b"hunter2!"
                + b"mysql_native_password\x00"
            )
            _mysql_send_packet(conn, sequence=1, payload=login)
            _mysql_recv_packet(conn)  # auth ok

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SHOW PROCESSLIST")
            process_rows = _mysql_recv_result_rows(conn)
            assert any(b"SHOW PROCESSLIST" in row for row in process_rows)

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SELECT @@hostname")
            host_rows = _mysql_recv_result_rows(conn)
            assert any(b"db01-clownpeanuts" in row for row in host_rows)

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SHOW VARIABLES LIKE 'version%'")
            variable_rows = _mysql_recv_result_rows(conn)
            assert any(b"version_comment" in row for row in variable_rows)
            assert any(b"clownpeanuts" in row for row in variable_rows)

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SHOW STATUS LIKE 'Threads_connected'")
            status_rows = _mysql_recv_result_rows(conn)
            assert any(b"Threads_connected" in row for row in status_rows)

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SHOW ENGINE INNODB STATUS")
            innodb_rows = _mysql_recv_result_rows(conn)
            assert any(b"InnoDB" in row for row in innodb_rows)
            assert any(b"BACKGROUND THREAD" in row for row in innodb_rows)

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SHOW MASTER STATUS")
            master_rows = _mysql_recv_result_rows(conn)
            assert any(b"mysql-bin" in row for row in master_rows)

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SHOW BINARY LOGS")
            binlog_rows = _mysql_recv_result_rows(conn)
            assert any(b"mysql-bin.000247" in row for row in binlog_rows)

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SHOW REPLICA STATUS")
            replica_rows = _mysql_recv_result_rows(conn)
            assert any(b"Slave_IO_Running" in row or b"Yes" in row for row in replica_rows)
            assert any(b"Seconds_Behind_Master" in row or b"0" in row for row in replica_rows)

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SHOW CREATE TABLE users")
            create_rows = _mysql_recv_result_rows(conn)
            assert any(b"CREATE TABLE `users`" in row for row in create_rows)
            assert any(b"username_uniq" in row for row in create_rows)

            _mysql_send_packet(conn, sequence=0, payload=b"\x03SHOW GRANTS FOR root@localhost")
            grants_rows = _mysql_recv_result_rows(conn)
            assert any(b"GRANT ALL PRIVILEGES" in row for row in grants_rows)

            _mysql_send_packet(conn, sequence=0, payload=b"\x01")
    finally:
        asyncio.run(emulator.stop())


def test_postgres_db_emulator_handshake_and_query() -> None:
    emulator = PostgresDbEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="postgres-db",
        module="clownpeanuts.services.database.postgres_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            conn.settimeout(2.0)
            startup_payload = (
                struct.pack("!I", 196608)
                + b"user\x00postgres\x00"
                + b"database\x00postgres\x00"
                + b"application_name\x00psql\x00"
                + b"\x00"
            )
            conn.sendall(struct.pack("!I", len(startup_payload) + 4) + startup_payload)

            msg_type, auth_req = _pg_recv_message(conn)
            assert msg_type == b"R"
            assert int.from_bytes(auth_req[:4], "big") == 3

            _pg_send_message(conn, b"p", b"hunter2\x00")

            saw_auth_ok = False
            saw_ready = False
            while not saw_ready:
                msg_type, payload = _pg_recv_message(conn)
                if msg_type == b"R" and int.from_bytes(payload[:4], "big") == 0:
                    saw_auth_ok = True
                if msg_type == b"Z":
                    saw_ready = True
            assert saw_auth_ok is True

            _pg_send_message(conn, b"Q", b"SELECT 1\x00")
            saw_data_or_complete = False
            while True:
                msg_type, _payload = _pg_recv_message(conn)
                if msg_type in {b"D", b"C"}:
                    saw_data_or_complete = True
                if msg_type == b"Z":
                    break
            assert saw_data_or_complete is True

            _pg_send_message(conn, b"X", b"")

        snapshot = emulator.runtime.session_manager.snapshot() if emulator.runtime else {}
        assert snapshot["credential_events"] >= 1
        assert snapshot["command_events"] >= 1
    finally:
        asyncio.run(emulator.stop())


def test_postgres_db_emulator_supports_server_version_query() -> None:
    emulator = PostgresDbEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="postgres-db",
        module="clownpeanuts.services.database.postgres_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            conn.settimeout(2.0)
            startup_payload = (
                struct.pack("!I", 196608)
                + b"user\x00postgres\x00"
                + b"database\x00postgres\x00"
                + b"application_name\x00psql\x00"
                + b"\x00"
            )
            conn.sendall(struct.pack("!I", len(startup_payload) + 4) + startup_payload)

            _pg_recv_message(conn)  # AuthenticationCleartextPassword
            _pg_send_message(conn, b"p", b"hunter2\x00")

            while True:
                msg_type, _ = _pg_recv_message(conn)
                if msg_type == b"Z":
                    break

            _pg_send_message(conn, b"Q", b"SHOW server_version;\x00")
            saw_version_row = False
            while True:
                msg_type, payload = _pg_recv_message(conn)
                if msg_type == b"D" and b"15.4-clownpeanuts" in payload:
                    saw_version_row = True
                if msg_type == b"Z":
                    break
            assert saw_version_row is True

            _pg_send_message(conn, b"X", b"")
    finally:
        asyncio.run(emulator.stop())


def test_postgres_db_emulator_supports_extended_query_flow() -> None:
    emulator = PostgresDbEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="postgres-db",
        module="clownpeanuts.services.database.postgres_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            conn.settimeout(2.0)
            startup_payload = (
                struct.pack("!I", 196608)
                + b"user\x00postgres\x00"
                + b"database\x00postgres\x00"
                + b"application_name\x00psql\x00"
                + b"\x00"
            )
            conn.sendall(struct.pack("!I", len(startup_payload) + 4) + startup_payload)

            _pg_recv_message(conn)  # AuthenticationCleartextPassword
            _pg_send_message(conn, b"p", b"hunter2\x00")
            while True:
                msg_type, _ = _pg_recv_message(conn)
                if msg_type == b"Z":
                    break

            parse_payload = b"s1\x00SELECT current_user\x00" + struct.pack("!H", 0)
            bind_payload = b"p1\x00s1\x00" + struct.pack("!H", 0) + struct.pack("!H", 0) + struct.pack("!H", 0)
            execute_payload = b"p1\x00" + struct.pack("!I", 0)
            _pg_send_message(conn, b"P", parse_payload)
            _pg_send_message(conn, b"B", bind_payload)
            _pg_send_message(conn, b"E", execute_payload)
            _pg_send_message(conn, b"S", b"")

            seen_parse_complete = False
            seen_bind_complete = False
            seen_data = False
            while True:
                msg_type, payload = _pg_recv_message(conn)
                if msg_type == b"1":
                    seen_parse_complete = True
                if msg_type == b"2":
                    seen_bind_complete = True
                if msg_type == b"D" and b"postgres" in payload:
                    seen_data = True
                if msg_type == b"Z":
                    break
            assert seen_parse_complete is True
            assert seen_bind_complete is True
            assert seen_data is True

            _pg_send_message(conn, b"X", b"")
    finally:
        asyncio.run(emulator.stop())


def test_postgres_db_emulator_caps_prepared_statement_inventory() -> None:
    emulator = PostgresDbEmulator()
    emulator._MAX_PREPARED_STATEMENTS = 2
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="postgres-db",
        module="clownpeanuts.services.database.postgres_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            conn.settimeout(2.0)
            startup_payload = (
                struct.pack("!I", 196608)
                + b"user\x00postgres\x00"
                + b"database\x00postgres\x00"
                + b"application_name\x00psql\x00"
                + b"\x00"
            )
            conn.sendall(struct.pack("!I", len(startup_payload) + 4) + startup_payload)

            _pg_recv_message(conn)  # AuthenticationCleartextPassword
            _pg_send_message(conn, b"p", b"hunter2\x00")
            while True:
                msg_type, _ = _pg_recv_message(conn)
                if msg_type == b"Z":
                    break

            parse_payload_1 = b"s1\x00SELECT 1\x00" + struct.pack("!H", 0)
            parse_payload_2 = b"s2\x00SELECT 2\x00" + struct.pack("!H", 0)
            parse_payload_3 = b"s3\x00SELECT 3\x00" + struct.pack("!H", 0)
            _pg_send_message(conn, b"P", parse_payload_1)
            msg_type, _ = _pg_recv_message(conn)
            assert msg_type == b"1"

            _pg_send_message(conn, b"P", parse_payload_2)
            msg_type, _ = _pg_recv_message(conn)
            assert msg_type == b"1"

            _pg_send_message(conn, b"P", parse_payload_3)
            msg_type, payload = _pg_recv_message(conn)
            assert msg_type == b"E"
            assert b"too many prepared statements" in payload

            _pg_send_message(conn, b"S", b"")
            while True:
                msg_type, _ = _pg_recv_message(conn)
                if msg_type == b"Z":
                    break

            _pg_send_message(conn, b"X", b"")
    finally:
        asyncio.run(emulator.stop())


def test_postgres_db_emulator_supports_catalog_and_count_queries() -> None:
    emulator = PostgresDbEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="postgres-db",
        module="clownpeanuts.services.database.postgres_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            conn.settimeout(2.0)
            startup_payload = (
                struct.pack("!I", 196608)
                + b"user\x00postgres\x00"
                + b"database\x00postgres\x00"
                + b"application_name\x00psql\x00"
                + b"\x00"
            )
            conn.sendall(struct.pack("!I", len(startup_payload) + 4) + startup_payload)

            _pg_recv_message(conn)  # AuthenticationCleartextPassword
            _pg_send_message(conn, b"p", b"hunter2\x00")
            while True:
                msg_type, _ = _pg_recv_message(conn)
                if msg_type == b"Z":
                    break

            search_path_rows = _pg_query_rows(conn, "SHOW search_path;")
            assert any(b"public" in row for row in search_path_rows)

            catalog_rows = _pg_query_rows(
                conn,
                "select schemaname, tablename from pg_catalog.pg_tables where schemaname not in ('pg_catalog','information_schema');",
            )
            assert any(b"users" in row or b"orders" in row for row in catalog_rows)

            column_rows = _pg_query_rows(
                conn,
                "select table_schema, table_name, column_name, data_type from information_schema.columns where table_name='users';",
            )
            assert any(b"password_hash" in row for row in column_rows)

            index_rows = _pg_query_rows(
                conn,
                "select indexname, indexdef from pg_indexes where tablename='users';",
            )
            assert any(b"users_pkey" in row for row in index_rows)

            count_rows = _pg_query_rows(conn, "select count(*) from audit_events;")
            assert any(b"51872" in row for row in count_rows)

            _pg_send_message(conn, b"X", b"")
    finally:
        asyncio.run(emulator.stop())


def test_postgres_db_emulator_includes_narrative_table_variants() -> None:
    emulator = PostgresDbEmulator()
    emulator.set_runtime(_runtime_with_narrative())
    config = ServiceConfig(
        name="postgres-db",
        module="clownpeanuts.services.database.postgres_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            conn.settimeout(2.0)
            startup_payload = (
                struct.pack("!I", 196608)
                + b"user\x00postgres\x00"
                + b"database\x00postgres\x00"
                + b"application_name\x00psql\x00"
                + b"\x00"
            )
            conn.sendall(struct.pack("!I", len(startup_payload) + 4) + startup_payload)

            _pg_recv_message(conn)  # AuthenticationCleartextPassword
            _pg_send_message(conn, b"p", b"hunter2\x00")
            while True:
                msg_type, _ = _pg_recv_message(conn)
                if msg_type == b"Z":
                    break

            _pg_send_message(conn, b"Q", b"select table_name from information_schema.tables;\x00")
            saw_narrative = False
            while True:
                msg_type, payload = _pg_recv_message(conn)
                if msg_type == b"D" and (b"_history" in payload or b"_audit" in payload or b"_flags" in payload):
                    saw_narrative = True
                if msg_type == b"Z":
                    break
            assert saw_narrative is True
            _pg_send_message(conn, b"X", b"")
    finally:
        asyncio.run(emulator.stop())


def test_postgres_db_emulator_supports_runtime_metadata_queries() -> None:
    emulator = PostgresDbEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="postgres-db",
        module="clownpeanuts.services.database.postgres_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            conn.settimeout(2.0)
            startup_payload = (
                struct.pack("!I", 196608)
                + b"user\x00postgres\x00"
                + b"database\x00postgres\x00"
                + b"application_name\x00psql\x00"
                + b"\x00"
            )
            conn.sendall(struct.pack("!I", len(startup_payload) + 4) + startup_payload)

            _pg_recv_message(conn)  # AuthenticationCleartextPassword
            _pg_send_message(conn, b"p", b"hunter2\x00")
            while True:
                msg_type, _ = _pg_recv_message(conn)
                if msg_type == b"Z":
                    break

            timezone_rows = _pg_query_rows(conn, "SHOW TimeZone;")
            assert any(b"UTC" in row for row in timezone_rows)

            wal_level_rows = _pg_query_rows(conn, "SHOW wal_level;")
            assert any(b"replica" in row for row in wal_level_rows)

            wal_senders_rows = _pg_query_rows(conn, "SHOW max_wal_senders;")
            assert any(b"10" in row for row in wal_senders_rows)

            app_rows = _pg_query_rows(conn, "SHOW application_name;")
            assert any(b"psql" in row for row in app_rows)

            addr_rows = _pg_query_rows(conn, "SELECT inet_server_addr();")
            assert any(b"10.41." in row for row in addr_rows)

            version_num_rows = _pg_query_rows(conn, "SELECT current_setting('server_version_num');")
            assert any(b"150004" in row for row in version_num_rows)

            recovery_rows = _pg_query_rows(conn, "SELECT pg_is_in_recovery();")
            assert any(b"f" in row for row in recovery_rows)

            activity_rows = _pg_query_rows(
                conn,
                "select pid, usename, application_name, client_addr, state, query from pg_stat_activity;",
            )
            assert any(b"postgres" in row for row in activity_rows)
            assert any(b"psql" in row for row in activity_rows)

            lock_rows = _pg_query_rows(
                conn,
                "select locktype, mode, granted, pid from pg_locks;",
            )
            assert any(b"AccessShareLock" in row for row in lock_rows)
            assert any(b"RowExclusiveLock" in row for row in lock_rows)

            stat_db_rows = _pg_query_rows(
                conn,
                "select datname, numbackends, xact_commit, xact_rollback from pg_stat_database;",
            )
            assert any(b"postgres" in row for row in stat_db_rows)
            assert any(b"template1" in row for row in stat_db_rows)

            stat_table_rows = _pg_query_rows(
                conn,
                "select relname, seq_scan, idx_scan, n_live_tup from pg_stat_user_tables;",
            )
            assert any(b"users" in row or b"orders" in row for row in stat_table_rows)

            role_rows = _pg_query_rows(
                conn,
                "select rolname, rolsuper, rolcanlogin from pg_roles;",
            )
            assert any(b"postgres" in row for row in role_rows)
            assert any(b"app_rw" in row for row in role_rows)

            namespace_rows = _pg_query_rows(
                conn,
                "select nspname from pg_namespace;",
            )
            assert any(b"public" in row for row in namespace_rows)
            assert any(b"pg_catalog" in row for row in namespace_rows)

            extension_rows = _pg_query_rows(
                conn,
                "select extname, extversion from pg_extension;",
            )
            assert any(b"plpgsql" in row for row in extension_rows)

            settings_rows = _pg_query_rows(
                conn,
                "select name, setting, unit from pg_settings where name in ('max_connections', 'shared_buffers');",
            )
            assert any(b"max_connections" in row for row in settings_rows)
            assert any(b"shared_buffers" in row for row in settings_rows)

            replication_rows = _pg_query_rows(
                conn,
                "select pid, client_addr, application_name, state, sent_lsn, write_lsn, flush_lsn from pg_stat_replication;",
            )
            assert any(b"replica01" in row for row in replication_rows)
            assert any(b"streaming" in row for row in replication_rows)

            _pg_send_message(conn, b"X", b"")
    finally:
        asyncio.run(emulator.stop())


def test_mongo_db_emulator_op_msg_and_auth_capture() -> None:
    emulator = MongoDbEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="mongo-db",
        module="clownpeanuts.services.database.mongo_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            conn.settimeout(2.0)

            _mongo_send_op_msg(
                conn,
                request_id=11,
                document={"hello": 1, "$db": "admin"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            hello_response = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert hello_response.get("ok") == 1.0
            assert hello_response.get("helloOk") is True

            _mongo_send_op_msg(
                conn,
                request_id=12,
                document={
                    "saslStart": 1,
                    "mechanism": "SCRAM-SHA-256",
                    "payload": b"n,,n=admin,r=fakenonce",
                    "$db": "admin",
                },
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            auth_response = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert auth_response.get("ok") == 1.0
            assert auth_response.get("conversationId") == 1

            _mongo_send_op_msg(
                conn,
                request_id=13,
                document={"find": "users", "filter": {"role": "admin"}, "$db": "app"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            find_response = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert find_response.get("ok") == 1.0

        snapshot = emulator.runtime.session_manager.snapshot() if emulator.runtime else {}
        assert snapshot["credential_events"] >= 1
        assert snapshot["command_events"] >= 3
    finally:
        asyncio.run(emulator.stop())


def test_mongo_db_emulator_supports_list_collections_and_stats() -> None:
    emulator = MongoDbEmulator()
    emulator.set_runtime(_runtime())
    config = ServiceConfig(
        name="mongo-db",
        module="clownpeanuts.services.database.mongo_emulator",
        listen_host="127.0.0.1",
        ports=[0],
        config={},
    )

    asyncio.run(emulator.start(config))
    try:
        endpoint = emulator.bound_endpoint
        assert endpoint is not None
        with socket.create_connection(endpoint, timeout=3.0) as conn:
            conn.settimeout(2.0)

            _mongo_send_op_msg(
                conn,
                request_id=31,
                document={"listCollections": 1, "$db": "app"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            list_collections = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert list_collections.get("ok") == 1.0
            cursor = list_collections.get("cursor", {})
            assert isinstance(cursor, dict)
            first_batch = cursor.get("firstBatch", [])
            assert isinstance(first_batch, list)
            assert any(isinstance(item, dict) and item.get("name") == "users" for item in first_batch)

            _mongo_send_op_msg(
                conn,
                request_id=32,
                document={"count": "orders", "$db": "app"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            count_response = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert count_response.get("ok") == 1.0
            assert int(count_response.get("n", 0)) >= 1000

            _mongo_send_op_msg(
                conn,
                request_id=33,
                document={"collStats": "events", "$db": "app"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            coll_stats = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert coll_stats.get("ok") == 1.0
            assert str(coll_stats.get("ns", "")).endswith(".events")
            assert int(coll_stats.get("count", 0)) >= 1000

            _mongo_send_op_msg(
                conn,
                request_id=34,
                document={"serverStatus": 1, "$db": "admin"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            server_status = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert server_status.get("ok") == 1.0
            assert server_status.get("process") == "mongod"
            assert "connections" in server_status

            _mongo_send_op_msg(
                conn,
                request_id=35,
                document={"getCmdLineOpts": 1, "$db": "admin"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            cmdline_opts = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert cmdline_opts.get("ok") == 1.0
            parsed = cmdline_opts.get("parsed", {})
            assert isinstance(parsed, dict)
            assert "net" in parsed

            _mongo_send_op_msg(
                conn,
                request_id=36,
                document={"replSetGetStatus": 1, "$db": "admin"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            repl_status = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert repl_status.get("ok") == 1.0
            assert repl_status.get("set") == "rs0"
            members = repl_status.get("members", [])
            assert isinstance(members, list)
            assert len(members) >= 2

            _mongo_send_op_msg(
                conn,
                request_id=361,
                document={"replSetGetConfig": 1, "$db": "admin"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            repl_config = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert repl_config.get("ok") == 1.0
            config_doc = repl_config.get("config", {})
            assert isinstance(config_doc, dict)
            assert config_doc.get("_id") == "rs0"
            config_members = config_doc.get("members", [])
            assert isinstance(config_members, list)
            assert len(config_members) >= 2

            _mongo_send_op_msg(
                conn,
                request_id=37,
                document={"connectionStatus": 1, "$db": "admin"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            connection_status = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert connection_status.get("ok") == 1.0
            auth_info = connection_status.get("authInfo", {})
            assert isinstance(auth_info, dict)
            assert isinstance(auth_info.get("authenticatedUsers", []), list)

            _mongo_send_op_msg(
                conn,
                request_id=38,
                document={"currentOp": 1, "$db": "admin"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            current_op = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert current_op.get("ok") == 1.0
            inprog = current_op.get("inprog", [])
            assert isinstance(inprog, list)
            assert len(inprog) >= 1

            _mongo_send_op_msg(
                conn,
                request_id=39,
                document={"getLog": "*", "$db": "admin"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            get_log_names = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert get_log_names.get("ok") == 1.0
            names = get_log_names.get("names", [])
            assert isinstance(names, list)
            assert "global" in names

            _mongo_send_op_msg(
                conn,
                request_id=40,
                document={"whatsmyuri": 1, "$db": "admin"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            whats_my_uri = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert whats_my_uri.get("ok") == 1.0
            assert ":" in str(whats_my_uri.get("you", ""))

            _mongo_send_op_msg(
                conn,
                request_id=41,
                document={"hostInfo": 1, "$db": "admin"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            host_info = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert host_info.get("ok") == 1.0
            system = host_info.get("system", {})
            assert isinstance(system, dict)
            assert system.get("hostname") == "db01.internal"

            _mongo_send_op_msg(
                conn,
                request_id=42,
                document={"usersInfo": {"user": "admin", "db": "admin"}, "$db": "admin"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            users_info = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert users_info.get("ok") == 1.0
            users = users_info.get("users", [])
            assert isinstance(users, list)
            assert users and isinstance(users[0], dict)
            assert users[0].get("user") == "admin"

            _mongo_send_op_msg(
                conn,
                request_id=43,
                document={"rolesInfo": {"role": "readWrite", "db": "app"}, "$db": "admin"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            roles_info = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert roles_info.get("ok") == 1.0
            roles = roles_info.get("roles", [])
            assert isinstance(roles, list)
            assert roles and isinstance(roles[0], dict)
            assert roles[0].get("role") == "readWrite"

            _mongo_send_op_msg(
                conn,
                request_id=44,
                document={"listIndexes": "users", "$db": "app"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            list_indexes = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert list_indexes.get("ok") == 1.0
            cursor = list_indexes.get("cursor", {})
            assert isinstance(cursor, dict)
            first_batch = cursor.get("firstBatch", [])
            assert isinstance(first_batch, list)
            assert any(isinstance(item, dict) and item.get("name") == "_id_" for item in first_batch)
            assert any(isinstance(item, dict) and item.get("name") == "username_1" for item in first_batch)

            _mongo_send_op_msg(
                conn,
                request_id=45,
                document={
                    "getParameter": 1,
                    "featureCompatibilityVersion": 1,
                    "authenticationMechanisms": 1,
                    "$db": "admin",
                },
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            get_parameter = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert get_parameter.get("ok") == 1.0
            fcv = get_parameter.get("featureCompatibilityVersion", {})
            assert isinstance(fcv, dict)
            assert fcv.get("version") == "7.0"
            assert "SCRAM-SHA-256" in str(get_parameter.get("authenticationMechanisms", ""))

            _mongo_send_op_msg(
                conn,
                request_id=46,
                document={"listCommands": 1, "$db": "admin"},
                encode_document=emulator._encode_document,
            )
            _, opcode, payload = _mongo_recv_frame(conn)
            assert opcode == 2013
            list_commands = _mongo_decode_op_msg_document(payload, emulator._decode_document)
            assert list_commands.get("ok") == 1.0
            commands = list_commands.get("commands", {})
            assert isinstance(commands, dict)
            assert "serverStatus" in commands
            assert "listCollections" in commands
    finally:
        asyncio.run(emulator.stop())
