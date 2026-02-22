import http.client
from pathlib import Path
import socket
import time
from urllib.parse import urlencode
import pytest

from clownpeanuts.config.schema import parse_config
from clownpeanuts.core.orchestrator import Orchestrator
from clownpeanuts.intel.rotation import ThreatFeedRotator


def test_orchestrator_rejects_default_redis_credentials_outside_development() -> None:
    config = parse_config(
        {
            "environment": "production",
            "session": {
                "backend": "redis",
                "redis_url": "redis://:clownpeanuts-dev-redis@redis:6379/0",
            },
            "services": [],
        }
    )
    with pytest.raises(RuntimeError, match="default credentials"):
        Orchestrator(config)


def test_orchestrator_rejects_default_api_token_outside_development() -> None:
    config = parse_config(
        {
            "environment": "production",
            "api": {
                "auth_enabled": True,
                "auth_operator_tokens": ["clownpeanuts-ops-operator-token-2026"],
                "docs_enabled": False,
            },
            "services": [],
        }
    )
    with pytest.raises(RuntimeError, match="default credentials"):
        Orchestrator(config)


def test_orchestrator_allows_default_credentials_in_development() -> None:
    config = parse_config(
        {
            "environment": "development",
            "session": {
                "backend": "redis",
                "redis_url": "redis://:clownpeanuts-dev-redis@redis:6379/0",
            },
            "api": {
                "auth_enabled": True,
                "auth_operator_tokens": ["clownpeanuts-ops-operator-token-2026"],
                "docs_enabled": False,
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    assert orchestrator.config.environment == "development"


def test_orchestrator_bootstrap_and_start() -> None:
    config = parse_config(
        {
            "environment": "test",
            "network": {
                "segmentation_mode": "vxlan",
                "require_segmentation": True,
                "enforce_runtime": True,
                "allow_outbound": False,
                "allowed_egress": ["redis"],
            },
            "services": [
                {
                    "name": "dummy",
                    "module": "clownpeanuts.services.dummy.emulator",
                    "enabled": True,
                    "ports": [2022],
                    "config": {"greeting": "hi"},
                }
            ],
        }
    )
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()
    orchestrator.start_all()
    status = orchestrator.status()
    assert status["bootstrapped"] is True
    assert status["services"][0]["running"] is True
    assert status["network"]["compliant"] is True
    assert status["sessions"]["backend"] == "memory"
    assert status["event_bus"]["backend"] == "memory"
    assert "narrative" in status
    assert status["narrative"]["enabled"] is False
    assert "bandit" in status
    assert status["bandit"]["algorithm"] == "thompson"
    assert "theater" in status
    assert status["theater"]["rollout_mode"] == "observe-only"
    orchestrator.stop_all()


def _recv_until(sock: socket.socket, marker: bytes, timeout_seconds: float = 2.0) -> bytes:
    deadline = time.time() + timeout_seconds
    chunks = bytearray()
    while time.time() < deadline:
        try:
            part = sock.recv(4096)
        except TimeoutError:
            break
        if not part:
            break
        chunks.extend(part)
        if marker in chunks:
            break
    return bytes(chunks)


def _endpoint_for(orchestrator: Orchestrator, service_name: str) -> tuple[str, int]:
    for loaded in orchestrator.loaded_services:
        if loaded.config.name != service_name:
            continue
        endpoint = getattr(loaded.emulator, "bound_endpoint", None)
        if endpoint:
            return endpoint
    raise RuntimeError(f"missing endpoint for {service_name}")


def test_orchestrator_end_to_end_multi_service_capture_flow() -> None:
    config = parse_config(
        {
            "environment": "test",
            "network": {
                "segmentation_mode": "vxlan",
                "require_segmentation": True,
                "enforce_runtime": True,
                "allow_outbound": False,
                "allowed_egress": ["redis"],
            },
            "services": [
                {
                    "name": "ssh",
                    "module": "clownpeanuts.services.ssh.emulator",
                    "enabled": True,
                    "listen_host": "127.0.0.1",
                    "ports": [0],
                    "config": {
                        "auth_failures_before_success": 0,
                        "tarpit_min_delay_ms": 0,
                        "tarpit_max_delay_ms": 0,
                    },
                },
                {
                    "name": "http-admin",
                    "module": "clownpeanuts.services.http.emulator",
                    "enabled": True,
                    "listen_host": "127.0.0.1",
                    "ports": [0],
                    "config": {},
                },
                {
                    "name": "redis-db",
                    "module": "clownpeanuts.services.database.redis_emulator",
                    "enabled": True,
                    "listen_host": "127.0.0.1",
                    "ports": [0],
                    "config": {
                        "tarpit_min_delay_ms": 0,
                        "tarpit_max_delay_ms": 0,
                    },
                },
            ],
        }
    )

    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()
    try:
        orchestrator.start_all()

        ssh_host, ssh_port = _endpoint_for(orchestrator, "ssh")
        with socket.create_connection((ssh_host, ssh_port), timeout=2.0) as conn:
            _recv_until(conn, b"\n")
            conn.sendall(b"SSH-2.0-OpenSSH_9.8\r\n")
            _recv_until(conn, b"login as: ")
            conn.sendall(b"root\n")
            _recv_until(conn, b"password: ")
            conn.sendall(b"toor\n")
            _recv_until(conn, b"$ ")
            conn.sendall(b"whoami\n")
            _recv_until(conn, b"$ ")
            conn.sendall(b"exit\n")

        http_host, http_port = _endpoint_for(orchestrator, "http-admin")
        client = http.client.HTTPConnection(http_host, http_port, timeout=3.0)
        client.request("GET", "/wp-login.php")
        response = client.getresponse()
        assert response.status == 200
        response.read()
        cookie = response.headers.get("Set-Cookie", "")
        form = urlencode({"log": "admin", "pwd": "hunter2"})
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookie:
            headers["Cookie"] = cookie
        client.request("POST", "/wp-login.php", body=form, headers=headers)
        response = client.getresponse()
        assert response.status == 200
        response.read()
        client.close()

        redis_host, redis_port = _endpoint_for(orchestrator, "redis-db")
        with socket.create_connection((redis_host, redis_port), timeout=2.0) as conn:
            conn.sendall(b"*1\r\n$4\r\nPING\r\n")
            _recv_until(conn, b"\r\n")
            conn.sendall(b"*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$7\r\nhunter2\r\n")
            _recv_until(conn, b"\r\n")
            conn.sendall(b"*3\r\n$3\r\nSET\r\n$5\r\nstage\r\n$4\r\nprod\r\n")
            _recv_until(conn, b"\r\n")
            conn.sendall(b"*1\r\n$4\r\nQUIT\r\n")
            _recv_until(conn, b"\r\n")

        deadline = time.time() + 1.0
        snapshot = orchestrator.session_manager.snapshot()
        while snapshot.get("credential_events", 0) < 2 and time.time() < deadline:
            time.sleep(0.05)
            snapshot = orchestrator.session_manager.snapshot()

        assert snapshot["sessions"] >= 3
        assert snapshot["credential_events"] >= 2
        assert snapshot["command_events"] >= 3
    finally:
        orchestrator.stop_all()


def test_threat_intel_rotation_scheduler_reapplies_runtime_config(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    feed_payload = {"value": "ssh telnet brute force\n"}
    monkeypatch.setattr(
        ThreatFeedRotator,
        "_read_source",
        staticmethod(lambda _source: feed_payload["value"]),
    )
    config = parse_config(
        {
            "environment": "test",
            "network": {
                "segmentation_mode": "vxlan",
                "require_segmentation": True,
                "enforce_runtime": True,
                "allow_outbound": False,
                "allowed_egress": ["redis"],
            },
            "threat_intel": {
                "enabled": True,
                "strategy": "aggressive",
                "rotation_interval_seconds": 1,
                "feed_urls": ["https://feeds.example.test/threat-intel.txt"],
            },
            "services": [
                {
                    "name": "ssh",
                    "module": "clownpeanuts.services.ssh.emulator",
                    "enabled": True,
                    "listen_host": "127.0.0.1",
                    "ports": [0],
                    "config": {"auth_failures_before_success": 0},
                },
                {
                    "name": "http-admin",
                    "module": "clownpeanuts.services.http.emulator",
                    "enabled": True,
                    "listen_host": "127.0.0.1",
                    "ports": [0],
                    "config": {},
                },
            ],
        }
    )

    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()
    orchestrator.start_all()
    try:
        ssh_loaded = next(loaded for loaded in orchestrator.loaded_services if loaded.config.name == "ssh")
        assert ssh_loaded.config.config.get("auth_failures_before_success") == 2
        assert getattr(ssh_loaded.emulator, "_auth_failures_before_success") == 2
        first_rotation_time = orchestrator.status()["threat_intel"]["last_rotated_at"]
        assert first_rotation_time

        feed_payload["value"] = "http wordpress admin panel\n"

        deadline = time.time() + 3.5
        while time.time() < deadline:
            status = orchestrator.status()
            if status["threat_intel"]["last_profile"] == "web-heavy":
                break
            time.sleep(0.1)
        status = orchestrator.status()

        assert status["threat_intel"]["last_profile"] == "web-heavy"
        assert status["threat_intel"]["last_rotated_at"] != first_rotation_time
        assert status["threat_intel"]["scheduler_running"] is True
        assert ssh_loaded.emulator.running is True
        assert getattr(ssh_loaded.emulator, "_auth_failures_before_success") == 0
    finally:
        orchestrator.stop_all()


def test_manual_threat_intel_rotation_returns_snapshot(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        ThreatFeedRotator,
        "_read_source",
        staticmethod(lambda _source: "http wordpress admin panel\n"),
    )
    config = parse_config(
        {
            "environment": "test",
            "network": {
                "segmentation_mode": "vxlan",
                "require_segmentation": True,
                "enforce_runtime": True,
                "allow_outbound": False,
                "allowed_egress": ["redis"],
            },
            "threat_intel": {
                "enabled": True,
                "strategy": "aggressive",
                "rotation_interval_seconds": 60,
                "feed_urls": ["https://feeds.example.test/threat-intel.txt"],
            },
            "services": [
                {
                    "name": "http-admin",
                    "module": "clownpeanuts.services.http.emulator",
                    "enabled": True,
                    "listen_host": "127.0.0.1",
                    "ports": [0],
                    "config": {},
                },
            ],
        }
    )
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()
    snapshot = orchestrator.rotate_threat_intel()
    assert snapshot["enabled"] is True
    assert snapshot["rotation_trigger"] == "manual"
    assert snapshot["last_profile"] == "web-heavy"


def test_threat_intel_preview_returns_candidate_profile(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        ThreatFeedRotator,
        "_read_source",
        staticmethod(lambda _source: "ssh telnet brute force\n"),
    )
    config = parse_config(
        {
            "environment": "test",
            "threat_intel": {
                "enabled": True,
                "strategy": "aggressive",
                "rotation_interval_seconds": 60,
                "feed_urls": ["https://feeds.example.test/threat-intel.txt"],
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    preview = orchestrator.threat_intel_preview()
    assert preview["enabled"] is True
    assert preview["strategy"] == "aggressive"
    assert preview["selected_profile"] == "ssh-heavy"


def test_orchestrator_canary_ingest_and_session_replay() -> None:
    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    ingested = orchestrator.ingest_canary_hit(
        token="ct-int-001",
        source_ip="198.51.100.29",
        metadata={"channel": "dns"},
    )
    assert ingested["session_id"].startswith("canary-")
    assert ingested["tenant"] == config.multi_tenant.default_tenant

    replay = orchestrator.session_replay(session_id=ingested["session_id"], events_limit=100)
    assert replay["found"] is True
    assert replay["session"]["event_count"] == 1
    assert replay["canaries"]["total_hits"] == 1
    assert replay["canaries"]["tokens"][0]["token"] == "ct-int-001"

    token_inventory = orchestrator.canary_tokens(limit=10)
    assert token_inventory["count"] >= 1
    token_id = str(ingested["token_id"])

    token_detail = orchestrator.canary_token(token_id=token_id)
    assert token_detail["found"] is True
    assert token_detail["token"]["hit_count"] >= 1
    assert token_detail["token"]["token"] == "ct-int-001"

    hits = orchestrator.canary_hits(limit=10, token_id=token_id)
    assert hits["count"] >= 1
    assert hits["hits"][0]["token"] == "ct-int-001"


def test_orchestrator_canary_generate_persists_inventory() -> None:
    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    generated = orchestrator.generate_canary_token(namespace="corp", token_type="dns", metadata={"label": "seed"})
    assert generated["token_type"] == "dns"
    assert generated["namespace"] == "corp"
    assert generated["stored"] is True

    token_id = str(generated["token_id"])
    detail = orchestrator.canary_token(token_id=token_id)
    assert detail["found"] is True
    assert detail["token"]["metadata"]["label"] == "seed"


def test_orchestrator_session_replay_missing_returns_not_found() -> None:
    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    replay = orchestrator.session_replay(session_id="does-not-exist", events_limit=100)
    assert replay == {"found": False, "session_id": "does-not-exist", "session": None}


def test_orchestrator_session_replay_compare_returns_overlap_and_deltas() -> None:
    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    orchestrator.session_manager.get_or_create(session_id="cmp-left", source_ip="203.0.113.90")
    orchestrator.session_manager.record_event(
        session_id="cmp-left",
        service="ssh",
        action="auth_attempt",
        payload={"source_ip": "203.0.113.90", "username": "root"},
    )
    orchestrator.session_manager.record_event(
        session_id="cmp-left",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.90", "command": "whoami"},
    )

    orchestrator.session_manager.get_or_create(session_id="cmp-right", source_ip="203.0.113.91")
    orchestrator.session_manager.record_event(
        session_id="cmp-right",
        service="ssh",
        action="auth_attempt",
        payload={"source_ip": "203.0.113.91", "username": "admin"},
    )
    orchestrator.session_manager.record_event(
        session_id="cmp-right",
        service="http_admin",
        action="credential_capture",
        payload={"source_ip": "203.0.113.91", "username": "admin", "password": "hunter2"},
    )

    comparison = orchestrator.session_replay_compare(
        left_session_id="cmp-left",
        right_session_id="cmp-right",
        events_limit=100,
    )
    assert comparison["found"] is True
    payload = comparison["comparison"]
    assert "ssh" in payload["shared_services"]
    assert "http_admin" in payload["right_only_services"]
    assert "T1110" in payload["shared_techniques"]
    assert 0.0 <= float(payload["similarity"]["score"]) <= 1.0
    assert isinstance(payload["score_delta"]["event_count"], int)
    assert payload["summary"]["primary_change"] in {
        "classification_shift",
        "new_techniques",
        "service_expansion",
        "activity_increase",
        "activity_decrease",
        "minimal_change",
    }
    assert isinstance(payload["operator_actions"], list)
    assert payload["operator_actions"]


def test_orchestrator_intelligence_history_persists_reports() -> None:
    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="s1", source_ip="203.0.113.90")
    orchestrator.session_manager.record_event(
        session_id="s1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.90", "command": "nmap -sV 10.0.0.0/24"},
    )
    report = orchestrator.intelligence_report(limit=100, events_per_session=100)
    assert "report_id" in report

    history = orchestrator.intelligence_history(limit=10)
    assert history["count"] >= 1
    assert history["reports"][0]["report_id"] == report["report_id"]

    payload = orchestrator.intelligence_history_report_payload(report_id=int(report["report_id"]))
    assert payload is not None
    assert payload["totals"]["sessions"] >= 1


def test_orchestrator_service_plan_includes_template_inventory(tmp_path: Path) -> None:
    template_path = tmp_path / "template.yml"
    template_path.write_text(
        "templates:\n"
        "  - service: ssh\n"
        "    config:\n"
        "      banner: SSH-2.0-OpenSSH_9.9\n",
        encoding="utf-8",
    )
    config = parse_config(
        {
            "templates": {"enabled": True, "paths": [str(template_path)]},
            "services": [{"name": "ssh", "module": "clownpeanuts.services.ssh.emulator", "ports": [2222], "config": {}}],
        }
    )
    orchestrator = Orchestrator(config)
    inventory = orchestrator.template_inventory()
    assert inventory["template_count"] == 1
    assert "ssh" in inventory["services"]

    plan = orchestrator.service_plan()
    assert plan["count"] == 1
    assert plan["services"][0]["config"]["banner"] == "SSH-2.0-OpenSSH_9.9"

    validation = orchestrator.template_validation()
    assert validation["ok"] is True
    assert validation["error_count"] == 0
    assert validation["service_count"] == 1


def test_orchestrator_template_validation_all_tenants(tmp_path: Path) -> None:
    template_path = tmp_path / "template.yml"
    template_path.write_text(
        "templates:\n"
        "  - service: ssh\n"
        "    ports: [2222]\n",
        encoding="utf-8",
    )
    config = parse_config(
        {
            "templates": {"enabled": True, "paths": [str(template_path)]},
            "multi_tenant": {
                "enabled": True,
                "default_tenant": "tenant-a",
                "tenants": [
                    {"id": "tenant-a", "enabled": True},
                    {"id": "tenant-b", "enabled": True},
                ],
            },
            "services": [{"name": "ssh", "module": "clownpeanuts.services.ssh.emulator", "ports": [2222], "config": {}}],
        }
    )
    orchestrator = Orchestrator(config)

    validation = orchestrator.template_validation(all_tenants=True)
    assert validation["ok"] is True
    assert validation["all_tenants"] is True
    assert validation["tenant_count"] == 2
    tenant_ids = {item["tenant"] for item in validation["tenants"]}
    assert tenant_ids == {"tenant-a", "tenant-b"}


def test_orchestrator_service_plan_all_tenants(tmp_path: Path) -> None:
    template_path = tmp_path / "template.yml"
    template_path.write_text(
        "templates:\n"
        "  - service: ssh\n"
        "    ports: [2222]\n",
        encoding="utf-8",
    )
    config = parse_config(
        {
            "templates": {"enabled": True, "paths": [str(template_path)]},
            "multi_tenant": {
                "enabled": True,
                "default_tenant": "tenant-a",
                "tenants": [
                    {"id": "tenant-a", "enabled": True},
                    {"id": "tenant-b", "enabled": True},
                ],
            },
            "services": [{"name": "ssh", "module": "clownpeanuts.services.ssh.emulator", "ports": [2222], "config": {}}],
        }
    )
    orchestrator = Orchestrator(config)

    plan = orchestrator.service_plan(all_tenants=True, apply_threat_rotation=False)
    assert plan["all_tenants"] is True
    assert plan["tenant_count"] == 2
    assert plan["count"] == 2
    tenant_ids = {item["tenant"] for item in plan["plans"]}
    assert tenant_ids == {"tenant-a", "tenant-b"}


def test_orchestrator_service_plan_diff_detects_tenant_override_changes() -> None:
    config = parse_config(
        {
            "multi_tenant": {
                "enabled": True,
                "default_tenant": "tenant-a",
                "tenants": [
                    {"id": "tenant-a", "enabled": True, "service_overrides": {"ssh": {"ports": [2222]}}},
                    {"id": "tenant-b", "enabled": True, "service_overrides": {"ssh": {"ports": [2299], "enabled": False}}},
                ],
            },
            "services": [{"name": "ssh", "module": "clownpeanuts.services.ssh.emulator", "ports": [2200], "config": {}}],
        }
    )
    orchestrator = Orchestrator(config)

    diff = orchestrator.service_plan_diff(
        left_tenant_id="tenant-a",
        right_tenant_id="tenant-b",
        apply_threat_rotation=False,
    )
    assert diff["different"] is True
    assert diff["left_tenant"] == "tenant-a"
    assert diff["right_tenant"] == "tenant-b"
    assert diff["changed_count"] >= 1
    ssh_diff = next(item for item in diff["changed"] if item["service"] == "ssh")
    assert "ports" in ssh_diff["fields_changed"]
    assert "enabled" in ssh_diff["fields_changed"]


def test_orchestrator_service_plan_diff_matrix_returns_pairwise_sweep() -> None:
    config = parse_config(
        {
            "multi_tenant": {
                "enabled": True,
                "default_tenant": "tenant-a",
                "tenants": [
                    {"id": "tenant-a", "enabled": True, "service_overrides": {"ssh": {"ports": [2222]}}},
                    {"id": "tenant-b", "enabled": True, "service_overrides": {"ssh": {"ports": [2222]}}},
                    {"id": "tenant-c", "enabled": True, "service_overrides": {"ssh": {"ports": [2299]}}},
                ],
            },
            "services": [{"name": "ssh", "module": "clownpeanuts.services.ssh.emulator", "ports": [2200], "config": {}}],
        }
    )
    orchestrator = Orchestrator(config)

    matrix = orchestrator.service_plan_diff_matrix(apply_threat_rotation=False)
    assert matrix["tenant_count"] == 3
    assert matrix["comparison_count"] == 3
    assert matrix["different_count"] >= 1
    assert matrix["all_same"] is False


def test_orchestrator_alert_test_reflects_alert_enablement() -> None:
    disabled = parse_config({"alerts": {"enabled": False}, "services": []})
    disabled_orchestrator = Orchestrator(disabled)
    disabled_result = disabled_orchestrator.alert_test(
        severity="medium",
        title="manual_alert_test",
        summary="synthetic",
    )
    assert disabled_result["queued"] is False

    enabled = parse_config({"alerts": {"enabled": True, "min_severity": "low", "throttle_seconds": 0}, "services": []})
    enabled_orchestrator = Orchestrator(enabled)
    enabled_result = enabled_orchestrator.alert_test(
        severity="high",
        title="manual_alert_test",
        summary="synthetic",
        metadata={"scope": "integration"},
    )
    assert enabled_result["queued"] is True
