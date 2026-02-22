import time
from pathlib import Path
from typing import Any

import pytest

from clownpeanuts.config.schema import parse_config
from clownpeanuts.core.orchestrator import Orchestrator
from clownpeanuts.dashboard.api import create_app


def test_dashboard_websocket_streams_events_under_load() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()
    app = create_app(orchestrator)
    client = testclient.TestClient(app)
    total_events = 80

    with client.websocket_connect("/ws/events") as websocket:
        for index in range(total_events):
            orchestrator.event_bus.publish(
                "events",
                {
                    "service": "ssh",
                    "action": "command",
                    "message": f"ws-load-{index}",
                },
            )
        received = [websocket.receive_json() for _ in range(total_events)]

    messages = [item.get("payload", {}).get("message") for item in received]
    assert messages[0] == "ws-load-0"
    assert messages[-1] == f"ws-load-{total_events - 1}"


def test_dashboard_websocket_reconnect_recovers_without_refresh() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    with client.websocket_connect("/ws/events") as websocket:
        orchestrator.event_bus.publish(
            "events",
            {"service": "ssh", "action": "command", "message": "reconnect-a"},
        )
        first_payload = websocket.receive_json()

    first_message = first_payload.get("payload", {}).get("message")
    assert first_message == "reconnect-a"

    with client.websocket_connect("/ws/events") as websocket:
        orchestrator.event_bus.publish(
            "events",
            {"service": "ssh", "action": "command", "message": "reconnect-b"},
        )
        observed_messages = [str(websocket.receive_json().get("payload", {}).get("message", "")) for _ in range(2)]

    assert "reconnect-b" in observed_messages


def test_dashboard_websocket_cursor_and_batch_controls() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    for index in range(4):
        orchestrator.event_bus.publish(
            "events",
            {"service": "ssh", "action": "command", "message": f"cursor-{index}"},
        )

    with client.websocket_connect("/ws/events?cursor=3&batch_limit=1&interval_ms=50") as websocket:
        first = websocket.receive_json()
        assert first.get("payload", {}).get("message") == "cursor-3"

        orchestrator.event_bus.publish(
            "events",
            {"service": "ssh", "action": "command", "message": "cursor-4"},
        )
        orchestrator.event_bus.publish(
            "events",
            {"service": "ssh", "action": "command", "message": "cursor-5"},
        )

        second = websocket.receive_json()
        third = websocket.receive_json()

    assert second.get("payload", {}).get("message") == "cursor-4"
    assert third.get("payload", {}).get("message") == "cursor-5"


def test_dashboard_websocket_batch_mode_streams_single_payload_per_poll() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    for index in range(3):
        orchestrator.event_bus.publish(
            "events",
            {"service": "ssh", "action": "command", "message": f"batch-{index}"},
        )

    with client.websocket_connect("/ws/events?format=batch&cursor=0&batch_limit=2&interval_ms=50") as websocket:
        first = websocket.receive_json()
        second = websocket.receive_json()

    assert first.get("stream") == "events_batch"
    assert first.get("count") == 2
    first_events = first.get("events", [])
    assert isinstance(first_events, list)
    assert [item.get("payload", {}).get("message") for item in first_events] == ["batch-0", "batch-1"]
    assert second.get("count") == 1
    second_events = second.get("events", [])
    assert isinstance(second_events, list)
    assert second_events[0].get("payload", {}).get("message") == "batch-2"


def test_dashboard_websocket_supports_server_side_event_filters() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    orchestrator.event_bus.publish(
        "events",
        {
            "service": "ssh",
            "action": "command",
            "session_id": "ws-filter-target",
            "payload": {"command": "id"},
            "message": "ws-filter-keep",
        },
    )
    orchestrator.event_bus.publish(
        "events",
        {
            "service": "ssh",
            "action": "auth_attempt",
            "session_id": "ws-filter-target",
            "payload": {"username": "root"},
            "message": "ws-filter-drop-action",
        },
    )
    orchestrator.event_bus.publish(
        "events",
        {
            "service": "http_admin",
            "action": "command",
            "session_id": "ws-filter-other",
            "payload": {"path": "/admin"},
            "message": "ws-filter-drop-service",
        },
    )

    with client.websocket_connect(
        "/ws/events?format=batch&cursor=0&batch_limit=10&interval_ms=50&service=ssh&action=command&session_id=ws-filter-target&include_payload=false"
    ) as websocket:
        payload = websocket.receive_json()

    assert payload.get("stream") == "events_batch"
    assert payload.get("count") == 1
    events = payload.get("events", [])
    assert isinstance(events, list)
    assert events[0].get("payload", {}).get("message") == "ws-filter-keep"
    redacted_payload = events[0].get("payload", {}).get("payload", {})
    assert isinstance(redacted_payload, dict)
    assert redacted_payload.get("redacted") is True


def test_dashboard_theater_websocket_streams_live_payload() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()
    orchestrator.session_manager.get_or_create(session_id="theater-ws-1", source_ip="203.0.113.71")
    orchestrator.session_manager.record_event(
        session_id="theater-ws-1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.71", "command": "whoami"},
    )
    orchestrator.session_manager.record_event(
        session_id="theater-ws-1",
        service="http_admin",
        action="http_request",
        payload={"source_ip": "203.0.113.71", "path": "/admin"},
    )

    app = create_app(orchestrator)
    client = testclient.TestClient(app)
    with client.websocket_connect("/ws/theater/live?limit=20&events_per_session=20&interval_ms=100") as websocket:
        payload = websocket.receive_json()

    assert payload["stream"] == "theater_live"
    theater_payload = payload["payload"]
    assert theater_payload["count"] >= 1
    assert isinstance(theater_payload.get("recommendations", []), list)
    assert "within_latency_budget" in theater_payload


def test_dashboard_theater_websocket_reconnect_recovers_without_refresh() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()
    orchestrator.session_manager.get_or_create(session_id="theater-ws-reconnect-1", source_ip="203.0.113.131")
    orchestrator.session_manager.record_event(
        session_id="theater-ws-reconnect-1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.131", "command": "hostname"},
    )

    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    with client.websocket_connect("/ws/theater/live?limit=20&events_per_session=20&interval_ms=100") as websocket:
        first_payload = websocket.receive_json()

    assert first_payload["stream"] == "theater_live"
    first_sessions = first_payload.get("payload", {}).get("sessions", [])
    first_session_ids = {str(item.get("session_id", "")) for item in first_sessions if isinstance(item, dict)}
    assert "theater-ws-reconnect-1" in first_session_ids

    orchestrator.session_manager.get_or_create(session_id="theater-ws-reconnect-2", source_ip="203.0.113.132")
    orchestrator.session_manager.record_event(
        session_id="theater-ws-reconnect-2",
        service="http_admin",
        action="http_request",
        payload={"source_ip": "203.0.113.132", "path": "/internal/api/orders"},
    )

    with client.websocket_connect("/ws/theater/live?limit=20&events_per_session=20&interval_ms=100") as websocket:
        second_payload = websocket.receive_json()

    assert second_payload["stream"] == "theater_live"
    second_sessions = second_payload.get("payload", {}).get("sessions", [])
    second_session_ids = {str(item.get("session_id", "")) for item in second_sessions if isinstance(item, dict)}
    assert "theater-ws-reconnect-2" in second_session_ids


def test_dashboard_theater_end_to_end_workflow_is_deterministic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    monkeypatch.setenv("CLOWNPEANUTS_INTEL_DB", str(tmp_path / "cp903-dashboard.sqlite3"))
    config = parse_config(
        {
            "narrative": {
                "enabled": True,
                "world_seed": "cp903-dashboard",
                "entity_count": 96,
                "per_tenant_worlds": True,
            },
            "bandit": {
                "enabled": True,
                "algorithm": "thompson",
                "exploration_floor": 0.0,
                "safety_caps": {
                    "max_arm_exposure_percent": 1.0,
                    "cooldown_seconds": 0.0,
                    "denylist": [],
                },
            },
            "theater": {
                "enabled": True,
                "rollout_mode": "apply-enabled",
                "max_live_sessions": 30,
                "recommendation_cooldown_seconds": 0.0,
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()

    session_id = "cp903-dashboard-1"
    source_ip = "203.0.113.201"
    orchestrator.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
    orchestrator.session_manager.record_event(
        session_id=session_id,
        service="ssh",
        action="command",
        payload={"source_ip": source_ip, "command": "hostname"},
    )
    orchestrator.session_manager.record_event(
        session_id=session_id,
        service="http_admin",
        action="http_request",
        payload={"source_ip": source_ip, "path": "/internal/api/orders"},
    )
    orchestrator.session_manager.record_event(
        session_id=session_id,
        service="mysql_db",
        action="command",
        payload={"source_ip": source_ip, "query": "show databases"},
    )
    orchestrator.rabbit_hole.resolve_narrative_context(
        session_id=session_id,
        source_ip=source_ip,
        tenant_id="default",
        service="ssh",
        action="command",
        hints={"command": "hostname"},
    )
    orchestrator.rabbit_hole.resolve_narrative_context(
        session_id=session_id,
        source_ip=source_ip,
        tenant_id="default",
        service="http_admin",
        action="get_/internal/api/orders",
        hints={"route": "/internal/api/orders"},
    )
    orchestrator.rabbit_hole.resolve_narrative_context(
        session_id=session_id,
        source_ip=source_ip,
        tenant_id="default",
        service="mysql_db",
        action="query",
        hints={"query": "show databases"},
    )

    decision = orchestrator.bandit_select(
        context_key="ssh:generic",
        candidates=["ssh-baseline", "ssh-credential-bait", "ssh-lateral-bait"],
    )
    assert decision["recorded"] is True
    decision_id = int(decision["decision_id"])
    reward = orchestrator.intel_store.record_bandit_reward(
        decision_id=decision_id,
        reward=0.88,
        signals={"dwell_time": 0.9, "cross_protocol_pivot": 1.0, "technique_novelty": 0.7},
        metadata={"source": "integration"},
    )
    assert reward is not None
    assert reward["decision_id"] == decision_id

    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    recommendation_response = client.get("/theater/recommendations?limit=5&session_limit=10&events_per_session=50")
    assert recommendation_response.status_code == 200
    recommendation_payload = recommendation_response.json()
    assert recommendation_payload["count"] >= 1
    recommendation = recommendation_payload["recommendations"][0]
    assert recommendation["session_id"] == session_id

    apply_response = client.post(
        "/theater/actions/apply-lure",
        json={
            "session_id": session_id,
            "recommendation_id": recommendation["recommendation_id"],
            "lure_arm": recommendation["recommended_lure_arm"],
            "context_key": recommendation["context_key"],
            "duration_seconds": 120,
            "actor": "cp903-analyst",
        },
    )
    assert apply_response.status_code == 200
    assert apply_response.json()["applied"] is True

    label_response = client.post(
        "/theater/actions/label",
        json={
            "session_id": session_id,
            "recommendation_id": recommendation["recommendation_id"],
            "label": "priority_triage",
            "confidence": 0.91,
            "actor": "cp903-analyst",
        },
    )
    assert label_response.status_code == 200
    assert label_response.json()["accepted"] is True

    actions_response = client.get(f"/theater/actions?session_id={session_id}")
    assert actions_response.status_code == 200
    assert actions_response.json()["count"] >= 2
    action_types = {str(item.get("action_type", "")) for item in actions_response.json()["actions"]}
    assert {"apply_lure", "label"} <= action_types

    performance_response = client.get("/intel/bandit/performance?limit=50")
    assert performance_response.status_code == 200
    performance = performance_response.json()
    assert performance["decision_count"] >= 1
    assert performance["reward_count"] >= 1
    assert performance["reward_avg"] > 0.0

    with client.websocket_connect("/ws/theater/live?limit=10&events_per_session=50&interval_ms=100") as websocket:
        stream_payload = websocket.receive_json()
    assert stream_payload["stream"] == "theater_live"
    theater_payload = stream_payload["payload"]
    assert theater_payload["count"] >= 1
    session_views = theater_payload.get("sessions", [])
    selected_view = next((item for item in session_views if item.get("session_id") == session_id), None)
    assert selected_view is not None
    assert selected_view["narrative"]["context_id"]
    assert selected_view["narrative"]["world_id"]
    assert {"ssh", "http_admin", "mysql_db"} <= set(selected_view["narrative"]["touched_services"])
    assert selected_view["recommendation"]["apply_allowed"] is True


def test_external_alert_delivery_via_event_bus(monkeypatch: pytest.MonkeyPatch) -> None:
    delivered: list[dict[str, Any]] = []

    def _capture(*, endpoint: str, payload: dict[str, Any]) -> None:
        delivered.append({"endpoint": endpoint, "payload": payload})

    monkeypatch.setattr("clownpeanuts.alerts.router.send_webhook", _capture)

    config = parse_config(
        {
            "alerts": {
                "enabled": True,
                "min_severity": "low",
                "throttle_seconds": 0,
                "destinations": [
                    {
                        "name": "soc-webhook",
                        "type": "webhook",
                        "enabled": True,
                        "endpoint": "https://example.test/hook",
                    }
                ],
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()

    for index in range(8):
        orchestrator.event_bus.publish(
            "events",
            {
                "service": "ssh",
                "action": "credential_capture",
                "message": f"integration-{index}",
                "source_ip": f"198.51.100.{index + 10}",
                "payload": {"username": "root"},
            },
        )

    deadline = time.time() + 0.5
    while len(delivered) < 8 and time.time() < deadline:
        time.sleep(0.01)

    assert len(delivered) == 8
    assert delivered[0]["endpoint"] == "https://example.test/hook"
    snapshot = orchestrator.alert_router.snapshot()
    assert len(snapshot["recent"]) >= 8


def test_external_alert_delivery_includes_bandit_degradation_signal(monkeypatch: pytest.MonkeyPatch) -> None:
    delivered: list[dict[str, Any]] = []

    def _capture(*, endpoint: str, payload: dict[str, Any]) -> None:
        delivered.append({"endpoint": endpoint, "payload": payload})

    monkeypatch.setattr("clownpeanuts.alerts.router.send_webhook", _capture)

    config = parse_config(
        {
            "alerts": {
                "enabled": True,
                "min_severity": "low",
                "throttle_seconds": 0,
                "destinations": [
                    {
                        "name": "soc-webhook",
                        "type": "webhook",
                        "enabled": True,
                        "endpoint": "https://example.test/hook",
                    }
                ],
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()

    reward_curve = [0.91, 0.68, 0.42]
    for index, reward in enumerate(reward_curve):
        orchestrator.alert_router.send_intel_alert(
            report={"totals": {"sessions": 3, "events": 12, "bandit_reward_avg": reward}, "techniques": []},
            bandit_metrics={
                "reward_avg": reward,
                "exploration_ratio": 0.2 + index * 0.05,
                "decision_count": 30,
                "reward_count": 20 + index,
            },
        )

    deadline = time.time() + 0.5
    while len(delivered) < 4 and time.time() < deadline:
        time.sleep(0.01)

    titles = [str(item.get("payload", {}).get("title", "")) for item in delivered]
    assert "bandit_reward_degradation" in titles
