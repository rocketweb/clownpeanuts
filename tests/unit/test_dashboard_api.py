import base64
from uuid import uuid4

import pytest

from clownpeanuts.config.schema import parse_config
from clownpeanuts.core.orchestrator import Orchestrator
from clownpeanuts.dashboard.api import create_app


OPERATOR_TOKEN = "operator-token-0123456789abcdef"
VIEWER_TOKEN = "viewer-token-0123456789abcdef"


def _encode_ws_token(token: str) -> str:
    return base64.urlsafe_b64encode(token.encode("utf-8")).decode("ascii").rstrip("=")


def test_create_app_requires_fastapi_if_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("clownpeanuts.dashboard.api.FastAPI", None)
    monkeypatch.setattr("clownpeanuts.dashboard.api.Query", None)
    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    with pytest.raises(RuntimeError):
        create_app(orchestrator)


def test_dashboard_api_health_route() -> None:
    fastapi = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")
    assert fastapi is not None

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_dashboard_api_ecosystem_routes_are_gated_when_disabled() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    deployments = client.get("/ecosystem/deployments")
    assert deployments.status_code == 404
    state = client.get("/ecosystem/state")
    assert state.status_code == 404
    drift = client.get("/ecosystem/drift/snapshot")
    assert drift.status_code == 404
    witchbait = client.get("/ecosystem/witchbait/credentials")
    assert witchbait.status_code == 404
    jit_pool = client.get("/ecosystem/jit/pool")
    assert jit_pool.status_code == 404
    agents_status = client.get("/ecosystem/agents/status")
    assert agents_status.status_code == 404
    pripyatsprings = client.get("/ecosystem/pripyatsprings/status")
    assert pripyatsprings.status_code == 404
    adlibs_validate = client.post("/ecosystem/adlibs/validate")
    assert adlibs_validate.status_code == 404
    witchbait_preview = client.post("/ecosystem/witchbait/credentials/preview", json={"credentials": []})
    assert witchbait_preview.status_code == 404
    witchbait_trip_summary = client.get("/ecosystem/witchbait/trips/summary")
    assert witchbait_trip_summary.status_code == 404
    dirtylaundry_stats = client.get("/ecosystem/dirtylaundry/stats")
    assert dirtylaundry_stats.status_code == 404
    dirtylaundry_preview = client.post("/ecosystem/dirtylaundry/sessions/preview", json={"metrics": {}})
    assert dirtylaundry_preview.status_code == 404
    adlibs_summary = client.get("/ecosystem/adlibs/trips/summary")
    assert adlibs_summary.status_code == 404
    pripyatsprings_summary = client.get("/ecosystem/pripyatsprings/hits/summary")
    assert pripyatsprings_summary.status_code == 404


def test_dashboard_api_ecosystem_deployment_lifecycle() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"ecosystem": {"enabled": True}, "services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    manifest = {
        "source": "unit-test",
        "services": [
            {
                "name": "runtime-dummy",
                "module": "clownpeanuts.services.dummy.emulator",
                "listen_host": "127.0.0.1",
                "ports": [29001],
                "config": {"greeting": "hi"},
            }
        ],
    }
    created = client.post("/ecosystem/deployments", json=manifest)
    assert created.status_code == 200
    created_payload = created.json()
    deployment_id = str(created_payload["deployment_id"])
    assert created_payload["status"] == "pending"
    assert created_payload["service_count"] == 1
    assert created_payload["session_count"] == 0

    listed = client.get("/ecosystem/deployments")
    assert listed.status_code == 200
    assert listed.json()["count"] == 1
    assert listed.json()["deployments"][0]["session_count"] == 0

    activated = client.post(f"/ecosystem/deployments/{deployment_id}/activate")
    assert activated.status_code == 200
    activated_payload = activated.json()
    assert activated_payload["status"] == "active"
    assert activated_payload["deployment_id"] == deployment_id

    detail = client.get(f"/ecosystem/deployments/{deployment_id}")
    assert detail.status_code == 200
    detail_payload = detail.json()
    assert detail_payload["status"] == "active"
    assert detail_payload["manifest"]["services"][0]["name"] == "runtime-dummy"
    assert detail_payload["session_count"] == 0
    assert "session_history" in detail_payload
    assert "drift_metadata" in detail_payload

    orchestrator.session_manager.get_or_create(session_id="runtime-session-1", source_ip="203.0.113.210")
    orchestrator.session_manager.record_event(
        session_id="runtime-session-1",
        service="runtime-dummy",
        action="synthetic_probe",
        payload={"source_ip": "203.0.113.210"},
    )
    listed_with_session = client.get("/ecosystem/deployments")
    assert listed_with_session.status_code == 200
    assert listed_with_session.json()["deployments"][0]["session_count"] == 1
    detail_with_session = client.get(f"/ecosystem/deployments/{deployment_id}")
    assert detail_with_session.status_code == 200
    assert detail_with_session.json()["session_count"] == 1

    state = client.get("/ecosystem/state")
    assert state.status_code == 200
    state_payload = state.json()
    assert any(item["deployment_id"] == deployment_id for item in state_payload["deployments"])
    assert any(item["deployment_id"] == deployment_id and item["session_count"] == 1 for item in state_payload["deployments"])
    assert "active_services" in state_payload
    assert any(
        item.get("deployment_id") == deployment_id for item in state_payload["active_service_bindings"]
    )
    drift_snapshot = client.get("/ecosystem/drift/snapshot")
    assert drift_snapshot.status_code == 200
    drift_payload = drift_snapshot.json()
    assert drift_payload["count"] >= 1
    runtime_instance = next(
        item for item in drift_payload["instances"] if item.get("service") == "runtime-dummy"
    )
    assert runtime_instance["metadata"]["deployment_source"] == "unit-test"
    assert runtime_instance["metadata"]["deployment_activated_at"]
    assert runtime_instance["metadata"]["configuration_updated_at"]

    deleted = client.delete(f"/ecosystem/deployments/{deployment_id}")
    assert deleted.status_code == 200
    assert deleted.json()["status"] == "deleted"

    detail_after_delete = client.get(f"/ecosystem/deployments/{deployment_id}")
    assert detail_after_delete.status_code == 200
    assert detail_after_delete.json()["status"] == "deleted"


def test_dashboard_api_ecosystem_deployment_list_filters_and_sorting() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"ecosystem": {"enabled": True}, "services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    created_a = client.post(
        "/ecosystem/deployments",
        json={
            "source": "source-a",
            "services": [
                {
                    "name": "runtime-dummy-a",
                    "module": "clownpeanuts.services.dummy.emulator",
                    "listen_host": "127.0.0.1",
                    "ports": [29021],
                    "config": {},
                }
            ],
        },
    )
    assert created_a.status_code == 200
    deployment_a = str(created_a.json()["deployment_id"])

    created_b = client.post(
        "/ecosystem/deployments",
        json={
            "source": "source-b",
            "services": [
                {
                    "name": "runtime-dummy-b1",
                    "module": "clownpeanuts.services.dummy.emulator",
                    "listen_host": "127.0.0.1",
                    "ports": [29022],
                    "config": {},
                },
                {
                    "name": "runtime-dummy-b2",
                    "module": "clownpeanuts.services.dummy.emulator",
                    "listen_host": "127.0.0.1",
                    "ports": [29023],
                    "config": {},
                },
            ],
        },
    )
    assert created_b.status_code == 200

    activated = client.post(f"/ecosystem/deployments/{deployment_a}/activate")
    assert activated.status_code == 200
    orchestrator.session_manager.get_or_create(session_id="deploy-filter-session-1", source_ip="203.0.113.55")
    orchestrator.session_manager.record_event(
        session_id="deploy-filter-session-1",
        service="runtime-dummy-a",
        action="probe",
        payload={"source_ip": "203.0.113.55"},
    )

    active_only = client.get("/ecosystem/deployments?status=active")
    assert active_only.status_code == 200
    assert active_only.json()["count"] == 1
    assert active_only.json()["deployments"][0]["deployment_id"] == deployment_a

    pending_only = client.get("/ecosystem/deployments?status=pending")
    assert pending_only.status_code == 200
    assert pending_only.json()["count"] == 1
    assert pending_only.json()["deployments"][0]["source"] == "source-b"

    source_filtered = client.get("/ecosystem/deployments?source=source-b")
    assert source_filtered.status_code == 200
    assert source_filtered.json()["count"] == 1
    assert source_filtered.json()["deployments"][0]["source"] == "source-b"

    deployment_prefix = deployment_a[:6]
    prefix_filtered = client.get(f"/ecosystem/deployments?deployment_id_prefix={deployment_prefix}")
    assert prefix_filtered.status_code == 200
    assert prefix_filtered.json()["count"] == 1
    assert prefix_filtered.json()["deployments"][0]["deployment_id"] == deployment_a

    service_filtered = client.get("/ecosystem/deployments?service_name=runtime-dummy-b2")
    assert service_filtered.status_code == 200
    assert service_filtered.json()["count"] == 1
    assert "runtime-dummy-b2" in service_filtered.json()["deployments"][0]["services"]

    min_session_filtered = client.get("/ecosystem/deployments?min_session_count=1")
    assert min_session_filtered.status_code == 200
    assert min_session_filtered.json()["count"] == 1
    assert min_session_filtered.json()["deployments"][0]["deployment_id"] == deployment_a

    query_filtered = client.get("/ecosystem/deployments?query=source-b")
    assert query_filtered.status_code == 200
    assert query_filtered.json()["count"] == 1
    assert query_filtered.json()["deployments"][0]["source"] == "source-b"

    sorted_by_service_count = client.get("/ecosystem/deployments?sort_by=service_count&sort_order=desc")
    assert sorted_by_service_count.status_code == 200
    assert sorted_by_service_count.json()["count"] == 2
    assert sorted_by_service_count.json()["deployments"][0]["service_count"] == 2

    invalid_status = client.get("/ecosystem/deployments?status=unknown")
    assert invalid_status.status_code == 400

    invalid_sort_by = client.get("/ecosystem/deployments?sort_by=nope")
    assert invalid_sort_by.status_code == 400

    invalid_sort_order = client.get("/ecosystem/deployments?sort_order=sideways")
    assert invalid_sort_order.status_code == 400


def test_dashboard_api_ecosystem_drift_snapshot_filters_and_sorting() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config(
        {
            "ecosystem": {"enabled": True},
            "services": [
                {
                    "name": "baseline-dummy",
                    "module": "clownpeanuts.services.dummy.emulator",
                    "listen_host": "127.0.0.1",
                    "ports": [29031],
                    "config": {"banner": "baseline-banner"},
                }
            ],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    created = client.post(
        "/ecosystem/deployments",
        json={
            "source": "drift-source",
            "services": [
                {
                    "name": "runtime-dummy",
                    "module": "clownpeanuts.services.dummy.emulator",
                    "listen_host": "127.0.0.1",
                    "ports": [29032],
                    "config": {"banner": "runtime-banner"},
                }
            ],
        },
    )
    assert created.status_code == 200
    deployment_id = str(created.json()["deployment_id"])
    activated = client.post(f"/ecosystem/deployments/{deployment_id}/activate")
    assert activated.status_code == 200

    snapshot = client.get("/ecosystem/drift/snapshot")
    assert snapshot.status_code == 200
    assert snapshot.json()["count"] >= 2

    source_filtered = client.get("/ecosystem/drift/snapshot?source=drift-source")
    assert source_filtered.status_code == 200
    assert source_filtered.json()["count"] == 1
    assert source_filtered.json()["instances"][0]["service"] == "runtime-dummy"

    deployment_prefix_filtered = client.get(
        f"/ecosystem/drift/snapshot?deployment_id_prefix={deployment_id[:6]}"
    )
    assert deployment_prefix_filtered.status_code == 200
    assert deployment_prefix_filtered.json()["count"] == 1
    assert deployment_prefix_filtered.json()["instances"][0]["deployment_id"] == deployment_id

    service_prefix_filtered = client.get("/ecosystem/drift/snapshot?service_prefix=baseline")
    assert service_prefix_filtered.status_code == 200
    assert service_prefix_filtered.json()["count"] == 1
    assert service_prefix_filtered.json()["instances"][0]["service"] == "baseline-dummy"

    protocol_filtered = client.get("/ecosystem/drift/snapshot?protocol=runtime-dummy&running=true")
    assert protocol_filtered.status_code == 200
    assert protocol_filtered.json()["count"] == 1
    assert protocol_filtered.json()["instances"][0]["running"] is True

    query_filtered = client.get("/ecosystem/drift/snapshot?query=baseline-banner")
    assert query_filtered.status_code == 200
    assert query_filtered.json()["count"] == 1
    assert query_filtered.json()["instances"][0]["service"] == "baseline-dummy"

    sorted_snapshot = client.get("/ecosystem/drift/snapshot?sort_by=service&sort_order=asc")
    assert sorted_snapshot.status_code == 200
    services = [str(item.get("service", "")) for item in sorted_snapshot.json()["instances"]]
    assert services == sorted(services)

    bad_running = client.get("/ecosystem/drift/snapshot?running=maybe")
    assert bad_running.status_code == 400

    bad_sort = client.get("/ecosystem/drift/snapshot?sort_by=invalid")
    assert bad_sort.status_code == 400


def test_dashboard_api_ecosystem_state_filters_and_compact_controls() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"ecosystem": {"enabled": True}, "services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    created_a = client.post(
        "/ecosystem/deployments",
        json={
            "source": "alpha",
            "services": [
                {
                    "name": "runtime-a",
                    "module": "clownpeanuts.services.dummy.emulator",
                    "listen_host": "127.0.0.1",
                    "ports": [29041],
                    "config": {},
                }
            ],
        },
    )
    assert created_a.status_code == 200
    deployment_a = str(created_a.json()["deployment_id"])

    created_b = client.post(
        "/ecosystem/deployments",
        json={
            "source": "beta",
            "services": [
                {
                    "name": "runtime-b",
                    "module": "clownpeanuts.services.dummy.emulator",
                    "listen_host": "127.0.0.1",
                    "ports": [29042],
                    "config": {},
                }
            ],
        },
    )
    assert created_b.status_code == 200
    deployment_b = str(created_b.json()["deployment_id"])

    activated_a = client.post(f"/ecosystem/deployments/{deployment_a}/activate")
    assert activated_a.status_code == 200
    activated_b = client.post(f"/ecosystem/deployments/{deployment_b}/activate")
    assert activated_b.status_code == 200

    orchestrator.session_manager.get_or_create(session_id="state-filter-session-1", source_ip="198.51.100.77")
    orchestrator.session_manager.record_event(
        session_id="state-filter-session-1",
        service="runtime-b",
        action="probe",
        payload={"source_ip": "198.51.100.77"},
    )

    source_filtered = client.get("/ecosystem/state?source=beta")
    assert source_filtered.status_code == 200
    assert source_filtered.json()["deployment_count"] == 1
    assert source_filtered.json()["deployments"][0]["source"] == "beta"

    service_filtered = client.get("/ecosystem/state?service_name=runtime-a")
    assert service_filtered.status_code == 200
    assert service_filtered.json()["deployment_count"] == 1
    assert service_filtered.json()["deployments"][0]["deployment_id"] == deployment_a

    prefix_filtered = client.get(f"/ecosystem/state?deployment_id_prefix={deployment_b[:6]}")
    assert prefix_filtered.status_code == 200
    assert prefix_filtered.json()["deployment_count"] == 1
    assert prefix_filtered.json()["deployments"][0]["deployment_id"] == deployment_b

    min_sessions_filtered = client.get("/ecosystem/state?min_session_count=1")
    assert min_sessions_filtered.status_code == 200
    assert min_sessions_filtered.json()["deployment_count"] == 1
    assert min_sessions_filtered.json()["deployments"][0]["deployment_id"] == deployment_b

    query_filtered = client.get("/ecosystem/state?query=beta")
    assert query_filtered.status_code == 200
    assert query_filtered.json()["deployment_count"] == 1
    assert query_filtered.json()["deployments"][0]["source"] == "beta"

    compact = client.get("/ecosystem/state?include_active_services=false&include_runtime_deployments=false")
    assert compact.status_code == 200
    compact_payload = compact.json()
    assert compact_payload["active_service_bindings"] == []
    assert compact_payload["active_services"] == []
    assert compact_payload["active_runtime_deployments"] == []
    assert compact_payload["include_active_services"] is False
    assert compact_payload["include_runtime_deployments"] is False

    bad_sort = client.get("/ecosystem/state?sort_by=invalid")
    assert bad_sort.status_code == 400


def test_dashboard_api_ecosystem_agents_status() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config(
        {
            "ecosystem": {"enabled": True},
            "agents": {
                "pripyatsprings": {"enabled": True},
                "adlibs": {"enabled": False},
                "dirtylaundry": {"enabled": True},
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    status = client.get("/ecosystem/agents/status")
    assert status.status_code == 200
    payload = status.json()
    assert payload["ecosystem_enabled"] is True
    assert payload["enabled_count"] == 2
    module_state = {item["name"]: item["state"] for item in payload["modules"]}
    assert module_state["pripyatsprings"] == "ready"
    assert module_state["adlibs"] == "disabled"
    assert module_state["dirtylaundry"] == "ready"


def test_dashboard_api_agent_module_routes_require_module_enabled() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"ecosystem": {"enabled": True}, "services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    adlibs = client.post("/ecosystem/adlibs/validate")
    assert adlibs.status_code == 404
    pripyatsprings = client.get("/ecosystem/pripyatsprings/status")
    assert pripyatsprings.status_code == 404
    dirtylaundry = client.get("/ecosystem/dirtylaundry/stats")
    assert dirtylaundry.status_code == 404


def test_dashboard_api_ecosystem_pripyatsprings_routes() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config(
        {
            "ecosystem": {"enabled": True},
            "agents": {
                "pripyatsprings": {
                    "enabled": True,
                    "tracking_domain": "t.example.local",
                    "canary_dns_domain": "c.example.local",
                }
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    status = client.get("/ecosystem/pripyatsprings/status")
    assert status.status_code == 200
    assert status.json()["enabled"] is True

    fingerprint = client.post(
        "/ecosystem/pripyatsprings/fingerprints",
        json={
            "payload": "export-row-1",
            "session_id": "session-1",
            "deployment_id": "deployment-1",
            "metadata": {"surface": "db-export"},
        },
    )
    assert fingerprint.status_code == 200
    fingerprint_id = str(fingerprint.json()["fingerprint_id"])
    second_fingerprint = client.post(
        "/ecosystem/pripyatsprings/fingerprints",
        json={
            "payload": "export-row-2",
            "session_id": "session-2",
            "deployment_id": "deployment-2",
            "metadata": {"surface": "file-drop"},
        },
    )
    assert second_fingerprint.status_code == 200

    listed_fingerprints = client.get("/ecosystem/pripyatsprings/fingerprints")
    assert listed_fingerprints.status_code == 200
    assert listed_fingerprints.json()["count"] == 2

    filtered_fingerprints = client.get("/ecosystem/pripyatsprings/fingerprints?session_id=session-1")
    assert filtered_fingerprints.status_code == 200
    assert filtered_fingerprints.json()["count"] == 1
    assert filtered_fingerprints.json()["fingerprints"][0]["session_id"] == "session-1"

    queried_fingerprints = client.get("/ecosystem/pripyatsprings/fingerprints?query=file-drop")
    assert queried_fingerprints.status_code == 200
    assert queried_fingerprints.json()["count"] == 1
    assert queried_fingerprints.json()["fingerprints"][0]["deployment_id"] == "deployment-2"

    bad_fingerprint_sort = client.get("/ecosystem/pripyatsprings/fingerprints?sort_by=invalid")
    assert bad_fingerprint_sort.status_code == 400

    hit = client.post(
        "/ecosystem/pripyatsprings/hits",
        json={
            "fingerprint_id": fingerprint_id,
            "source_ip": "203.0.113.7",
            "user_agent": "curl/8.0",
        },
    )
    assert hit.status_code == 200
    hit_payload = hit.json()
    assert hit_payload["session_id"] == "session-1"
    assert hit_payload["deployment_id"] == "deployment-1"
    second_hit = client.post(
        "/ecosystem/pripyatsprings/hits",
        json={
            "fingerprint_id": fingerprint_id,
            "source_ip": "198.51.100.8",
            "user_agent": "python-httpx/1.0",
        },
    )
    assert second_hit.status_code == 200

    hits = client.get("/ecosystem/pripyatsprings/hits")
    assert hits.status_code == 200
    hits_payload = hits.json()
    assert hits_payload["count"] == 2
    assert hits_payload["hits"][0]["session_id"] == "session-1"
    assert hits_payload["hits"][0]["deployment_id"] == "deployment-1"
    assert hits_payload["hits"][0]["fingerprint_metadata"]["surface"] == "db-export"

    source_filtered = client.get("/ecosystem/pripyatsprings/hits?source_ip_prefix=198.51")
    assert source_filtered.status_code == 200
    assert source_filtered.json()["count"] == 1
    assert source_filtered.json()["hits"][0]["source_ip"] == "198.51.100.8"

    session_filtered = client.get("/ecosystem/pripyatsprings/hits?session_id=session-1")
    assert session_filtered.status_code == 200
    assert session_filtered.json()["count"] == 2

    query_filtered = client.get("/ecosystem/pripyatsprings/hits?query=httpx")
    assert query_filtered.status_code == 200
    assert query_filtered.json()["count"] == 1

    summary = client.get("/ecosystem/pripyatsprings/hits/summary")
    assert summary.status_code == 200
    summary_payload = summary.json()
    assert summary_payload["count"] == 2
    assert summary_payload["by_source_ip"][0]["count"] >= 1
    assert summary_payload["by_fingerprint_id"][0]["fingerprint_id"] == fingerprint_id

    bad_sort = client.get("/ecosystem/pripyatsprings/hits?sort_by=invalid")
    assert bad_sort.status_code == 400

    bad_range = client.get(
        "/ecosystem/pripyatsprings/hits?created_after=2026-02-21T10:00:00Z&created_before=2026-02-21T09:00:00Z"
    )
    assert bad_range.status_code == 400


def test_dashboard_api_ecosystem_adlibs_routes() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config(
        {
            "ecosystem": {"enabled": True},
            "agents": {
                "adlibs": {
                    "enabled": True,
                    "ldap_uri": "ldaps://dc.example.local:636",
                    "ldap_bind_dn": "CN=svc,OU=Service Accounts,DC=example,DC=local",
                    "ldap_bind_password_env": "CP_ADLIBS_PASSWORD",
                    "base_dn": "DC=example,DC=local",
                    "target_ou": "OU=Deception,DC=example,DC=local",
                    "fake_users": 2,
                    "fake_service_accounts": 1,
                    "fake_groups": 1,
                }
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    validate = client.post("/ecosystem/adlibs/validate")
    assert validate.status_code == 200
    validate_payload = validate.json()
    assert validate_payload["ready"] is True
    assert validate_payload["plan"]["projected_total"] == 4
    assert validate_payload["plan"]["preview"]["users"]["preview_count"] == 2

    seeded = client.post("/ecosystem/adlibs/seed")
    assert seeded.status_code == 200
    seeded_payload = seeded.json()
    assert seeded_payload["status"] == "seeded"
    assert seeded_payload["count"] == 4
    assert seeded_payload["witchbait"]["enabled"] is True
    assert seeded_payload["witchbait"]["registered"] == 3

    objects = client.get("/ecosystem/adlibs/objects")
    assert objects.status_code == 200
    objects_payload = objects.json()
    assert objects_payload["count"] == 4
    assert objects_payload["relationships"]
    object_id = str(objects_payload["objects"][0]["object_id"])

    type_filtered_objects = client.get("/ecosystem/adlibs/objects?object_type=service_account")
    assert type_filtered_objects.status_code == 200
    assert type_filtered_objects.json()["count"] == 1
    assert type_filtered_objects.json()["objects"][0]["object_type"] == "service_account"

    name_filtered_objects = client.get("/ecosystem/adlibs/objects?name_prefix=usr-decoy")
    assert name_filtered_objects.status_code == 200
    assert name_filtered_objects.json()["count"] == 2

    query_filtered_objects = client.get("/ecosystem/adlibs/objects?query=svc-decoy-01")
    assert query_filtered_objects.status_code == 200
    assert query_filtered_objects.json()["count"] == 1
    assert query_filtered_objects.json()["objects"][0]["name"] == "svc-decoy-01"

    bad_object_sort = client.get("/ecosystem/adlibs/objects?sort_by=invalid")
    assert bad_object_sort.status_code == 400

    witchbait_credentials = client.get("/ecosystem/witchbait/credentials")
    assert witchbait_credentials.status_code == 200
    assert witchbait_credentials.json()["count"] == 3

    trip = client.post(
        "/ecosystem/adlibs/trips",
        json={
            "object_id": object_id,
            "event_type": "4769",
            "source_host": "wkstn-01",
            "source_user": "alice",
        },
    )
    assert trip.status_code == 200
    second_trip = client.post(
        "/ecosystem/adlibs/trips",
        json={
            "object_id": object_id,
            "event_type": "4624",
            "source_host": "adm-02",
            "source_user": "bob",
        },
    )
    assert second_trip.status_code == 200
    trips = client.get("/ecosystem/adlibs/trips")
    assert trips.status_code == 200
    assert trips.json()["count"] == 2

    filtered_trips = client.get("/ecosystem/adlibs/trips?event_type=4769")
    assert filtered_trips.status_code == 200
    assert filtered_trips.json()["count"] == 1
    assert filtered_trips.json()["trips"][0]["event_type"] == "4769"

    event_catalog = client.get("/ecosystem/adlibs/events/catalog")
    assert event_catalog.status_code == 200
    assert event_catalog.json()["count"] >= 6

    prefix_filtered = client.get("/ecosystem/adlibs/trips?source_host_prefix=adm")
    assert prefix_filtered.status_code == 200
    assert prefix_filtered.json()["count"] == 1
    assert prefix_filtered.json()["trips"][0]["source_host"] == "adm-02"

    query_filtered = client.get("/ecosystem/adlibs/trips?query=alice")
    assert query_filtered.status_code == 200
    assert query_filtered.json()["count"] == 1
    assert query_filtered.json()["trips"][0]["source_user"] == "alice"

    summary = client.get("/ecosystem/adlibs/trips/summary")
    assert summary.status_code == 200
    summary_payload = summary.json()
    assert summary_payload["count"] == 2
    assert summary_payload["by_event_type"][0]["count"] >= 1
    assert summary_payload["by_object_id"][0]["object_id"] == object_id

    bad_sort = client.get("/ecosystem/adlibs/trips?sort_order=sideways")
    assert bad_sort.status_code == 400

    bad_range = client.get(
        "/ecosystem/adlibs/trips?created_after=2026-02-21T10:00:00Z&created_before=2026-02-21T09:00:00Z"
    )
    assert bad_range.status_code == 400

    ingested = client.post(
        "/ecosystem/adlibs/events/ingest",
        json={
            "event_id": 4769,
            "target_account": objects_payload["objects"][1]["name"],
            "source_host": "wkstn-77",
        },
    )
    assert ingested.status_code == 200
    assert ingested.json()["status"] == "recorded"

    ingested_batch = client.post(
        "/ecosystem/adlibs/events/ingest/batch",
        json={
            "events": [
                {"event_id": 4624, "target_account": objects_payload["objects"][1]["name"], "source_host": "wkstn-77"},
                {"event_id": 4768, "target_account": "missing-user", "source_host": "wkstn-78"},
            ]
        },
    )
    assert ingested_batch.status_code == 200
    assert ingested_batch.json()["recorded"] == 1
    assert ingested_batch.json()["ignored"] == 1

    deleted = client.delete(f"/ecosystem/adlibs/objects/{object_id}")
    assert deleted.status_code == 200
    assert deleted.json()["status"] == "deleted"


def test_dashboard_api_ecosystem_dirtylaundry_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config(
        {
            "ecosystem": {"enabled": True},
            "agents": {
                "dirtylaundry": {
                    "enabled": True,
                    "match_threshold": 0.95,
                    "sharing": {
                        "enabled": True,
                        "endpoint": "https://sharing.example",
                        "request_timeout_seconds": 9.5,
                        "headers": {"Authorization": "Bearer dashboard-token"},
                    },
                }
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    metrics = {
        "typing_cadence": 0.8,
        "command_vocabulary": 0.7,
        "tool_signatures": 0.6,
        "temporal_pattern": 0.5,
        "credential_reuse": 0.4,
    }
    created = client.post(
        "/ecosystem/dirtylaundry/sessions",
        json={"session_id": "dl-session-1", "metrics": metrics},
    )
    assert created.status_code == 200
    created_payload = created.json()
    assert created_payload["status"] == "created"
    assert created_payload["match_breakdown"] == {}
    profile_id = str(created_payload["profile"]["profile_id"])

    preview = client.post(
        "/ecosystem/dirtylaundry/sessions/preview",
        json={"metrics": metrics, "limit": 3, "include_breakdown": True},
    )
    assert preview.status_code == 200
    preview_payload = preview.json()
    assert preview_payload["count"] == 1
    assert preview_payload["candidate_profile_id"] == profile_id
    assert isinstance(preview_payload["matches"][0]["breakdown"], dict)

    evaluated = client.post(
        "/ecosystem/dirtylaundry/sessions/evaluate",
        json={
            "metrics": {
                "typing_cadence": 0.95,
                "command_vocabulary": 0.95,
                "tool_signatures": 0.95,
                "temporal_pattern": 0.95,
                "credential_reuse": 0.95,
            }
        },
    )
    assert evaluated.status_code == 200
    assert evaluated.json()["skill"] == "apt"

    matched = client.post(
        "/ecosystem/dirtylaundry/sessions",
        json={"session_id": "dl-session-2", "metrics": metrics},
    )
    assert matched.status_code == 200
    assert matched.json()["status"] == "matched"
    assert matched.json()["auto_theater_recommended"] is False
    assert "typing_cadence" in matched.json()["match_breakdown"]

    reclassified = client.post(
        "/ecosystem/dirtylaundry/sessions/reclassify",
        json={
            "session_id": "dl-session-2",
            "profile_id": profile_id,
            "metrics": {
                "typing_cadence": 0.95,
                "command_vocabulary": 0.95,
                "tool_signatures": 0.95,
                "temporal_pattern": 0.95,
                "credential_reuse": 0.95,
            },
        },
    )
    assert reclassified.status_code == 200
    assert reclassified.json()["status"] == "reclassified"
    assert reclassified.json()["current_skill"] == "apt"

    apt = client.post(
        "/ecosystem/dirtylaundry/sessions",
        json={
            "session_id": "dl-session-apt-1",
            "metrics": {
                "typing_cadence": 0.95,
                "command_vocabulary": 0.95,
                "tool_signatures": 0.95,
                "temporal_pattern": 0.95,
                "credential_reuse": 0.95,
            },
        },
    )
    assert apt.status_code == 200
    assert apt.json()["profile"]["skill"] == "apt"
    assert apt.json()["auto_theater_recommended"] is True

    profiles = client.get("/ecosystem/dirtylaundry/profiles")
    assert profiles.status_code == 200
    assert profiles.json()["count"] == 1

    filtered_profiles = client.get("/ecosystem/dirtylaundry/profiles?skill=apt")
    assert filtered_profiles.status_code == 200
    assert filtered_profiles.json()["count"] == 1
    assert filtered_profiles.json()["profiles"][0]["skill"] == "apt"

    sorted_profiles = client.get("/ecosystem/dirtylaundry/profiles?sort_by=session_count&sort_order=desc")
    assert sorted_profiles.status_code == 200
    assert sorted_profiles.json()["count"] == 1
    assert sorted_profiles.json()["profiles"][0]["session_count"] == 3

    bad_sort = client.get("/ecosystem/dirtylaundry/profiles?sort_by=invalid")
    assert bad_sort.status_code == 400

    detail = client.get(f"/ecosystem/dirtylaundry/profiles/{profile_id}")
    assert detail.status_code == 200
    assert detail.json()["profile_id"] == profile_id

    sessions = client.get(f"/ecosystem/dirtylaundry/profiles/{profile_id}/sessions")
    assert sessions.status_code == 200
    assert sessions.json()["count"] == 3

    filtered_sessions = client.get(
        f"/ecosystem/dirtylaundry/profiles/{profile_id}/sessions?session_prefix=dl-session-2"
    )
    assert filtered_sessions.status_code == 200
    assert filtered_sessions.json()["count"] == 1
    assert filtered_sessions.json()["sessions"] == ["dl-session-2"]

    queried_sessions = client.get(
        f"/ecosystem/dirtylaundry/profiles/{profile_id}/sessions?query=session-1"
    )
    assert queried_sessions.status_code == 200
    assert queried_sessions.json()["count"] == 1
    assert queried_sessions.json()["sessions"] == ["dl-session-1"]

    sorted_sessions = client.get(
        f"/ecosystem/dirtylaundry/profiles/{profile_id}/sessions?sort_order=desc"
    )
    assert sorted_sessions.status_code == 200
    assert sorted_sessions.json()["sessions"] == ["dl-session-apt-1", "dl-session-2", "dl-session-1"]

    bad_session_sort = client.get(
        f"/ecosystem/dirtylaundry/profiles/{profile_id}/sessions?sort_by=invalid"
    )
    assert bad_session_sort.status_code == 400

    noted = client.post(
        f"/ecosystem/dirtylaundry/profiles/{profile_id}/notes",
        json={"note": "high-confidence operator"},
    )
    assert noted.status_code == 200
    assert "high-confidence operator" in noted.json()["notes"]

    stats = client.get("/ecosystem/dirtylaundry/stats")
    assert stats.status_code == 200
    stats_payload = stats.json()
    assert stats_payload["profile_count"] == 1
    assert stats_payload["total_sessions"] == 3
    assert stats_payload["average_sessions_per_profile"] == 3.0
    assert stats_payload["return_rate"] == 1.0

    exported = client.post("/ecosystem/dirtylaundry/share/export")
    assert exported.status_code == 200
    assert exported.json()["schema"] == "clownpeanuts.dirtylaundry.profile_share.v1"

    imported = client.post("/ecosystem/dirtylaundry/share/import", json=exported.json())
    assert imported.status_code == 200
    assert imported.json()["imported"] >= 1

    exported_stix = client.post("/ecosystem/dirtylaundry/share/export?format=stix")
    assert exported_stix.status_code == 200
    assert exported_stix.json()["type"] == "bundle"

    imported_stix = client.post("/ecosystem/dirtylaundry/share/import", json=exported_stix.json())
    assert imported_stix.status_code == 200
    assert imported_stix.json()["format"] == "stix"
    assert imported_stix.json()["imported"] >= 1

    def _fake_push(
        *,
        endpoint: str,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
        timeout_seconds: float = 5.0,
    ) -> dict[str, Any]:
        assert endpoint == "https://sharing.example"
        assert isinstance(payload, dict)
        assert headers == {"Authorization": "Bearer dashboard-token"}
        assert timeout_seconds == 9.5
        return {"status": "accepted"}

    def _fake_pull(
        *,
        endpoint: str,
        headers: dict[str, str] | None = None,
        timeout_seconds: float = 5.0,
    ) -> dict[str, Any]:
        assert endpoint == "https://sharing.example"
        assert headers == {"Authorization": "Bearer dashboard-token"}
        assert timeout_seconds == 9.5
        return {
            "schema": "clownpeanuts.dirtylaundry.profile_share.v1",
            "profiles": [
                {
                    "profile_id": "remote-profile-1",
                    "skill": "advanced",
                    "created_at": "2026-02-21T00:00:00+00:00",
                    "last_seen_at": "2026-02-21T01:00:00+00:00",
                    "metrics": {"typing_cadence": 0.9},
                }
            ],
        }

    monkeypatch.setattr("clownpeanuts.agents.dirtylaundry.runtime.push_share_payload", _fake_push)
    monkeypatch.setattr("clownpeanuts.agents.dirtylaundry.runtime.pull_share_payload", _fake_pull)

    pushed = client.post("/ecosystem/dirtylaundry/share/push?format=native")
    assert pushed.status_code == 200
    assert pushed.json()["status"] == "pushed"
    assert pushed.json()["endpoint"] == "https://sharing.example"

    pulled = client.post("/ecosystem/dirtylaundry/share/pull")
    assert pulled.status_code == 200
    assert pulled.json()["status"] == "pulled"
    assert pulled.json()["import"]["status"] == "imported"
    assert pulled.json()["import"]["imported"] >= 1

    bad_export = client.post("/ecosystem/dirtylaundry/share/export?format=invalid")
    assert bad_export.status_code == 400


def test_dashboard_api_ecosystem_activation_rejects_port_conflict() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config(
        {
            "ecosystem": {"enabled": True},
            "services": [
                {
                    "name": "baseline-dummy",
                    "module": "clownpeanuts.services.dummy.emulator",
                    "listen_host": "127.0.0.1",
                    "ports": [29003],
                    "config": {},
                }
            ],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    created = client.post(
        "/ecosystem/deployments",
        json={
            "services": [
                {
                    "name": "runtime-dummy-conflict",
                    "module": "clownpeanuts.services.dummy.emulator",
                    "listen_host": "127.0.0.1",
                    "ports": [29003],
                    "config": {},
                }
            ]
        },
    )
    assert created.status_code == 200
    deployment_id = str(created.json()["deployment_id"])

    activated = client.post(f"/ecosystem/deployments/{deployment_id}/activate")
    assert activated.status_code == 409
    assert "binding conflict" in activated.json()["detail"].lower()


def test_dashboard_api_ecosystem_drift_compare_returns_scores() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"ecosystem": {"enabled": True}, "services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    created = client.post(
        "/ecosystem/deployments",
        json={
            "services": [
                {
                    "name": "runtime-dummy-drift",
                    "module": "clownpeanuts.services.dummy.emulator",
                    "listen_host": "127.0.0.1",
                    "ports": [29005],
                    "config": {"banner": "unit-banner", "hostname": "unit-host"},
                }
            ]
        },
    )
    assert created.status_code == 200
    deployment_id = str(created.json()["deployment_id"])
    activated = client.post(f"/ecosystem/deployments/{deployment_id}/activate")
    assert activated.status_code == 200

    compare = client.post(
        "/ecosystem/drift/compare",
        json={
            "services": [
                {
                    "service": "runtime-dummy-drift",
                    "protocol": "runtime-dummy-drift",
                    "ports": [29005],
                    "banner": "different-banner",
                }
            ]
        },
    )
    assert compare.status_code == 200
    payload = compare.json()
    assert payload["count"] == 1
    assert isinstance(payload["believability_score"], float)
    assert payload["below_threshold"] is True


def test_dashboard_api_ecosystem_activity_injection_and_schedule() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"ecosystem": {"enabled": True}, "services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    created = client.post(
        "/ecosystem/deployments",
        json={
            "services": [
                {
                    "name": "runtime-dummy-activity",
                    "module": "clownpeanuts.services.dummy.emulator",
                    "listen_host": "127.0.0.1",
                    "ports": [29006],
                    "config": {"greeting": "hi"},
                }
            ]
        },
    )
    assert created.status_code == 200
    deployment_id = str(created.json()["deployment_id"])
    activated = client.post(f"/ecosystem/deployments/{deployment_id}/activate")
    assert activated.status_code == 200

    injected = client.post(
        f"/ecosystem/activity/{deployment_id}/inject",
        json={
            "service": "runtime-dummy-activity",
            "type": "ssh_session",
            "session_id": "activity-session-1",
            "payload": {"command": "whoami"},
        },
    )
    assert injected.status_code == 200
    injected_payload = injected.json()
    assert injected_payload["run_count"] == 1
    assert "result" in injected_payload
    assert injected_payload["result"]["accepted_count"] >= 1

    scheduled = client.post(
        f"/ecosystem/activity/{deployment_id}/inject",
        json={
            "service": "runtime-dummy-activity",
            "type": "database_query",
            "payload": {"query": "select 1"},
            "schedule": {"mode": "interval", "interval_seconds": 5},
        },
    )
    assert scheduled.status_code == 200
    scheduled_payload = scheduled.json()
    assert scheduled_payload["active"] is True
    activity_id = str(scheduled_payload["activity_id"])
    assert isinstance(scheduled_payload["next_run_at"], str)
    assert scheduled_payload["next_run_at"] != ""

    listed = client.get(f"/ecosystem/activity/{deployment_id}")
    assert listed.status_code == 200
    assert listed.json()["count"] >= 2
    interval_only = client.get(f"/ecosystem/activity/{deployment_id}?schedule_mode=interval")
    assert interval_only.status_code == 200
    assert interval_only.json()["count"] == 1
    assert interval_only.json()["activities"][0]["schedule_mode"] == "interval"

    active_only = client.get(f"/ecosystem/activity/{deployment_id}?active=true")
    assert active_only.status_code == 200
    assert active_only.json()["count"] == 1
    assert active_only.json()["activities"][0]["active"] is True

    query_filtered = client.get(f"/ecosystem/activity/{deployment_id}?query=whoami")
    assert query_filtered.status_code == 200
    assert query_filtered.json()["count"] == 1

    bad_mode = client.get(f"/ecosystem/activity/{deployment_id}?schedule_mode=invalid")
    assert bad_mode.status_code == 400
    bad_sort = client.get(f"/ecosystem/activity/{deployment_id}?sort_by=invalid")
    assert bad_sort.status_code == 400

    cancelled = client.delete(f"/ecosystem/activity/{deployment_id}/{activity_id}")
    assert cancelled.status_code == 200
    assert cancelled.json()["active"] is False


def test_dashboard_api_ecosystem_activity_cron_schedule() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"ecosystem": {"enabled": True}, "services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    created = client.post(
        "/ecosystem/deployments",
        json={
            "services": [
                {
                    "name": "runtime-dummy-cron-activity",
                    "module": "clownpeanuts.services.dummy.emulator",
                    "listen_host": "127.0.0.1",
                    "ports": [29008],
                    "config": {"greeting": "hi"},
                }
            ]
        },
    )
    assert created.status_code == 200
    deployment_id = str(created.json()["deployment_id"])
    activated = client.post(f"/ecosystem/deployments/{deployment_id}/activate")
    assert activated.status_code == 200

    scheduled = client.post(
        f"/ecosystem/activity/{deployment_id}/inject",
        json={
            "service": "runtime-dummy-cron-activity",
            "type": "database_query",
            "payload": {"query": "select 1"},
            "schedule": {"mode": "cron", "cron": "*/5 * * * *"},
        },
    )
    assert scheduled.status_code == 200
    payload = scheduled.json()
    assert payload["active"] is True
    assert payload["schedule_mode"] == "cron"
    assert payload["cron"] == "*/5 * * * *"
    assert isinstance(payload["next_run_at"], str)
    assert payload["next_run_at"] != ""

    invalid = client.post(
        f"/ecosystem/activity/{deployment_id}/inject",
        json={
            "service": "runtime-dummy-cron-activity",
            "type": "database_query",
            "payload": {"query": "select 1"},
            "schedule": {"mode": "cron", "cron": "bad expr"},
        },
    )
    assert invalid.status_code == 400
    assert "cron expression" in invalid.json()["detail"].lower()


def test_dashboard_api_ecosystem_jit_endpoints_require_jit_enabled() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"ecosystem": {"enabled": True}, "services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/ecosystem/jit/pool")
    assert response.status_code == 404


def test_dashboard_api_ecosystem_jit_deploy_and_pool_status() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config(
        {
            "ecosystem": {
                "enabled": True,
                "jit": {
                    "enabled": True,
                    "pool_size": 2,
                    "ttl_idle_seconds": 300,
                    "ttl_max_seconds": 900,
                },
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    initial_pool = client.get("/ecosystem/jit/pool")
    assert initial_pool.status_code == 200
    assert initial_pool.json()["available_containers"] == 2

    deployed = client.post(
        "/ecosystem/jit/deploy",
        json={
            "source": "manual-jit",
            "services": [
                {
                    "name": "runtime-jit-dummy-1",
                    "module": "clownpeanuts.services.dummy.emulator",
                    "listen_host": "127.0.0.1",
                    "ports": [29007],
                    "config": {"greeting": "jit"},
                }
            ]
        },
    )
    assert deployed.status_code == 200
    deployment_id = str(deployed.json()["deployment_id"])
    assert deployed.json()["status"] == "active"
    assert deployed.json()["latency_target_ms"] == 500
    assert isinstance(deployed.json()["meets_latency_target"], bool)

    jit_deployments = client.get("/ecosystem/jit/deployments")
    assert jit_deployments.status_code == 200
    assert jit_deployments.json()["count"] == 1
    assert jit_deployments.json()["deployments"][0]["deployment_id"] == deployment_id

    by_source = client.get("/ecosystem/jit/deployments?source=manual-jit")
    assert by_source.status_code == 200
    assert by_source.json()["count"] == 1

    by_prefix = client.get(f"/ecosystem/jit/deployments?deployment_id_prefix={deployment_id[:6]}")
    assert by_prefix.status_code == 200
    assert by_prefix.json()["count"] == 1

    by_service = client.get("/ecosystem/jit/deployments?service_name=runtime-jit-dummy-1")
    assert by_service.status_code == 200
    assert by_service.json()["count"] == 1

    injected = client.post(
        f"/ecosystem/activity/{deployment_id}/inject",
        json={
            "service": "runtime-jit-dummy-1",
            "type": "ssh_session",
            "session_id": "jit-session-1",
            "payload": {"command": "id"},
        },
    )
    assert injected.status_code == 200

    with_sessions = client.get("/ecosystem/jit/deployments?min_session_count=1")
    assert with_sessions.status_code == 200
    assert with_sessions.json()["count"] == 1
    assert with_sessions.json()["deployments"][0]["session_count"] >= 1

    by_query = client.get("/ecosystem/jit/deployments?query=runtime-jit-dummy-1")
    assert by_query.status_code == 200
    assert by_query.json()["count"] == 1

    bad_sort_by = client.get("/ecosystem/jit/deployments?sort_by=invalid")
    assert bad_sort_by.status_code == 400

    bad_sort_order = client.get("/ecosystem/jit/deployments?sort_order=sideways")
    assert bad_sort_order.status_code == 400

    # Allow async pool replenishment worker to run.
    import time

    time.sleep(0.25)
    refreshed_pool = client.get("/ecosystem/jit/pool")
    assert refreshed_pool.status_code == 200
    pool_payload = refreshed_pool.json()
    assert pool_payload["available_containers"] >= 1
    assert pool_payload["in_use_containers"] == 1


def test_dashboard_api_ecosystem_witchbait_registry_and_trips() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"ecosystem": {"enabled": True}, "services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    registered = client.post(
        "/ecosystem/witchbait/credentials",
        json={
            "credential_id": "wb-ops-db-1",
            "credential_value": "unit-test-secret-1",
            "credential_type": "password",
            "placement_vector": "docs/snippet",
            "target_decoy_id": "runtime-dummy",
            "metadata": {"owner": "unit-test"},
        },
    )
    assert registered.status_code == 200
    registered_payload = registered.json()
    assert registered_payload["credential_id"] == "wb-ops-db-1"
    assert "credential_value" not in registered_payload
    assert len(registered_payload["credential_hash"]) == 64

    listed = client.get("/ecosystem/witchbait/credentials")
    assert listed.status_code == 200
    list_payload = listed.json()
    assert list_payload["count"] == 1
    assert list_payload["credentials"][0]["credential_id"] == "wb-ops-db-1"

    preview = client.post(
        "/ecosystem/witchbait/credentials/preview",
        json={
            "credentials": [
                {
                    "credential_id": "wb-ops-db-2",
                    "credential_value": "unit-test-secret-1",
                    "credential_type": "password",
                },
                {
                    "credential_id": "wb-ops-db-1",
                    "credential_value": "unit-test-secret-2",
                    "credential_type": "password",
                },
                {
                    "credential_id": "wb-ops-db-3",
                    "credential_value": "unit-test-secret-3",
                    "credential_type": "password",
                },
            ]
        },
    )
    assert preview.status_code == 200
    preview_payload = preview.json()
    assert preview_payload["to_register_count"] == 1
    assert preview_payload["already_present_count"] == 1
    assert preview_payload["collision_count"] == 1

    typed = client.get("/ecosystem/witchbait/credentials?credential_type=password")
    assert typed.status_code == 200
    assert typed.json()["count"] == 1

    queried_credentials = client.get("/ecosystem/witchbait/credentials?query=unit-test")
    assert queried_credentials.status_code == 200
    assert queried_credentials.json()["count"] == 1

    bad_credential_sort = client.get("/ecosystem/witchbait/credentials?sort_by=invalid")
    assert bad_credential_sort.status_code == 400

    orchestrator.event_logger.emit(
        message="unit-test auth event",
        service="ssh",
        action="auth_attempt",
        session_id="wb-trip-session-1",
        source_ip="203.0.113.99",
        event_type="authentication",
        outcome="failure",
        payload={"username": "root", "password": "unit-test-secret-1"},
    )

    trips = client.get("/ecosystem/witchbait/trips")
    assert trips.status_code == 200
    trips_payload = trips.json()
    assert trips_payload["count"] == 1
    first_trip = trips_payload["trips"][0]
    assert first_trip["credential_id"] == "wb-ops-db-1"
    assert first_trip["session_id"] == "wb-trip-session-1"

    filtered_by_service = client.get("/ecosystem/witchbait/trips?service=ssh")
    assert filtered_by_service.status_code == 200
    assert filtered_by_service.json()["count"] == 1

    filtered_by_credential = client.get("/ecosystem/witchbait/trips?credential_id=wb-ops-db-1")
    assert filtered_by_credential.status_code == 200
    assert filtered_by_credential.json()["count"] == 1

    filtered_by_query = client.get("/ecosystem/witchbait/trips?query=203.0.113.99")
    assert filtered_by_query.status_code == 200
    assert filtered_by_query.json()["count"] == 1

    summary = client.get("/ecosystem/witchbait/trips/summary")
    assert summary.status_code == 200
    summary_payload = summary.json()
    assert summary_payload["count"] == 1
    assert summary_payload["by_credential_id"][0]["credential_id"] == "wb-ops-db-1"
    assert summary_payload["by_service"][0]["service"] == "ssh"

    replay = orchestrator.session_manager.export_session("wb-trip-session-1", events_limit=10)
    assert replay is not None
    assert "witchbait" in replay["tags"]
    assert "wb-ops-db-1" in replay["tags"]

    bad_sort = client.get("/ecosystem/witchbait/trips?sort_by=invalid")
    assert bad_sort.status_code == 400

    bad_sort_order = client.get("/ecosystem/witchbait/trips?sort_order=sideways")
    assert bad_sort_order.status_code == 400

    bad_range = client.get(
        "/ecosystem/witchbait/trips?created_after=2026-02-21T10:00:00Z&created_before=2026-02-21T09:00:00Z"
    )
    assert bad_range.status_code == 400

    deleted = client.delete("/ecosystem/witchbait/credentials/wb-ops-db-1")
    assert deleted.status_code == 200
    assert deleted.json()["status"] == "deleted"

def test_dashboard_api_disables_docs_by_default() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/docs")
    assert response.status_code == 404


def test_dashboard_api_dashboard_summary_route_returns_aggregated_payload() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/dashboard/summary")
    assert response.status_code == 200
    payload = response.json()
    assert "status" in payload
    assert "intel" in payload
    assert "map" in payload
    assert "alerts" in payload
    assert "alert_routes" in payload


def test_dashboard_api_dashboard_summary_can_toggle_heavy_sections() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    lightweight_response = client.get(
        "/dashboard/summary?include_templates=false&include_doctor=false&include_handoff=false"
    )
    assert lightweight_response.status_code == 200
    lightweight_payload = lightweight_response.json()
    assert "template_inventory" not in lightweight_payload
    assert "doctor" not in lightweight_payload
    assert "handoff" not in lightweight_payload

    heavy_response = client.get("/dashboard/summary?include_templates=true&include_doctor=true&include_handoff=true")
    assert heavy_response.status_code == 200
    heavy_payload = heavy_response.json()
    assert "template_inventory" in heavy_payload
    assert "template_plan" in heavy_payload
    assert "template_validation" in heavy_payload
    assert "doctor" in heavy_payload
    assert "handoff" in heavy_payload
    assert "markdown" in heavy_payload["handoff"]


def test_dashboard_api_reuses_cached_intel_report_across_endpoints() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="cache-s1", source_ip="203.0.113.44")
    orchestrator.session_manager.record_event(
        session_id="cache-s1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.44", "command": "whoami"},
    )
    calls = 0
    original_report = orchestrator.intelligence_report

    def wrapped_report(*, limit: int, events_per_session: int):
        nonlocal calls
        calls += 1
        return original_report(limit=limit, events_per_session=events_per_session)

    orchestrator.intelligence_report = wrapped_report  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    params = "?limit=75&events_per_session=40"
    assert client.get(f"/intel/report{params}").status_code == 200
    assert client.get(f"/intel/coverage{params}").status_code == 200
    assert client.get(f"/intel/fingerprints{params}").status_code == 200
    assert calls == 1


def test_dashboard_api_intel_report_cache_scopes_by_query_shape() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="cache-s2", source_ip="203.0.113.45")
    orchestrator.session_manager.record_event(
        session_id="cache-s2",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.45", "command": "id"},
    )
    calls = 0
    original_report = orchestrator.intelligence_report

    def wrapped_report(*, limit: int, events_per_session: int):
        nonlocal calls
        calls += 1
        return original_report(limit=limit, events_per_session=events_per_session)

    orchestrator.intelligence_report = wrapped_report  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    assert client.get("/intel/report?limit=75&events_per_session=40").status_code == 200
    assert client.get("/intel/report?limit=76&events_per_session=40").status_code == 200
    assert calls == 2


def test_dashboard_api_can_disable_intel_report_cache_with_zero_ttl() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config(
        {
            "api": {"intel_report_cache_ttl_seconds": 0},
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="cache-s3", source_ip="203.0.113.46")
    orchestrator.session_manager.record_event(
        session_id="cache-s3",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.46", "command": "uname -a"},
    )
    calls = 0
    original_report = orchestrator.intelligence_report

    def wrapped_report(*, limit: int, events_per_session: int):
        nonlocal calls
        calls += 1
        return original_report(limit=limit, events_per_session=events_per_session)

    orchestrator.intelligence_report = wrapped_report  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    assert client.get("/intel/report?limit=75&events_per_session=40").status_code == 200
    assert client.get("/intel/report?limit=75&events_per_session=40").status_code == 200
    assert calls == 2


def test_dashboard_api_reuses_cached_theater_recommendations_for_same_query() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="theater-cache-s1", source_ip="203.0.113.150")
    orchestrator.session_manager.record_event(
        session_id="theater-cache-s1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.150", "command": "id"},
    )
    calls = 0
    original = orchestrator.theater_recommendations

    def wrapped(*, limit: int, session_limit: int, events_per_session: int):
        nonlocal calls
        calls += 1
        return original(limit=limit, session_limit=session_limit, events_per_session=events_per_session)

    orchestrator.theater_recommendations = wrapped  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    query = "/theater/recommendations?limit=10&session_limit=25&events_per_session=50"
    assert client.get(query).status_code == 200
    assert client.get(query).status_code == 200
    assert calls == 1


def test_dashboard_api_reuses_cached_theater_live_for_same_query() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    calls = 0
    original = orchestrator.theater_live

    def wrapped(*, limit: int, events_per_session: int):
        nonlocal calls
        calls += 1
        return original(limit=limit, events_per_session=events_per_session)

    orchestrator.theater_live = wrapped  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    query = "/theater/live?limit=40&events_per_session=120"
    assert client.get(query).status_code == 200
    assert client.get(query).status_code == 200
    assert calls == 1


def test_dashboard_api_reuses_cached_theater_actions_for_same_query() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    calls = 0
    original = orchestrator.theater_actions

    def wrapped(*, limit: int, session_id: str | None, action_type: str | None):
        nonlocal calls
        calls += 1
        return original(limit=limit, session_id=session_id, action_type=action_type)

    orchestrator.theater_actions = wrapped  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    query = "/theater/actions?limit=50&session_id=session-a&action_type=label"
    assert client.get(query).status_code == 200
    assert client.get(query).status_code == 200
    assert calls == 1


def test_dashboard_api_reuses_cached_theater_actions_export_for_same_query() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    calls = 0
    original = orchestrator.theater_actions

    def wrapped(*, limit: int, session_id: str | None, action_type: str | None):
        nonlocal calls
        calls += 1
        return original(limit=limit, session_id=session_id, action_type=action_type)

    orchestrator.theater_actions = wrapped  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    query = "/theater/actions/export?limit=50&session_id=session-a&action_type=label&format=jsonl"
    assert client.get(query).status_code == 200
    assert client.get(query).status_code == 200
    assert calls == 1


def test_dashboard_api_reuses_cached_theater_actions_export_rendering_for_same_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    render_calls = 0
    from clownpeanuts.dashboard import api as dashboard_api

    original_render = dashboard_api.render_theater_action_export

    def wrapped_render(payload: dict[str, object], *, output_format: str) -> str:
        nonlocal render_calls
        render_calls += 1
        return original_render(payload, output_format=output_format)

    monkeypatch.setattr("clownpeanuts.dashboard.api.render_theater_action_export", wrapped_render)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    query = "/theater/actions/export?limit=50&session_id=session-a&action_type=label&format=csv"
    assert client.get(query).status_code == 200
    assert client.get(query).status_code == 200
    assert render_calls == 1


def test_dashboard_api_theater_actions_support_filter_sort_and_compact() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    def stubbed(*, limit: int, session_id: str | None, action_type: str | None):
        _ = (limit, session_id, action_type)
        return {
            "actions": [
                {
                    "row_id": 3,
                    "created_at": "2026-02-21T00:00:03+00:00",
                    "action_type": "label",
                    "session_id": "s-c",
                    "recommendation_id": "rec-1",
                    "actor": "analyst-1",
                    "payload": {"label": "high_value_actor"},
                    "metadata": {"tenant_id": "default"},
                },
                {
                    "row_id": 2,
                    "created_at": "2026-02-21T00:00:02+00:00",
                    "action_type": "apply_lure",
                    "session_id": "s-b",
                    "recommendation_id": "rec-2",
                    "actor": "analyst-2",
                    "payload": {"lure_arm": "http-query-bait"},
                    "metadata": {"tenant_id": "default"},
                },
                {
                    "row_id": 1,
                    "created_at": "2026-02-21T00:00:01+00:00",
                    "action_type": "apply_lure",
                    "session_id": "s-a",
                    "recommendation_id": "rec-1",
                    "actor": "analyst-1",
                    "payload": {"lure_arm": "ssh-credential-bait"},
                    "metadata": {"tenant_id": "default"},
                },
            ],
            "count": 3,
            "store": {"enabled": True},
        }

    orchestrator.theater_actions = stubbed  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get(
        "/theater/actions?limit=100&actor=analyst-1&recommendation_id=rec-1"
        "&created_after=2026-02-21T00:00:01Z&created_before=2026-02-21T00:00:03Z"
        "&compact=true&sort_by=session_id&sort_order=asc"
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 2
    actions = payload["actions"]
    assert isinstance(actions, list)
    assert [item["session_id"] for item in actions] == ["s-a", "s-c"]
    assert [item["result_rank"] for item in actions] == [1, 2]
    assert set(actions[0].keys()) <= {
        "row_id",
        "created_at",
        "action_type",
        "session_id",
        "recommendation_id",
        "actor",
        "result_rank",
    }
    filtering = payload["filtering"]
    assert filtering["actor"] == "analyst-1"
    assert filtering["actor_prefix"] == ""
    assert filtering["query"] == ""
    assert filtering["recommendation_id"] == "rec-1"
    assert filtering["session_prefix"] == ""
    assert filtering["action_types"] == []
    assert filtering["created_after"].startswith("2026-02-21T00:00:01")
    assert filtering["created_before"].startswith("2026-02-21T00:00:03")
    assert filtering["compact"] is True
    assert filtering["sort_by"] == "session_id"
    assert filtering["sort_order"] == "asc"


def test_dashboard_api_theater_actions_support_action_types_filter() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    def stubbed(*, limit: int, session_id: str | None, action_type: str | None):
        _ = (limit, session_id, action_type)
        return {
            "actions": [
                {
                    "row_id": 5,
                    "created_at": "2026-02-21T00:00:05+00:00",
                    "action_type": "label",
                    "session_id": "s-label",
                    "recommendation_id": "rec-label",
                    "actor": "analyst-1",
                    "payload": {"label": "high_value_actor"},
                    "metadata": {"tenant_id": "default"},
                },
                {
                    "row_id": 6,
                    "created_at": "2026-02-21T00:00:06+00:00",
                    "action_type": "apply_lure",
                    "session_id": "s-apply",
                    "recommendation_id": "rec-apply",
                    "actor": "analyst-2",
                    "payload": {"lure_arm": "ssh-credential-bait"},
                    "metadata": {"tenant_id": "default"},
                },
            ],
            "count": 2,
            "store": {"enabled": True},
        }

    orchestrator.theater_actions = stubbed  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/theater/actions?action_types=label")
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert payload["actions"][0]["action_type"] == "label"
    assert payload["filtering"]["action_types"] == ["label"]


def test_dashboard_api_theater_actions_support_actor_and_session_prefix_filters() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    def stubbed(*, limit: int, session_id: str | None, action_type: str | None):
        _ = (limit, session_id, action_type)
        return {
            "actions": [
                {
                    "row_id": 7,
                    "created_at": "2026-02-21T00:00:07+00:00",
                    "action_type": "label",
                    "session_id": "prod-001",
                    "recommendation_id": "rec-7",
                    "actor": "team-alpha",
                    "payload": {"label": "high_value_actor"},
                    "metadata": {"tenant_id": "default"},
                },
                {
                    "row_id": 8,
                    "created_at": "2026-02-21T00:00:08+00:00",
                    "action_type": "label",
                    "session_id": "prod-002",
                    "recommendation_id": "rec-8",
                    "actor": "team-beta",
                    "payload": {"label": "medium_value_actor"},
                    "metadata": {"tenant_id": "default"},
                },
            ],
            "count": 2,
            "store": {"enabled": True},
        }

    orchestrator.theater_actions = stubbed  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/theater/actions?actor_prefix=team-a&session_prefix=prod-00")
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert payload["actions"][0]["actor"] == "team-alpha"
    assert payload["filtering"]["actor_prefix"] == "team-a"
    assert payload["filtering"]["session_prefix"] == "prod-00"


def test_dashboard_api_theater_actions_support_session_ids_filter() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    def stubbed(*, limit: int, session_id: str | None, action_type: str | None):
        _ = (limit, session_id, action_type)
        return {
            "actions": [
                {
                    "row_id": 18,
                    "created_at": "2026-02-21T00:00:18+00:00",
                    "action_type": "label",
                    "session_id": "prod-001",
                    "recommendation_id": "rec-18",
                    "actor": "team-alpha",
                    "payload": {"label": "high_value_actor"},
                    "metadata": {"tenant_id": "default"},
                },
                {
                    "row_id": 19,
                    "created_at": "2026-02-21T00:00:19+00:00",
                    "action_type": "label",
                    "session_id": "prod-002",
                    "recommendation_id": "rec-19",
                    "actor": "team-beta",
                    "payload": {"label": "medium_value_actor"},
                    "metadata": {"tenant_id": "default"},
                },
                {
                    "row_id": 20,
                    "created_at": "2026-02-21T00:00:20+00:00",
                    "action_type": "apply_lure",
                    "session_id": "prod-003",
                    "recommendation_id": "rec-20",
                    "actor": "team-gamma",
                    "payload": {"lure_arm": "ssh-credential-bait"},
                    "metadata": {"tenant_id": "default"},
                },
            ],
            "count": 3,
            "store": {"enabled": True},
        }

    orchestrator.theater_actions = stubbed  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/theater/actions?session_ids=prod-001,prod-003")
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 2
    assert [item["session_id"] for item in payload["actions"]] == ["prod-003", "prod-001"]
    assert payload["filtering"]["session_ids"] == ["prod-001", "prod-003"]


def test_dashboard_api_theater_actions_support_query_filter() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    def stubbed(*, limit: int, session_id: str | None, action_type: str | None):
        _ = (limit, session_id, action_type)
        return {
            "actions": [
                {
                    "row_id": 9,
                    "created_at": "2026-02-21T00:00:09+00:00",
                    "action_type": "label",
                    "session_id": "prod-009",
                    "recommendation_id": "rec-9",
                    "actor": "team-zeta",
                    "payload": {"label": "high_value_actor"},
                    "metadata": {"ticket": "SOC-1009"},
                },
                {
                    "row_id": 10,
                    "created_at": "2026-02-21T00:00:10+00:00",
                    "action_type": "apply_lure",
                    "session_id": "prod-010",
                    "recommendation_id": "rec-10",
                    "actor": "team-theta",
                    "payload": {"lure_arm": "http-query-bait"},
                    "metadata": {"ticket": "SOC-1010"},
                },
            ],
            "count": 2,
            "store": {"enabled": True},
        }

    orchestrator.theater_actions = stubbed  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/theater/actions?query=soc-1010")
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert payload["actions"][0]["session_id"] == "prod-010"
    assert payload["filtering"]["query"] == "soc-1010"


def test_dashboard_api_theater_actions_rejects_invalid_created_after() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/theater/actions?created_after=not-a-timestamp")
    assert response.status_code == 400
    assert "created_after" in response.json()["detail"]


def test_dashboard_api_theater_actions_export_supports_csv_format() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    def stubbed(*, limit: int, session_id: str | None, action_type: str | None):
        _ = (limit, session_id, action_type)
        return {
            "actions": [
                {
                    "row_id": 10,
                    "created_at": "2026-02-21T00:00:10+00:00",
                    "action_type": "apply_lure",
                    "session_id": "s-export",
                    "recommendation_id": "rec-export",
                    "actor": "analyst-export",
                    "payload": {"lure_arm": "ssh-credential-bait"},
                    "metadata": {"tenant_id": "default"},
                }
            ],
            "count": 1,
            "store": {"enabled": True},
        }

    orchestrator.theater_actions = stubbed  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/theater/actions/export?format=csv")
    assert response.status_code == 200
    assert "text/csv" in response.headers.get("content-type", "")
    assert "row_id,created_at,action_type,session_id" in response.text
    assert "apply_lure" in response.text


def test_dashboard_api_theater_actions_export_supports_jsonl_format() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    def stubbed(*, limit: int, session_id: str | None, action_type: str | None):
        _ = (limit, session_id, action_type)
        return {
            "actions": [
                {
                    "row_id": 11,
                    "created_at": "2026-02-21T00:00:11+00:00",
                    "action_type": "label",
                    "session_id": "s-export-2",
                    "recommendation_id": "rec-export-2",
                    "actor": "analyst-export-2",
                    "payload": {"label": "high_value_actor"},
                    "metadata": {"tenant_id": "default"},
                }
            ],
            "count": 1,
            "store": {"enabled": True},
        }

    orchestrator.theater_actions = stubbed  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/theater/actions/export?format=jsonl")
    assert response.status_code == 200
    assert "application/x-ndjson" in response.headers.get("content-type", "")
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert lines
    assert '"record_type":"theater_action"' in lines[0]


def test_dashboard_api_theater_actions_export_supports_tsv_format() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    def stubbed(*, limit: int, session_id: str | None, action_type: str | None):
        _ = (limit, session_id, action_type)
        return {
            "actions": [
                {
                    "row_id": 12,
                    "created_at": "2026-02-21T00:00:12+00:00",
                    "action_type": "label",
                    "session_id": "s-export-tsv",
                    "recommendation_id": "rec-export-tsv",
                    "actor": "analyst-export-tsv",
                    "payload": {"label": "high_value_actor"},
                    "metadata": {"tenant_id": "default"},
                }
            ],
            "count": 1,
            "store": {"enabled": True},
        }

    orchestrator.theater_actions = stubbed  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/theater/actions/export?format=tsv")
    assert response.status_code == 200
    assert "text/tab-separated-values" in response.headers.get("content-type", "")
    assert "row_id\tcreated_at\taction_type\tsession_id" in response.text
    assert "label" in response.text


def test_dashboard_api_theater_actions_export_supports_logfmt_format() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    def stubbed(*, limit: int, session_id: str | None, action_type: str | None):
        _ = (limit, session_id, action_type)
        return {
            "actions": [
                {
                    "row_id": 15,
                    "created_at": "2026-02-21T00:00:15+00:00",
                    "action_type": "label",
                    "session_id": "s-export-logfmt",
                    "recommendation_id": "rec-export-logfmt",
                    "actor": "analyst-export-logfmt",
                    "payload": {"label": "high_value_actor"},
                    "metadata": {"tenant_id": "default"},
                }
            ],
            "count": 1,
            "store": {"enabled": True},
        }

    orchestrator.theater_actions = stubbed  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/theater/actions/export?format=logfmt")
    assert response.status_code == 200
    assert "text/plain" in response.headers.get("content-type", "")
    assert "record_type=theater_action" in response.text
    assert "action_type=\"label\"" in response.text


def test_dashboard_api_theater_actions_export_supports_cef_format() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    def stubbed(*, limit: int, session_id: str | None, action_type: str | None):
        _ = (limit, session_id, action_type)
        return {
            "actions": [
                {
                    "row_id": 16,
                    "created_at": "2026-02-21T00:00:16+00:00",
                    "action_type": "apply_lure",
                    "session_id": "s-export-cef",
                    "recommendation_id": "rec-export-cef",
                    "actor": "analyst-export-cef",
                    "payload": {"lure_arm": "ssh-credential-bait"},
                    "metadata": {"tenant_id": "default"},
                }
            ],
            "count": 1,
            "store": {"enabled": True},
        }

    orchestrator.theater_actions = stubbed  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/theater/actions/export?format=cef")
    assert response.status_code == 200
    assert "text/plain" in response.headers.get("content-type", "")
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("CEF:0|ClownPeanuts|Theater Actions|0.1.0|")


def test_dashboard_api_theater_actions_export_supports_leef_format() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    def stubbed(*, limit: int, session_id: str | None, action_type: str | None):
        _ = (limit, session_id, action_type)
        return {
            "actions": [
                {
                    "row_id": 17,
                    "created_at": "2026-02-21T00:00:17+00:00",
                    "action_type": "label",
                    "session_id": "s-export-leef",
                    "recommendation_id": "rec-export-leef",
                    "actor": "analyst-export-leef",
                    "payload": {"label": "high_value_actor"},
                    "metadata": {"tenant_id": "default"},
                }
            ],
            "count": 1,
            "store": {"enabled": True},
        }

    orchestrator.theater_actions = stubbed  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/theater/actions/export?format=leef")
    assert response.status_code == 200
    assert "text/plain" in response.headers.get("content-type", "")
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("LEEF:2.0|ClownPeanuts|Theater Actions|0.1.0|")


def test_dashboard_api_theater_actions_export_supports_syslog_format() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    def stubbed(*, limit: int, session_id: str | None, action_type: str | None):
        _ = (limit, session_id, action_type)
        return {
            "actions": [
                {
                    "row_id": 21,
                    "created_at": "2026-02-21T00:00:21+00:00",
                    "action_type": "apply_lure",
                    "session_id": "s-export-syslog",
                    "recommendation_id": "rec-export-syslog",
                    "actor": "analyst-export-syslog",
                    "payload": {"lure_arm": "http-query-bait"},
                    "metadata": {"tenant_id": "default"},
                }
            ],
            "count": 1,
            "store": {"enabled": True},
        }

    orchestrator.theater_actions = stubbed  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/theater/actions/export?format=syslog")
    assert response.status_code == 200
    assert "text/plain" in response.headers.get("content-type", "")
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("<133>1 ")
    assert " clownpeanuts theater-actions " in lines[0]


def test_dashboard_api_theater_actions_export_supports_action_types_filter() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    def stubbed(*, limit: int, session_id: str | None, action_type: str | None):
        _ = (limit, session_id, action_type)
        return {
            "actions": [
                {
                    "row_id": 13,
                    "created_at": "2026-02-21T00:00:13+00:00",
                    "action_type": "apply_lure",
                    "session_id": "s-export-a",
                    "recommendation_id": "rec-export-a",
                    "actor": "analyst-export-a",
                    "payload": {"lure_arm": "http-query-bait"},
                    "metadata": {"tenant_id": "default"},
                },
                {
                    "row_id": 14,
                    "created_at": "2026-02-21T00:00:14+00:00",
                    "action_type": "label",
                    "session_id": "s-export-b",
                    "recommendation_id": "rec-export-b",
                    "actor": "analyst-export-b",
                    "payload": {"label": "high_value_actor"},
                    "metadata": {"tenant_id": "default"},
                },
            ],
            "count": 2,
            "store": {"enabled": True},
        }

    orchestrator.theater_actions = stubbed  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/theater/actions/export?action_types=label")
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert payload["actions"][0]["action_type"] == "label"


def test_dashboard_api_theater_actions_export_supports_session_ids_filter() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    def stubbed(*, limit: int, session_id: str | None, action_type: str | None):
        _ = (limit, session_id, action_type)
        return {
            "actions": [
                {
                    "row_id": 22,
                    "created_at": "2026-02-21T00:00:22+00:00",
                    "action_type": "label",
                    "session_id": "s-export-a",
                    "recommendation_id": "rec-export-a",
                    "actor": "analyst-export-a",
                    "payload": {"label": "high_value_actor"},
                    "metadata": {"tenant_id": "default"},
                },
                {
                    "row_id": 23,
                    "created_at": "2026-02-21T00:00:23+00:00",
                    "action_type": "label",
                    "session_id": "s-export-b",
                    "recommendation_id": "rec-export-b",
                    "actor": "analyst-export-b",
                    "payload": {"label": "medium_value_actor"},
                    "metadata": {"tenant_id": "default"},
                },
            ],
            "count": 2,
            "store": {"enabled": True},
        }

    orchestrator.theater_actions = stubbed  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/theater/actions/export?session_ids=s-export-b")
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert payload["actions"][0]["session_id"] == "s-export-b"


def test_dashboard_api_theater_recommendations_support_filter_sort_and_compact() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    def stubbed(*, limit: int, session_limit: int, events_per_session: int):
        _ = (limit, session_limit, events_per_session)
        return {
            "enabled": True,
            "mode": "apply-enabled",
            "count": 3,
            "generated_at": "2026-02-20T00:00:00+00:00",
            "latency_ms": 12.0,
            "within_latency_budget": True,
            "recommendations": [
                {
                    "recommendation_id": "rec-1",
                    "session_id": "s-a",
                    "context_key": "ssh:discovery",
                    "recommended_lure_arm": "ssh-credential-bait",
                    "predicted_stage": "credential_access",
                    "predicted_action": "credential_stuffing",
                    "confidence": 0.91,
                    "prediction_confidence": 0.77,
                    "apply_allowed": True,
                    "queue_position": 2,
                    "rationale": "a",
                    "explanation_digest": "digest-a",
                    "explanation": {"components": {"composite_score": 0.85}},
                },
                {
                    "recommendation_id": "rec-2",
                    "session_id": "s-b",
                    "context_key": "http_admin:reconnaissance",
                    "recommended_lure_arm": "http-query-bait",
                    "predicted_stage": "reconnaissance",
                    "predicted_action": "enumeration",
                    "confidence": 0.42,
                    "prediction_confidence": 0.41,
                    "apply_allowed": False,
                    "queue_position": 1,
                    "rationale": "b",
                    "explanation_digest": "digest-b",
                    "explanation": {"components": {"composite_score": 0.4}},
                },
                {
                    "recommendation_id": "rec-3",
                    "session_id": "s-c",
                    "context_key": "redis:collection",
                    "recommended_lure_arm": "mysql-query-bait",
                    "predicted_stage": "credential_access",
                    "predicted_action": "dump_credentials",
                    "confidence": 0.81,
                    "prediction_confidence": 0.75,
                    "apply_allowed": True,
                    "queue_position": 3,
                    "rationale": "c",
                    "explanation_digest": "digest-c",
                    "explanation": {"components": {"composite_score": 0.75}},
                },
            ],
        }

    orchestrator.theater_recommendations = stubbed  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get(
        "/theater/recommendations?limit=10&session_limit=25&events_per_session=50"
        "&min_confidence=0.8&predicted_stage=credential_access&lure_arm=ssh-credential-bait"
        "&context_key_prefix=ssh:&apply_allowed_only=true"
        "&include_explanation=false&compact=true&sort_by=session_id&sort_order=asc"
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    recommendations = payload["recommendations"]
    assert isinstance(recommendations, list)
    assert [item["session_id"] for item in recommendations] == ["s-a"]
    assert [item["result_rank"] for item in recommendations] == [1]
    assert "explanation" not in recommendations[0]
    assert set(recommendations[0].keys()) <= {
        "recommendation_id",
        "session_id",
        "context_key",
        "recommended_lure_arm",
        "predicted_stage",
        "predicted_action",
        "confidence",
        "prediction_confidence",
        "apply_allowed",
        "queue_position",
        "result_rank",
        "explanation_digest",
    }
    filtering = payload["filtering"]
    assert filtering["compact"] is True
    assert filtering["sort_by"] == "session_id"
    assert filtering["sort_order"] == "asc"
    assert filtering["predicted_stage"] == "credential_access"
    assert filtering["lure_arm"] == "ssh-credential-bait"
    assert filtering["context_key_prefix"] == "ssh:"
    assert filtering["min_prediction_confidence"] == 0.0


def test_dashboard_api_theater_recommendations_filters_min_prediction_confidence() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)

    def stubbed(*, limit: int, session_limit: int, events_per_session: int):
        _ = (limit, session_limit, events_per_session)
        return {
            "enabled": True,
            "mode": "apply-enabled",
            "count": 2,
            "generated_at": "2026-02-21T00:00:00+00:00",
            "latency_ms": 11.0,
            "within_latency_budget": True,
            "recommendations": [
                {
                    "recommendation_id": "rec-hi",
                    "session_id": "s-hi",
                    "predicted_stage": "credential_access",
                    "recommended_lure_arm": "ssh-credential-bait",
                    "confidence": 0.8,
                    "prediction_confidence": 0.9,
                    "apply_allowed": True,
                },
                {
                    "recommendation_id": "rec-lo",
                    "session_id": "s-lo",
                    "predicted_stage": "credential_access",
                    "recommended_lure_arm": "ssh-credential-bait",
                    "confidence": 0.9,
                    "prediction_confidence": 0.2,
                    "apply_allowed": True,
                },
            ],
        }

    orchestrator.theater_recommendations = stubbed  # type: ignore[method-assign]
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/theater/recommendations?min_prediction_confidence=0.8")
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert payload["recommendations"][0]["session_id"] == "s-hi"
    assert payload["filtering"]["min_prediction_confidence"] == 0.8


def test_dashboard_api_intel_handoff_route_returns_structured_summary() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="handoff-s1", source_ip="203.0.113.40")
    orchestrator.session_manager.record_event(
        session_id="handoff-s1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.40", "command": "whoami"},
    )
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/intel/handoff?max_techniques=3&max_sessions=3")
    assert response.status_code == 200
    payload = response.json()
    assert "generated_at" in payload
    assert "summary" in payload
    assert "top_techniques" in payload
    assert "priority_sessions" in payload
    assert "markdown" in payload
    assert "cef" in payload
    assert "logfmt" in payload
    assert "Executive Snapshot" in payload["markdown"]


def test_dashboard_api_intel_handoff_route_supports_historical_report_lookup() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="handoff-history-s1", source_ip="203.0.113.41")
    orchestrator.session_manager.record_event(
        session_id="handoff-history-s1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.41", "command": "id"},
    )
    _ = orchestrator.intelligence_report(limit=100, events_per_session=100)
    history = orchestrator.intelligence_history(limit=1)
    report_rows = history.get("reports", [])
    assert isinstance(report_rows, list)
    assert report_rows
    report_id = int(report_rows[0]["report_id"])

    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get(f"/intel/handoff?report_id={report_id}&max_techniques=2&max_sessions=2")
    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["sessions"] >= 1

    missing_response = client.get("/intel/handoff?report_id=999999")
    assert missing_response.status_code == 404


def test_dashboard_api_intel_handoff_route_supports_markdown_format() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="handoff-md-s1", source_ip="203.0.113.42")
    orchestrator.session_manager.record_event(
        session_id="handoff-md-s1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.42", "command": "uname -a"},
    )
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/intel/handoff?format=markdown&max_techniques=2&max_sessions=2")
    assert response.status_code == 200
    assert "text/markdown" in response.headers.get("content-type", "")
    assert "ClownPeanuts SOC Handoff" in response.text
    assert "Executive Snapshot" in response.text


def test_dashboard_api_intel_handoff_route_supports_csv_format() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="handoff-csv-s1", source_ip="203.0.113.43")
    orchestrator.session_manager.record_event(
        session_id="handoff-csv-s1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.43", "command": "whoami"},
    )
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/intel/handoff?format=csv&max_techniques=2&max_sessions=2")
    assert response.status_code == 200
    assert "text/csv" in response.headers.get("content-type", "")
    assert "record_type,generated_at" in response.text
    assert "summary," in response.text


def test_dashboard_api_intel_handoff_route_supports_tsv_format() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="handoff-tsv-s1", source_ip="203.0.113.44")
    orchestrator.session_manager.record_event(
        session_id="handoff-tsv-s1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.44", "command": "whoami"},
    )
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/intel/handoff?format=tsv&max_techniques=2&max_sessions=2")
    assert response.status_code == 200
    assert "text/tab-separated-values" in response.headers.get("content-type", "")
    assert "record_type\tgenerated_at" in response.text
    assert "summary\t" in response.text


def test_dashboard_api_intel_handoff_route_supports_ndjson_format() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="handoff-ndjson-s1", source_ip="203.0.113.47")
    orchestrator.session_manager.record_event(
        session_id="handoff-ndjson-s1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.47", "command": "whoami"},
    )
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/intel/handoff?format=ndjson&max_techniques=2&max_sessions=2")
    assert response.status_code == 200
    assert "application/x-ndjson" in response.headers.get("content-type", "")
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert lines
    assert '"record_type":"summary"' in lines[0]


def test_dashboard_api_intel_handoff_route_supports_jsonl_format() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="handoff-jsonl-s1", source_ip="203.0.113.52")
    orchestrator.session_manager.record_event(
        session_id="handoff-jsonl-s1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.52", "command": "whoami"},
    )
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/intel/handoff?format=jsonl&max_techniques=2&max_sessions=2")
    assert response.status_code == 200
    assert "application/x-ndjson" in response.headers.get("content-type", "")
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert lines
    assert '"record_type":"summary"' in lines[0]


def test_dashboard_api_intel_handoff_route_supports_cef_format() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="handoff-cef-s1", source_ip="203.0.113.48")
    orchestrator.session_manager.record_event(
        session_id="handoff-cef-s1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.48", "command": "whoami"},
    )
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/intel/handoff?format=cef&max_techniques=2&max_sessions=2")
    assert response.status_code == 200
    assert "text/plain" in response.headers.get("content-type", "")
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("CEF:0|ClownPeanuts|SOC Handoff|0.1.0|")


def test_dashboard_api_intel_handoff_route_supports_leef_format() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="handoff-leef-s1", source_ip="203.0.113.49")
    orchestrator.session_manager.record_event(
        session_id="handoff-leef-s1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.49", "command": "whoami"},
    )
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/intel/handoff?format=leef&max_techniques=2&max_sessions=2")
    assert response.status_code == 200
    assert "text/plain" in response.headers.get("content-type", "")
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("LEEF:2.0|ClownPeanuts|SOC Handoff|0.1.0|")


def test_dashboard_api_intel_handoff_route_supports_syslog_format() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="handoff-syslog-s1", source_ip="203.0.113.50")
    orchestrator.session_manager.record_event(
        session_id="handoff-syslog-s1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.50", "command": "whoami"},
    )
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/intel/handoff?format=syslog&max_techniques=2&max_sessions=2")
    assert response.status_code == 200
    assert "text/plain" in response.headers.get("content-type", "")
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("<")
    assert "intel-handoff" in lines[0]


def test_dashboard_api_intel_handoff_route_supports_logfmt_format() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="handoff-logfmt-s1", source_ip="203.0.113.51")
    orchestrator.session_manager.record_event(
        session_id="handoff-logfmt-s1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.51", "command": "whoami"},
    )
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/intel/handoff?format=logfmt&max_techniques=2&max_sessions=2")
    assert response.status_code == 200
    assert "text/plain" in response.headers.get("content-type", "")
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("record=summary ")
    assert "generated_at=" in lines[0]


def test_dashboard_api_hardening_controls_docs_cors_and_trusted_hosts() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config(
        {
            "api": {
                "docs_enabled": False,
                "cors_allow_origins": ["https://soc.example"],
                "cors_allow_credentials": False,
                "trusted_hosts": ["allowed.test"],
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)

    allowed_client = testclient.TestClient(app, base_url="http://allowed.test")
    health_response = allowed_client.get("/health", headers={"Origin": "https://soc.example"})
    assert health_response.status_code == 200
    assert health_response.headers.get("access-control-allow-origin") == "https://soc.example"
    docs_response = allowed_client.get("/docs")
    assert docs_response.status_code == 404

    blocked_client = testclient.TestClient(app, base_url="http://blocked.test")
    blocked_response = blocked_client.get("/health")
    assert blocked_response.status_code == 400


def test_dashboard_api_rejects_wildcard_cors_when_credentials_enabled() -> None:
    _ = pytest.importorskip("fastapi")

    config = parse_config({"services": []})
    config.api.cors_allow_origins = ["*"]
    config.api.cors_allow_credentials = True
    orchestrator = Orchestrator(config)
    with pytest.raises(RuntimeError, match="cors_allow_credentials cannot be true"):
        create_app(orchestrator)


def test_dashboard_api_rate_limit_restricts_non_exempt_paths() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config(
        {
            "api": {
                "rate_limit_enabled": True,
                "rate_limit_requests_per_minute": 1,
                "rate_limit_burst": 0,
                "rate_limit_exempt_paths": ["/health"],
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    first_status = client.get("/status")
    assert first_status.status_code == 200
    assert first_status.headers.get("x-ratelimit-limit") == "1"
    assert first_status.headers.get("x-ratelimit-remaining") == "0"

    second_status = client.get("/status")
    assert second_status.status_code == 429
    assert second_status.headers.get("retry-after") is not None
    assert second_status.headers.get("x-ratelimit-limit") == "1"

    health_response = client.get("/health")
    assert health_response.status_code == 200


def test_dashboard_api_rejects_oversized_mutation_payload() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config(
        {
            "api": {
                "max_request_body_bytes": 1024,
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    oversized_summary = "x" * 2000
    response = client.post("/alerts/test", json={"summary": oversized_summary})
    assert response.status_code == 413
    assert response.json()["detail"] == "request body too large"

    ok_response = client.post("/alerts/test", json={"summary": "ok"})
    assert ok_response.status_code == 200

    malformed_payload = '{"summary":"' + ("y" * 2000) + '"}'
    malformed_length_response = client.post(
        "/alerts/test",
        content=malformed_payload,
        headers={"content-type": "application/json", "content-length": "invalid"},
    )
    assert malformed_length_response.status_code == 413


def test_dashboard_api_auth_requires_token_when_enabled() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config(
        {
            "api": {
                "auth_enabled": True,
                "auth_operator_tokens": [OPERATOR_TOKEN],
                "auth_viewer_tokens": [VIEWER_TOKEN],
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    unauth_status_response = client.get("/status")
    assert unauth_status_response.status_code == 401
    assert unauth_status_response.headers.get("www-authenticate") == "Bearer"

    health_response = client.get("/health")
    assert health_response.status_code == 200

    viewer_status_response = client.get("/status", headers={"Authorization": f"Bearer {VIEWER_TOKEN}"})
    assert viewer_status_response.status_code == 200

    api_key_status_response = client.get("/status", headers={"X-API-Key": VIEWER_TOKEN})
    assert api_key_status_response.status_code == 200


def test_dashboard_api_auth_accepts_cookie_token_when_enabled() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config(
        {
            "api": {
                "auth_enabled": True,
                "auth_operator_tokens": [OPERATOR_TOKEN],
                "auth_viewer_tokens": [VIEWER_TOKEN],
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    client.cookies.set("cp_api_token", VIEWER_TOKEN)
    response = client.get("/status")
    assert response.status_code == 200


def test_dashboard_api_auth_can_require_health_authentication() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config(
        {
            "api": {
                "auth_enabled": True,
                "auth_operator_tokens": [OPERATOR_TOKEN],
                "allow_unauthenticated_health": False,
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    unauth_health_response = client.get("/health")
    assert unauth_health_response.status_code == 401

    auth_health_response = client.get("/health", headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"})
    assert auth_health_response.status_code == 200


def test_dashboard_api_auth_restricts_mutations_to_operator_tokens() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config(
        {
            "api": {
                "auth_enabled": True,
                "auth_operator_tokens": [OPERATOR_TOKEN],
                "auth_viewer_tokens": [VIEWER_TOKEN],
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    viewer_rotate_response = client.post("/intel/rotate", headers={"Authorization": f"Bearer {VIEWER_TOKEN}"})
    assert viewer_rotate_response.status_code == 403

    operator_rotate_response = client.post("/intel/rotate", headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"})
    assert operator_rotate_response.status_code == 200

    operator_alert_response = client.post(
        "/alerts/test",
        headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
        json={"summary": "operator synthetic alert"},
    )
    assert operator_alert_response.status_code == 200


def test_dashboard_api_auth_websocket_requires_token_when_enabled() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")
    websockets = pytest.importorskip("starlette.websockets")

    config = parse_config(
        {
            "api": {
                "auth_enabled": True,
                "auth_operator_tokens": [OPERATOR_TOKEN],
                "auth_viewer_tokens": [VIEWER_TOKEN],
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    with client.websocket_connect("/ws/theater/live") as websocket:
        with pytest.raises(websockets.WebSocketDisconnect) as unauth_exc:
            websocket.receive_json()
    assert unauth_exc.value.code == 4401

    encoded = _encode_ws_token(VIEWER_TOKEN)
    with client.websocket_connect(
        "/ws/theater/live?interval_ms=100",
        subprotocols=["cp-events-v1", f"cp-auth.{encoded}"],
    ) as websocket:
        payload = websocket.receive_json()
        assert payload["stream"] == "theater_live"


def test_dashboard_api_auth_websocket_accepts_cookie_token_when_enabled() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config(
        {
            "api": {
                "auth_enabled": True,
                "auth_operator_tokens": [OPERATOR_TOKEN],
                "auth_viewer_tokens": [VIEWER_TOKEN],
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    client.cookies.set("cp_api_token", VIEWER_TOKEN)
    with client.websocket_connect("/ws/theater/live?interval_ms=100") as websocket:
        payload = websocket.receive_json()
        assert payload["stream"] == "theater_live"


def test_dashboard_api_theater_websocket_stream() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="ws-s1", source_ip="203.0.113.90")
    orchestrator.session_manager.record_event(
        session_id="ws-s1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.90", "command": "whoami"},
    )

    app = create_app(orchestrator)
    client = testclient.TestClient(app)
    with client.websocket_connect("/ws/theater/live?limit=10&events_per_session=10&interval_ms=100") as websocket:
        payload = websocket.receive_json()
        assert payload["stream"] == "theater_live"
        assert "payload" in payload
        assert payload["payload"]["count"] >= 1
        assert "recommendations" in payload["payload"]


def test_dashboard_api_intel_routes() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    orchestrator.session_manager.get_or_create(session_id="s1", source_ip="203.0.113.11")
    orchestrator.session_manager.record_event(
        session_id="s1",
        service="ssh",
        action="command",
        payload={"source_ip": "203.0.113.11", "command": "whoami"},
    )
    orchestrator.session_manager.record_event(
        session_id="s1",
        service="http_admin",
        action="credential_capture",
        payload={
            "source_ip": "203.0.113.11",
            "indicator_type": "canary_token",
            "token": "ct-canary-001",
        },
    )
    orchestrator.session_manager.get_or_create(session_id="s2", source_ip="203.0.113.12")
    orchestrator.session_manager.record_event(
        session_id="s2",
        service="ssh",
        action="auth_attempt",
        payload={"source_ip": "203.0.113.12", "username": "admin"},
    )
    orchestrator.session_manager.record_event(
        session_id="s2",
        service="http_admin",
        action="credential_capture",
        payload={"source_ip": "203.0.113.12", "username": "admin", "password": "hunter2"},
    )
    orchestrator.rabbit_hole.resolve_narrative_context(
        session_id="s1",
        source_ip="203.0.113.11",
        tenant_id="default",
        service="ssh",
        action="command",
        hints={"command": "whoami"},
    )

    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    templates_inventory_response = client.get("/templates/inventory")
    assert templates_inventory_response.status_code == 200
    assert "enabled" in templates_inventory_response.json()

    templates_plan_response = client.get("/templates/plan")
    assert templates_plan_response.status_code == 200
    assert "services" in templates_plan_response.json()

    templates_plan_all_response = client.get("/templates/plan?all_tenants=true")
    assert templates_plan_all_response.status_code == 200
    assert templates_plan_all_response.json()["all_tenants"] is True
    assert templates_plan_all_response.json()["tenant_count"] >= 1

    templates_validate_response = client.get("/templates/validate")
    assert templates_validate_response.status_code == 200
    assert "ok" in templates_validate_response.json()
    assert "error_count" in templates_validate_response.json()

    templates_validate_all_response = client.get("/templates/validate?all_tenants=true")
    assert templates_validate_all_response.status_code == 200
    assert templates_validate_all_response.json()["all_tenants"] is True
    assert templates_validate_all_response.json()["tenant_count"] >= 1

    templates_diff_response = client.get("/templates/diff")
    assert templates_diff_response.status_code == 200
    assert "different" in templates_diff_response.json()

    templates_diff_matrix_response = client.get("/templates/diff/matrix")
    assert templates_diff_matrix_response.status_code == 200
    assert "comparison_count" in templates_diff_matrix_response.json()

    map_response = client.get("/intel/map")
    assert map_response.status_code == 200
    assert map_response.json()["count"] >= 1

    report_response = client.get("/intel/report")
    assert report_response.status_code == 200
    assert "report_id" in report_response.json()
    assert "coherence_score_avg" in report_response.json()["totals"]
    assert "coherence_score" in report_response.json()["sessions"][0]
    assert "coherence_violations" in report_response.json()["sessions"][0]

    history_response = client.get("/intel/history")
    assert history_response.status_code == 200
    assert history_response.json()["count"] >= 1
    report_id = int(history_response.json()["reports"][0]["report_id"])

    history_sessions_response = client.get("/intel/history/sessions")
    assert history_sessions_response.status_code == 200
    assert "sessions" in history_sessions_response.json()
    assert "coherence_score" in history_sessions_response.json()["sessions"][0]
    assert "coherence_violations" in history_sessions_response.json()["sessions"][0]

    history_report_response = client.get(f"/intel/history/{report_id}")
    assert history_report_response.status_code == 200
    assert history_report_response.json()["found"] is True
    assert history_report_response.json()["report"]["report_id"] == report_id

    history_report_sessions_response = client.get(f"/intel/history/{report_id}/sessions")
    assert history_report_sessions_response.status_code == 200
    assert history_report_sessions_response.json()["report_id"] == report_id

    replay_response = client.get("/sessions/s1/replay")
    assert replay_response.status_code == 200
    assert replay_response.json()["found"] is True
    assert replay_response.json()["session"]["session_id"] == "s1"

    replay_compare_response = client.get("/sessions/replay/compare?left_session_id=s1&right_session_id=s2")
    assert replay_compare_response.status_code == 200
    assert replay_compare_response.json()["found"] is True
    assert "comparison" in replay_compare_response.json()
    assert "summary" in replay_compare_response.json()["comparison"]
    assert isinstance(replay_compare_response.json()["comparison"]["operator_actions"], list)

    theater_live_response = client.get("/theater/live")
    assert theater_live_response.status_code == 200
    assert theater_live_response.json()["count"] >= 1
    assert "within_latency_budget" in theater_live_response.json()
    assert theater_live_response.json()["within_latency_budget"] is True

    theater_session_response = client.get("/theater/sessions/s1")
    assert theater_session_response.status_code == 200
    assert theater_session_response.json()["session_id"] == "s1"
    assert 0.0 <= float(theater_session_response.json()["prediction"]["confidence"]) <= 1.0

    theater_session_bundle_response = client.get("/theater/sessions/s1/bundle")
    assert theater_session_bundle_response.status_code == 200
    assert theater_session_bundle_response.json()["found"] is True
    assert theater_session_bundle_response.json()["session_id"] == "s1"
    assert theater_session_bundle_response.json()["replay"]["found"] is True
    assert theater_session_bundle_response.json()["theater_session"]["session_id"] == "s1"

    theater_recommendations_response = client.get("/theater/recommendations")
    assert theater_recommendations_response.status_code == 200
    assert theater_recommendations_response.json()["count"] >= 1
    assert "bandit_metrics" in theater_recommendations_response.json()
    assert "explanation" in theater_recommendations_response.json()["recommendations"][0]
    assert "explanation_digest" in theater_recommendations_response.json()["recommendations"][0]
    assert "prediction_confidence" in theater_recommendations_response.json()["recommendations"][0]
    recommendation_id = str(theater_recommendations_response.json()["recommendations"][0]["recommendation_id"])

    theater_apply_response = client.post(
        "/theater/actions/apply-lure",
        json={
            "session_id": "s1",
            "recommendation_id": recommendation_id,
            "lure_arm": "ssh-credential-bait",
            "context_key": "ssh:discovery",
            "duration_seconds": 120,
            "actor": "analyst-1",
        },
    )
    assert theater_apply_response.status_code == 200
    assert theater_apply_response.json()["applied"] is True

    theater_label_response = client.post(
        "/theater/actions/label",
        json={
            "session_id": "s1",
            "recommendation_id": recommendation_id,
            "label": "high_value_actor",
            "confidence": 0.87,
            "actor": "analyst-1",
        },
    )
    assert theater_label_response.status_code == 200
    assert theater_label_response.json()["accepted"] is True

    theater_actions_response = client.get("/theater/actions?session_id=s1")
    assert theater_actions_response.status_code == 200
    assert theater_actions_response.json()["count"] >= 2

    canary_response = client.get("/intel/canaries")
    assert canary_response.status_code == 200
    assert canary_response.json()["total_hits"] >= 1

    fingerprints_response = client.get("/intel/fingerprints")
    assert fingerprints_response.status_code == 200
    assert "fingerprints" in fingerprints_response.json()

    kill_chain_response = client.get("/intel/kill-chain")
    assert kill_chain_response.status_code == 200
    assert "stage_counts" in kill_chain_response.json()

    coverage_response = client.get("/intel/coverage")
    assert coverage_response.status_code == 200
    assert "coverage_percent" in coverage_response.json()
    assert "gaps" in coverage_response.json()

    kill_chain_graph_response = client.get("/intel/kill-chain/graph")
    assert kill_chain_graph_response.status_code == 200
    assert "nodes" in kill_chain_graph_response.json()
    assert "edges" in kill_chain_graph_response.json()

    credential_reuse_response = client.get("/intel/credential-reuse")
    assert credential_reuse_response.status_code == 200
    assert "patterns" in credential_reuse_response.json()

    geography_response = client.get("/intel/geography")
    assert geography_response.status_code == 200
    assert "countries" in geography_response.json()

    biometrics_response = client.get("/intel/biometrics")
    assert biometrics_response.status_code == 200
    assert "styles" in biometrics_response.json()

    bandit_arms_response = client.get("/intel/bandit/arms")
    assert bandit_arms_response.status_code == 200
    assert "bandit" in bandit_arms_response.json()
    assert "arms" in bandit_arms_response.json()["bandit"]

    bandit_performance_response = client.get("/intel/bandit/performance")
    assert bandit_performance_response.status_code == 200
    assert "arms" in bandit_performance_response.json()
    assert "decision_count" in bandit_performance_response.json()

    bandit_observability_response = client.get("/intel/bandit/observability")
    assert bandit_observability_response.status_code == 200
    assert "sample_count" in bandit_observability_response.json()
    assert "computed" in bandit_observability_response.json()

    bandit_override_response = client.post(
        "/intel/bandit/override",
        json={"context_key": "ssh:recon", "arm": "arm-a", "duration_seconds": 120},
    )
    assert bandit_override_response.status_code == 200
    assert bandit_override_response.json()["override"]["applied"] is True

    bandit_reset_response = client.post("/intel/bandit/reset", json={"reason": "unit reset"})
    assert bandit_reset_response.status_code == 200
    assert bandit_reset_response.json()["reset"]["reason"] == "unit reset"

    canary_hit_response = client.post(
        "/intel/canary/hit",
        json={
            "token": "ct-canary-002",
            "source_ip": "203.0.113.77",
            "service": "http_admin",
            "metadata": {"channel": "dns"},
        },
    )
    assert canary_hit_response.status_code == 200
    assert canary_hit_response.json()["ingested"]["token"] == "ct-canary-002"
    assert canary_hit_response.json()["ingested"]["session_id"].startswith("canary-")

    canary_generate_response = client.post("/intel/canary/generate", json={"namespace": "corp", "token_type": "dns"})
    assert canary_generate_response.status_code == 200
    assert canary_generate_response.json()["token"]["token_type"] == "dns"
    assert canary_generate_response.json()["token"]["artifact"]["artifact_type"] == "dns"
    token_id = str(canary_generate_response.json()["token"]["token_id"])

    canary_tokens_response = client.get("/intel/canary/tokens")
    assert canary_tokens_response.status_code == 200
    assert canary_tokens_response.json()["count"] >= 1

    canary_token_detail_response = client.get(f"/intel/canary/tokens/{token_id}")
    assert canary_token_detail_response.status_code == 200
    assert canary_token_detail_response.json()["found"] is True
    assert canary_token_detail_response.json()["token"]["token_id"] == token_id

    canary_hits_response = client.get(f"/intel/canary/hits?token_id={token_id}")
    assert canary_hits_response.status_code == 200
    assert "hits" in canary_hits_response.json()

    canary_types_response = client.get("/intel/canary/types")
    assert canary_types_response.status_code == 200
    assert canary_types_response.json()["count"] >= 5

    rotate_response = client.post("/intel/rotate")
    assert rotate_response.status_code == 200
    assert "threat_intel" in rotate_response.json()

    rotate_preview_response = client.get("/intel/rotate/preview")
    assert rotate_preview_response.status_code == 200
    assert "threat_intel" in rotate_preview_response.json()

    stix_response = client.get("/intel/stix")
    assert stix_response.status_code == 200
    assert stix_response.json()["type"] == "bundle"

    stix_history_response = client.get(f"/intel/stix/history/{report_id}")
    assert stix_history_response.status_code == 200
    assert stix_history_response.json()["type"] == "bundle"

    navigator_response = client.get("/intel/attack-navigator")
    assert navigator_response.status_code == 200
    assert navigator_response.json()["domain"] == "enterprise-attack"
    assert isinstance(navigator_response.json()["techniques"], list)

    navigator_history_response = client.get(f"/intel/attack-navigator/history/{report_id}")
    assert navigator_history_response.status_code == 200
    assert navigator_history_response.json()["domain"] == "enterprise-attack"

    profiles_response = client.get("/intel/profiles")
    assert profiles_response.status_code == 200
    assert profiles_response.json()["profiles"]

    taxii_response = client.get("/intel/taxii/collections")
    assert taxii_response.status_code == 200
    assert taxii_response.json()["collections"][0]["id"] == "clownpeanuts-intel"

    taxii2_discovery_response = client.get("/taxii2/")
    assert taxii2_discovery_response.status_code == 200
    assert taxii2_discovery_response.json()["default"].endswith("/taxii2/api/")
    assert taxii2_discovery_response.json()["api_roots"]

    taxii2_api_root_response = client.get("/taxii2/api/")
    assert taxii2_api_root_response.status_code == 200
    assert "taxii-2.1" in taxii2_api_root_response.json()["versions"]

    taxii2_collections_response = client.get("/taxii2/api/collections")
    assert taxii2_collections_response.status_code == 200
    assert taxii2_collections_response.json()["collections"][0]["id"] == "clownpeanuts-intel"
    assert taxii2_collections_response.json()["collections"][0]["media_types"] == ["application/stix+json;version=2.1"]

    taxii2_collection_response = client.get("/taxii2/api/collections/clownpeanuts-intel")
    assert taxii2_collection_response.status_code == 200
    assert taxii2_collection_response.json()["id"] == "clownpeanuts-intel"

    taxii2_objects_response = client.get("/taxii2/api/collections/clownpeanuts-intel/objects")
    assert taxii2_objects_response.status_code == 200
    assert isinstance(taxii2_objects_response.json()["objects"], list)
    assert "more" in taxii2_objects_response.json()

    taxii2_objects_paged_response = client.get("/taxii2/api/collections/clownpeanuts-intel/objects?limit=1")
    assert taxii2_objects_paged_response.status_code == 200
    assert len(taxii2_objects_paged_response.json()["objects"]) <= 1

    taxii2_manifest_response = client.get("/taxii2/api/collections/clownpeanuts-intel/manifest")
    assert taxii2_manifest_response.status_code == 200
    assert isinstance(taxii2_manifest_response.json()["objects"], list)
    assert "more" in taxii2_manifest_response.json()

    taxii2_manifest_filtered_response = client.get(
        "/taxii2/api/collections/clownpeanuts-intel/manifest?added_after=1970-01-01T00:00:00Z"
    )
    assert taxii2_manifest_filtered_response.status_code == 200
    assert isinstance(taxii2_manifest_filtered_response.json()["objects"], list)

    taxii_objects_response = client.get("/intel/taxii/collections/clownpeanuts-intel/objects")
    assert taxii_objects_response.status_code == 200
    assert isinstance(taxii_objects_response.json()["objects"], list)
    assert taxii_objects_response.json()["bundle_id"].startswith("bundle--")

    taxii_objects_history_response = client.get(f"/intel/taxii/collections/clownpeanuts-intel/objects?report_id={report_id}")
    assert taxii_objects_history_response.status_code == 200
    assert isinstance(taxii_objects_history_response.json()["objects"], list)

    taxii_manifest_response = client.get("/intel/taxii/collections/clownpeanuts-intel/manifest")
    assert taxii_manifest_response.status_code == 200
    assert isinstance(taxii_manifest_response.json()["manifest"], list)

    taxii_manifest_history_response = client.get(
        f"/intel/taxii/collections/clownpeanuts-intel/manifest?report_id={report_id}"
    )
    assert taxii_manifest_history_response.status_code == 200
    assert isinstance(taxii_manifest_history_response.json()["manifest"], list)

    objects = taxii_objects_response.json()["objects"]
    assert objects
    object_id = str(objects[0]["id"])
    taxii_object_response = client.get(f"/intel/taxii/collections/clownpeanuts-intel/objects/{object_id}")
    assert taxii_object_response.status_code == 200
    assert taxii_object_response.json()["object"]["id"] == object_id

    history_objects = taxii_objects_history_response.json()["objects"]
    assert history_objects
    history_object_id = str(history_objects[0]["id"])
    taxii_object_history_response = client.get(
        f"/intel/taxii/collections/clownpeanuts-intel/objects/{history_object_id}?report_id={report_id}"
    )
    assert taxii_object_history_response.status_code == 200
    assert taxii_object_history_response.json()["object"]["id"] == history_object_id

    taxii2_object_response = client.get(f"/taxii2/api/collections/clownpeanuts-intel/objects/{object_id}")
    assert taxii2_object_response.status_code == 200
    assert taxii2_object_response.json()["id"] == object_id

    local_llm_response = client.get("/engine/local-llm")
    assert local_llm_response.status_code == 200
    assert "enabled" in local_llm_response.json()

    narrative_world_response = client.get("/engine/narrative/world")
    assert narrative_world_response.status_code == 200
    assert narrative_world_response.json()["world_id"].startswith("world-")
    assert narrative_world_response.json()["entities"]

    narrative_session_response = client.get("/engine/narrative/session/s1")
    assert narrative_session_response.status_code == 200
    assert narrative_session_response.json()["session_id"] == "s1"
    assert "coherence_score" in narrative_session_response.json()
    assert "narrative" in narrative_session_response.json()

    doctor_response = client.get("/doctor")
    assert doctor_response.status_code == 200
    assert "checks" in doctor_response.json()
    assert any(item["name"] == "template_validation" for item in doctor_response.json()["checks"])

    alerts_test_response = client.post("/alerts/test", json={"summary": "unit synthetic alert"})
    assert alerts_test_response.status_code == 200
    assert "result" in alerts_test_response.json()

    alerts_routes_response = client.get("/alerts/routes?severity=high&service=ssh&action=command")
    assert alerts_routes_response.status_code == 200
    assert "routes" in alerts_routes_response.json()
    assert alerts_routes_response.json()["severity"] == "high"


def test_dashboard_api_campaign_routes_support_upsert_list_and_delete() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    campaign_id = f"campaign-edge-{uuid4().hex[:8]}"

    upsert_response = client.put(
        f"/campaigns/{campaign_id}",
        json={
            "name": "Campaign Edge 1",
            "status": "draft",
            "nodes": [
                {"node_id": "host-1", "node_type": "host", "label": "Host 1"},
                {"node_id": "svc-ssh", "node_type": "service", "label": "SSH"},
            ],
            "edges": [
                {"source": "host-1", "target": "svc-ssh", "relation": "exposes"},
            ],
            "metadata": {"owner": "soc"},
        },
    )
    assert upsert_response.status_code == 200
    upsert_payload = upsert_response.json()
    assert upsert_payload["saved"] is True
    assert upsert_payload["campaign"]["campaign_id"] == campaign_id
    assert upsert_payload["campaign"]["status"] == "draft"
    assert upsert_payload["campaign"]["version"] == 1
    assert upsert_payload["campaign"]["metadata"]["owner"] == "soc"

    detail_response = client.get(f"/campaigns/{campaign_id}")
    assert detail_response.status_code == 200
    assert detail_response.json()["campaign"]["campaign_id"] == campaign_id
    assert detail_response.json()["campaign"]["name"] == "Campaign Edge 1"
    assert detail_response.json()["campaign"]["version"] == 1

    second_campaign_id = f"campaign-edge-{uuid4().hex[:8]}"
    second_upsert = client.put(
        f"/campaigns/{second_campaign_id}",
        json={
            "name": "Campaign Edge 2",
            "status": "active",
            "nodes": [{"node_id": "host-2", "node_type": "host", "label": "Host 2"}],
            "edges": [],
            "metadata": {"owner": "ops"},
        },
    )
    assert second_upsert.status_code == 200
    assert second_upsert.json()["campaign"]["campaign_id"] == second_campaign_id

    list_response = client.get("/campaigns?status=draft")
    assert list_response.status_code == 200
    list_payload = list_response.json()
    assert list_payload["count"] >= 1
    draft_campaign_ids = {str(item.get("campaign_id", "")) for item in list_payload["campaigns"]}
    assert campaign_id in draft_campaign_ids
    draft_target = next(
        item
        for item in list_payload["campaigns"]
        if str(item.get("campaign_id", "")) == campaign_id
    )
    assert int(draft_target.get("version", 0) or 0) == 1

    status_response = client.post(
        f"/campaigns/{campaign_id}/status",
        json={"status": "active", "metadata": {"approved_by": "unit-test"}},
    )
    assert status_response.status_code == 200
    status_payload = status_response.json()
    assert status_payload["updated"] is True
    assert status_payload["changed"] is True
    assert status_payload["campaign"]["status"] == "active"
    assert status_payload["campaign"]["version"] == 2
    assert status_payload["campaign"]["metadata"]["approved_by"] == "unit-test"

    prefix_filtered = client.get(f"/campaigns?campaign_id_prefix={campaign_id[:8]}")
    assert prefix_filtered.status_code == 200
    prefix_ids = {str(item.get("campaign_id", "")) for item in prefix_filtered.json()["campaigns"]}
    assert campaign_id in prefix_ids

    name_filtered = client.get("/campaigns?name_prefix=Campaign Edge 2")
    assert name_filtered.status_code == 200
    assert name_filtered.json()["count"] >= 1
    name_ids = {str(item.get("campaign_id", "")) for item in name_filtered.json()["campaigns"]}
    assert second_campaign_id in name_ids

    graph_filtered = client.get("/campaigns?min_nodes=2&min_edges=1")
    assert graph_filtered.status_code == 200
    assert graph_filtered.json()["count"] >= 1
    graph_ids = {str(item.get("campaign_id", "")) for item in graph_filtered.json()["campaigns"]}
    assert campaign_id in graph_ids
    assert second_campaign_id not in graph_ids
    for item in graph_filtered.json()["campaigns"]:
        assert len(item.get("nodes", [])) >= 2
        assert len(item.get("edges", [])) >= 1

    query_filtered = client.get("/campaigns?query=unit-test")
    assert query_filtered.status_code == 200
    assert query_filtered.json()["count"] >= 1
    query_ids = {str(item.get("campaign_id", "")) for item in query_filtered.json()["campaigns"]}
    assert campaign_id in query_ids

    sorted_response = client.get("/campaigns?sort_by=node_count&sort_order=desc")
    assert sorted_response.status_code == 200
    assert sorted_response.json()["count"] >= 2
    top = sorted_response.json()["campaigns"][0]
    bottom = sorted_response.json()["campaigns"][1]
    assert len(top.get("nodes", [])) >= len(bottom.get("nodes", []))

    compact_response = client.get(f"/campaigns?compact=true&campaign_id_prefix={campaign_id[:8]}")
    assert compact_response.status_code == 200
    assert compact_response.json()["count"] >= 1
    compact_item = next(
        item
        for item in compact_response.json()["campaigns"]
        if str(item.get("campaign_id", "")) == campaign_id
    )
    assert "nodes" not in compact_item
    assert "edges" not in compact_item
    assert compact_item["node_count"] == 2
    assert compact_item["edge_count"] == 1

    inventory_export_json = client.get(f"/campaigns/export?campaign_id_prefix={campaign_id}")
    assert inventory_export_json.status_code == 200
    inventory_export_payload = inventory_export_json.json()
    assert inventory_export_payload["count"] >= 1
    inventory_export_ids = {str(item.get("campaign_id", "")) for item in inventory_export_payload["campaigns"]}
    assert campaign_id in inventory_export_ids

    inventory_export_csv = client.get(f"/campaigns/export?format=csv&campaign_id_prefix={second_campaign_id}")
    assert inventory_export_csv.status_code == 200
    assert "text/csv" in inventory_export_csv.headers.get("content-type", "").lower()
    inventory_csv_text = inventory_export_csv.text
    assert "campaign_id,name,status,version" in inventory_csv_text
    assert second_campaign_id in inventory_csv_text

    inventory_export_logfmt = client.get(f"/campaigns/export?format=logfmt&campaign_id_prefix={campaign_id}")
    assert inventory_export_logfmt.status_code == 200
    assert "text/plain" in inventory_export_logfmt.headers.get("content-type", "").lower()
    assert "campaign_id=" in inventory_export_logfmt.text

    versions_response = client.get(f"/campaigns/{campaign_id}/versions")
    assert versions_response.status_code == 200
    versions_payload = versions_response.json()
    assert versions_payload["found"] is True
    assert versions_payload["count"] == 2
    assert versions_payload["versions"][0]["version"] == 2
    assert versions_payload["versions"][0]["event_type"] == "status_change"
    assert versions_payload["versions"][1]["version"] == 1
    assert versions_payload["versions"][1]["event_type"] == "upsert"

    filtered_versions = client.get(f"/campaigns/{campaign_id}/versions?event_type=status_change")
    assert filtered_versions.status_code == 200
    assert filtered_versions.json()["count"] == 1
    assert filtered_versions.json()["versions"][0]["event_type"] == "status_change"

    ranged_versions = client.get(f"/campaigns/{campaign_id}/versions?min_version=2&max_version=2")
    assert ranged_versions.status_code == 200
    assert ranged_versions.json()["count"] == 1
    assert ranged_versions.json()["versions"][0]["version"] == 2

    queried_versions = client.get(f"/campaigns/{campaign_id}/versions?query=unit-test")
    assert queried_versions.status_code == 200
    queried_versions_payload = queried_versions.json()
    assert queried_versions_payload["count"] >= 1
    queried_version_ids = {int(item.get("version", 0) or 0) for item in queried_versions_payload["versions"]}
    assert 2 in queried_version_ids

    sorted_versions = client.get(f"/campaigns/{campaign_id}/versions?sort_order=asc")
    assert sorted_versions.status_code == 200
    assert sorted_versions.json()["versions"][0]["version"] == 1

    compact_versions = client.get(f"/campaigns/{campaign_id}/versions?compact=true")
    assert compact_versions.status_code == 200
    compact_versions_payload = compact_versions.json()
    assert compact_versions_payload["count"] == 2
    compact_version_row = compact_versions_payload["versions"][0]
    assert "nodes" not in compact_version_row
    assert "edges" not in compact_version_row
    assert "node_count" in compact_version_row
    assert "edge_count" in compact_version_row

    versions_export_json = client.get(f"/campaigns/{campaign_id}/versions/export?event_type=status_change")
    assert versions_export_json.status_code == 200
    versions_export_json_payload = versions_export_json.json()
    assert versions_export_json_payload["count"] == 1
    assert versions_export_json_payload["versions"][0]["event_type"] == "status_change"

    versions_export_csv = client.get(
        f"/campaigns/{campaign_id}/versions/export?format=csv&event_type=status_change"
    )
    assert versions_export_csv.status_code == 200
    assert "text/csv" in versions_export_csv.headers.get("content-type", "").lower()
    csv_text = versions_export_csv.text
    assert "campaign_id,version,status,event_type" in csv_text
    assert "status_change" in csv_text
    assert "upsert" not in csv_text

    versions_export_jsonl = client.get(
        f"/campaigns/{campaign_id}/versions/export?format=jsonl&event_type=status_change"
    )
    assert versions_export_jsonl.status_code == 200
    assert "application/x-ndjson" in versions_export_jsonl.headers.get("content-type", "").lower()
    jsonl_lines = [line for line in versions_export_jsonl.text.splitlines() if line.strip()]
    assert len(jsonl_lines) == 1
    assert '"event_type":"status_change"' in jsonl_lines[0]

    versions_export_logfmt = client.get(
        f"/campaigns/{campaign_id}/versions/export?format=logfmt&event_type=status_change"
    )
    assert versions_export_logfmt.status_code == 200
    assert "text/plain" in versions_export_logfmt.headers.get("content-type", "").lower()
    assert "event_type=" in versions_export_logfmt.text

    export_response = client.get(f"/campaigns/{campaign_id}/export?include_versions=true")
    assert export_response.status_code == 200
    export_payload = export_response.json()
    assert export_payload["schema"] == "clownpeanuts.campaign_graph.v1"
    assert export_payload["campaign"]["campaign_id"] == campaign_id
    assert export_payload["campaign"]["version"] == 2
    assert export_payload["version_count"] == 2
    assert len(export_payload["versions"]) == 2

    filtered_export_response = client.get(
        f"/campaigns/{campaign_id}/export?include_versions=true&version_event_type=status_change&version_compact=true"
    )
    assert filtered_export_response.status_code == 200
    filtered_export_payload = filtered_export_response.json()
    assert filtered_export_payload["version_count"] == 1
    assert filtered_export_payload["versions"][0]["event_type"] == "status_change"
    assert "nodes" not in filtered_export_payload["versions"][0]
    assert "edges" not in filtered_export_payload["versions"][0]

    bad_filtered_export = client.get(
        f"/campaigns/{campaign_id}/export?include_versions=true&version_sort_by=invalid"
    )
    assert bad_filtered_export.status_code == 400

    bad_inventory_export = client.get("/campaigns/export?format=invalid")
    assert bad_inventory_export.status_code == 400

    bad_versions_export = client.get(f"/campaigns/{campaign_id}/versions/export?format=invalid")
    assert bad_versions_export.status_code == 400

    delete_response = client.delete(f"/campaigns/{campaign_id}")
    assert delete_response.status_code == 200
    assert delete_response.json()["deleted"] is True
    second_delete_response = client.delete(f"/campaigns/{second_campaign_id}")
    assert second_delete_response.status_code == 200
    assert second_delete_response.json()["deleted"] is True

    missing_response = client.get(f"/campaigns/{campaign_id}")
    assert missing_response.status_code == 404


def test_dashboard_api_campaign_routes_validate_payload_shape() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    invalid_id_response = client.get("/campaigns/not valid")
    assert invalid_id_response.status_code == 400

    invalid_status_response = client.get("/campaigns?status=unknown")
    assert invalid_status_response.status_code == 400

    invalid_sort_response = client.get("/campaigns?sort_by=invalid")
    assert invalid_sort_response.status_code == 400

    invalid_sort_order_response = client.get("/campaigns?sort_order=sideways")
    assert invalid_sort_order_response.status_code == 400

    invalid_inventory_status_response = client.get("/campaigns/export?status=unknown")
    assert invalid_inventory_status_response.status_code == 400

    invalid_version_sort_response = client.get("/campaigns/campaign-edge-2/versions?sort_by=invalid")
    assert invalid_version_sort_response.status_code == 400

    invalid_version_range_response = client.get("/campaigns/campaign-edge-2/versions?min_version=2&max_version=1")
    assert invalid_version_range_response.status_code == 400

    invalid_status_transition_response = client.post(
        "/campaigns/campaign-edge-2/status",
        json={"status": "unknown"},
    )
    assert invalid_status_transition_response.status_code == 400

    invalid_node_response = client.put(
        "/campaigns/campaign-edge-2",
        json={
            "name": "Campaign Edge 2",
            "nodes": [{"node_id": "", "node_type": "host"}],
            "edges": [],
        },
    )
    assert invalid_node_response.status_code == 400

    invalid_edge_response = client.put(
        "/campaigns/campaign-edge-2",
        json={
            "name": "Campaign Edge 2",
            "nodes": [{"node_id": "host-1", "node_type": "host"}],
            "edges": [{"source": "host-1", "target": "missing-node", "relation": "exposes"}],
        },
    )
    assert invalid_edge_response.status_code == 400

    invalid_import_schema_response = client.post(
        "/campaigns/import",
        json={
            "schema": "unsupported.schema",
            "campaign": {"campaign_id": "campaign-edge-import", "name": "Import Edge", "nodes": [], "edges": []},
        },
    )
    assert invalid_import_schema_response.status_code == 400

    invalid_import_payload_response = client.post(
        "/campaigns/import",
        json={"schema": "clownpeanuts.campaign_graph.v1", "campaign": "not-an-object"},
    )
    assert invalid_import_payload_response.status_code == 400

    valid_import_response = client.post(
        "/campaigns/import",
        json={
            "schema": "clownpeanuts.campaign_graph.v1",
            "campaign_id": "campaign-edge-import",
            "campaign": {
                "name": "Import Edge",
                "status": "draft",
                "nodes": [{"node_id": "host-1", "node_type": "host"}],
                "edges": [],
            },
        },
    )
    assert valid_import_response.status_code == 200
    valid_import_payload = valid_import_response.json()
    assert valid_import_payload["imported"] is True
    assert valid_import_payload["campaign_id"] == "campaign-edge-import"
    assert valid_import_payload["campaign"]["campaign_id"] == "campaign-edge-import"
    assert valid_import_payload["campaign"]["metadata"]["imported"] is True

    missing_versions_response = client.get("/campaigns/missing/versions")
    assert missing_versions_response.status_code == 404
    missing_versions_export_response = client.get("/campaigns/missing/versions/export")
    assert missing_versions_export_response.status_code == 404
    missing_export_response = client.get("/campaigns/missing/export")
    assert missing_export_response.status_code == 404

    missing_delete_response = client.delete("/campaigns/campaign-edge-2")
    assert missing_delete_response.status_code == 404


def test_dashboard_api_campaign_routes_use_short_ttl_caching(monkeypatch: pytest.MonkeyPatch) -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    campaign_id = f"campaign-cache-{uuid4().hex[:8]}"
    upsert = client.put(
        f"/campaigns/{campaign_id}",
        json={
            "name": "Campaign Cache",
            "status": "draft",
            "nodes": [{"node_id": "cache-node", "node_type": "host"}],
            "edges": [],
        },
    )
    assert upsert.status_code == 200

    list_call_count = {"value": 0}
    versions_call_count = {"value": 0}
    original_campaign_graphs = orchestrator.campaign_graphs
    original_campaign_versions = orchestrator.campaign_versions

    def _wrapped_campaign_graphs(**kwargs: Any) -> dict[str, Any]:
        list_call_count["value"] += 1
        return original_campaign_graphs(**kwargs)

    def _wrapped_campaign_versions(**kwargs: Any) -> dict[str, Any]:
        versions_call_count["value"] += 1
        return original_campaign_versions(**kwargs)

    monkeypatch.setattr(orchestrator, "campaign_graphs", _wrapped_campaign_graphs)
    monkeypatch.setattr(orchestrator, "campaign_versions", _wrapped_campaign_versions)

    first_list = client.get("/campaigns?status=draft")
    second_list = client.get("/campaigns?status=draft")
    assert first_list.status_code == 200
    assert second_list.status_code == 200
    assert list_call_count["value"] == 1

    first_versions = client.get(f"/campaigns/{campaign_id}/versions")
    second_versions = client.get(f"/campaigns/{campaign_id}/versions")
    assert first_versions.status_code == 200
    assert second_versions.status_code == 200
    assert versions_call_count["value"] == 1

    cached_export = client.get(f"/campaigns/{campaign_id}/export?include_versions=true")
    assert cached_export.status_code == 200
    assert versions_call_count["value"] == 1


def test_dashboard_api_canary_hit_validation_and_taxii_not_found() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    config = parse_config({"services": []})
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    canary_hit_response = client.post(
        "/intel/canary/hit",
        json={"token": "", "source_ip": "203.0.113.88"},
    )
    assert canary_hit_response.status_code == 400

    canary_generate_invalid_response = client.post(
        "/intel/canary/generate",
        json={"namespace": "evil.attacker.com", "token_type": "dns"},
    )
    assert canary_generate_invalid_response.status_code == 400

    alerts_test_invalid_response = client.post("/alerts/test", json={"severity": "invalid"})
    assert alerts_test_invalid_response.status_code == 400

    alerts_routes_invalid_response = client.get("/alerts/routes?severity=invalid")
    assert alerts_routes_invalid_response.status_code == 400

    taxii_objects_response = client.get("/intel/taxii/collections/unknown/objects")
    assert taxii_objects_response.status_code == 404

    taxii_manifest_response = client.get("/intel/taxii/collections/unknown/manifest")
    assert taxii_manifest_response.status_code == 404

    taxii_object_response = client.get("/intel/taxii/collections/clownpeanuts-intel/objects/indicator--missing")
    assert taxii_object_response.status_code == 404

    taxii2_collection_response = client.get("/taxii2/api/collections/unknown")
    assert taxii2_collection_response.status_code == 404

    taxii2_objects_response = client.get("/taxii2/api/collections/unknown/objects")
    assert taxii2_objects_response.status_code == 404

    taxii2_manifest_response = client.get("/taxii2/api/collections/unknown/manifest")
    assert taxii2_manifest_response.status_code == 404

    taxii2_manifest_bad_added_after_response = client.get(
        "/taxii2/api/collections/clownpeanuts-intel/manifest?added_after=not-a-timestamp"
    )
    assert taxii2_manifest_bad_added_after_response.status_code == 400

    taxii2_objects_bad_next_response = client.get("/taxii2/api/collections/clownpeanuts-intel/objects?next=nope")
    assert taxii2_objects_bad_next_response.status_code == 400

    taxii_history_missing_report_response = client.get("/intel/taxii/collections/clownpeanuts-intel/objects?report_id=999999")
    assert taxii_history_missing_report_response.status_code == 404

    history_report_response = client.get("/intel/history/999999")
    assert history_report_response.status_code == 404

    stix_history_response = client.get("/intel/stix/history/999999")
    assert stix_history_response.status_code == 404

    navigator_history_response = client.get("/intel/attack-navigator/history/999999")
    assert navigator_history_response.status_code == 404

    canary_token_detail_response = client.get("/intel/canary/tokens/missing-token")
    assert canary_token_detail_response.status_code == 404

    narrative_session_missing_response = client.get("/engine/narrative/session/missing-session")
    assert narrative_session_missing_response.status_code == 404

    theater_session_missing_response = client.get("/theater/sessions/missing-session")
    assert theater_session_missing_response.status_code == 404

    theater_session_bundle_missing_response = client.get("/theater/sessions/missing-session/bundle")
    assert theater_session_bundle_missing_response.status_code == 404

    replay_compare_missing_response = client.get(
        "/sessions/replay/compare?left_session_id=s1&right_session_id=missing-session"
    )
    assert replay_compare_missing_response.status_code == 404

    theater_apply_missing_session_response = client.post(
        "/theater/actions/apply-lure",
        json={"lure_arm": "ssh-credential-bait"},
    )
    assert theater_apply_missing_session_response.status_code == 400

    theater_apply_invalid_duration_response = client.post(
        "/theater/actions/apply-lure",
        json={"session_id": "s1", "lure_arm": "ssh-credential-bait", "duration_seconds": 0},
    )
    assert theater_apply_invalid_duration_response.status_code == 400

    theater_label_missing_label_response = client.post(
        "/theater/actions/label",
        json={"session_id": "s1"},
    )
    assert theater_label_missing_label_response.status_code == 400

    theater_label_bad_confidence_response = client.post(
        "/theater/actions/label",
        json={"session_id": "s1", "label": "tagged", "confidence": 5},
    )
    assert theater_label_bad_confidence_response.status_code == 400

    bandit_override_missing_arm_response = client.post("/intel/bandit/override", json={"context_key": "ssh:recon"})
    assert bandit_override_missing_arm_response.status_code == 400

    bandit_override_bad_duration_response = client.post(
        "/intel/bandit/override",
        json={"context_key": "ssh:recon", "arm": "arm-a", "duration_seconds": 0},
    )
    assert bandit_override_bad_duration_response.status_code == 400


def test_dashboard_api_templates_validate_surfaces_lint_errors(tmp_path) -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    template_path = tmp_path / "template-invalid.yml"
    template_path.write_text(
        "templates:\n"
        "  - service: ssh\n"
        "    ports: [\"not-a-port\"]\n",
        encoding="utf-8",
    )
    config = parse_config(
        {
            "templates": {"enabled": True, "paths": [str(template_path)]},
            "services": [{"name": "ssh", "module": "clownpeanuts.services.ssh.emulator", "ports": [2222], "config": {}}],
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    response = client.get("/templates/validate")
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is False
    assert payload["error_count"] >= 1
