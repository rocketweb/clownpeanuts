import asyncio
import json
from pathlib import Path
import socket
import sys

from clownpeanuts.config.schema import EngineConfig, NarrativeConfig, parse_config
from clownpeanuts.core.orchestrator import Orchestrator
from clownpeanuts.core.logging import EventLogger, get_logger
from clownpeanuts.core.session import SessionManager
from clownpeanuts.engine.rabbit_hole import RabbitHoleEngine
from clownpeanuts.services.base import ServiceRuntime
from clownpeanuts.services.http.emulator import Emulator as HttpEmulator
from clownpeanuts.services.ssh.emulator import Emulator as SshEmulator


def _runtime_with_narrative() -> ServiceRuntime:
    session_manager = SessionManager()
    event_logger = EventLogger(logger=get_logger("clownpeanuts.test.narrative"), service_name="test")
    rabbit_hole = RabbitHoleEngine(
        EngineConfig(),
        narrative_config=NarrativeConfig(enabled=True, world_seed="consistency-seed", entity_count=96, per_tenant_worlds=True),
    )
    return ServiceRuntime(session_manager=session_manager, event_logger=event_logger, event_bus=None, rabbit_hole=rabbit_hole)


def _orchestrator_for_cp903() -> Orchestrator:
    config = parse_config(
        {
            "narrative": {
                "enabled": True,
                "world_seed": "cp903-seed",
                "entity_count": 80,
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
                "max_live_sessions": 25,
                "recommendation_cooldown_seconds": 0.0,
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()
    return orchestrator


def test_narrative_context_stays_coherent_across_ssh_http_and_db_views() -> None:
    runtime = _runtime_with_narrative()
    session_id = "cross-protocol-1"
    source_ip = "198.51.100.77"

    ssh = SshEmulator()
    ssh.set_runtime(runtime)
    http = HttpEmulator()
    http.set_runtime(runtime)

    ssh_result = asyncio.run(
        ssh.handle_connection(
            {
                "session_id": session_id,
                "source_ip": source_ip,
                "source_port": 61222,
                "username": "root",
                "password": "toor",
                "attempts": [("root", "guess"), ("root", "toor")],
                "commands": ["hostname", "cat notes.txt"],
            }
        )
    )
    assert ssh_result["accepted"] is True

    http_result = asyncio.run(
        http.handle_connection(
            {
                "session_id": session_id,
                "source_ip": source_ip,
                "source_port": 61808,
                "method": "GET",
                "path": "/internal/api/orders",
            }
        )
    )
    assert http_result["status"] == 200

    ssh_context = runtime.rabbit_hole.resolve_narrative_context(
        session_id=session_id,
        source_ip=source_ip,
        tenant_id="default",
        service="ssh",
        action="command",
        hints={"command": "hostname"},
    )
    http_context = runtime.rabbit_hole.resolve_narrative_context(
        session_id=session_id,
        source_ip=source_ip,
        tenant_id="default",
        service="http_admin",
        action="get_/internal/api/orders",
        hints={"route": "/internal/api/orders"},
    )
    db_context = runtime.rabbit_hole.resolve_narrative_context(
        session_id=session_id,
        source_ip=source_ip,
        tenant_id="default",
        service="mysql_db",
        action="query",
        hints={"query": "show databases"},
    )

    assert ssh_context["context_id"] == http_context["context_id"] == db_context["context_id"]
    assert ssh_context["world_id"] == http_context["world_id"] == db_context["world_id"]
    assert ssh_context["focus"]["service"]["entity_id"] == http_context["focus"]["service"]["entity_id"]
    assert http_context["focus"]["service"]["entity_id"] == db_context["focus"]["service"]["entity_id"]
    assert ssh_context["focus"]["dataset"]["entity_id"] == db_context["focus"]["dataset"]["entity_id"]

    session_view = runtime.rabbit_hole.narrative.session_view(session_id)
    assert session_view is not None
    assert "ssh" in session_view["touched_services"]
    assert "http_admin" in session_view["touched_services"]
    assert "mysql_db" in session_view["touched_services"]


def test_narrative_outputs_do_not_leak_local_hostname_or_runtime_process_name() -> None:
    runtime = _runtime_with_narrative()
    session_id = "cross-protocol-2"
    source_ip = "198.51.100.88"
    local_hostname = socket.gethostname().strip().lower()
    runtime_process = Path(sys.executable).name.strip().lower()

    ssh = SshEmulator()
    ssh.set_runtime(runtime)
    http = HttpEmulator()
    http.set_runtime(runtime)

    ssh_result = asyncio.run(
        ssh.handle_connection(
            {
                "session_id": session_id,
                "source_ip": source_ip,
                "source_port": 61333,
                "username": "root",
                "password": "toor",
                "attempts": [("root", "guess"), ("root", "toor")],
                "commands": ["hostname", "uname -a", "cat notes.txt"],
            }
        )
    )
    http_result = asyncio.run(
        http.handle_connection(
            {
                "session_id": session_id,
                "source_ip": source_ip,
                "source_port": 62808,
                "method": "GET",
                "path": "/internal/api/orders",
            }
        )
    )
    db_result = runtime.rabbit_hole.respond_database_command(
        service="mysql_db",
        session_id=session_id,
        source_ip=source_ip,
        command="select",
        document={},
        tenant_id="default",
    )

    combined = "\n".join(
        [
            ssh_result["commands"][0]["output"],
            ssh_result["commands"][1]["output"],
            ssh_result["commands"][2]["output"],
            str(http_result["body"]),
            json.dumps(db_result, separators=(",", ":"), ensure_ascii=True),
        ]
    ).lower()

    assert local_hostname not in combined
    assert runtime_process not in combined


def test_end_to_end_workflow_keeps_narrative_bandit_and_theater_in_sync() -> None:
    orchestrator = _orchestrator_for_cp903()
    session_id = "cp903-sync-1"
    source_ip = "198.51.100.121"

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

    ssh_context = orchestrator.rabbit_hole.resolve_narrative_context(
        session_id=session_id,
        source_ip=source_ip,
        tenant_id="default",
        service="ssh",
        action="command",
        hints={"command": "hostname"},
    )
    http_context = orchestrator.rabbit_hole.resolve_narrative_context(
        session_id=session_id,
        source_ip=source_ip,
        tenant_id="default",
        service="http_admin",
        action="get_/internal/api/orders",
        hints={"route": "/internal/api/orders"},
    )
    db_context = orchestrator.rabbit_hole.resolve_narrative_context(
        session_id=session_id,
        source_ip=source_ip,
        tenant_id="default",
        service="mysql_db",
        action="query",
        hints={"query": "show databases"},
    )
    repeat_context = orchestrator.rabbit_hole.resolve_narrative_context(
        session_id=session_id,
        source_ip=source_ip,
        tenant_id="default",
        service="ssh",
        action="command",
        hints={"command": "hostname"},
    )

    assert ssh_context["context_id"] == http_context["context_id"] == db_context["context_id"]
    assert ssh_context["world_id"] == http_context["world_id"] == db_context["world_id"]
    assert repeat_context["context_id"] == ssh_context["context_id"]
    assert repeat_context["world_id"] == ssh_context["world_id"]

    ssh_decision = orchestrator.bandit_select(
        context_key="ssh:generic",
        candidates=["ssh-baseline", "ssh-credential-bait", "ssh-lateral-bait"],
    )
    http_decision = orchestrator.bandit_select(
        context_key="http:api:get",
        candidates=["http-baseline", "http-query-bait", "http-backup-bait"],
    )
    db_decision = orchestrator.bandit_select(
        context_key="mysql:query",
        candidates=["mysql-baseline", "mysql-query-bait", "mysql-credential-bait"],
    )

    assert ssh_decision["recorded"] is True
    assert http_decision["recorded"] is True
    assert db_decision["recorded"] is True
    assert str(ssh_decision["selected_arm"]).startswith("ssh-")
    assert str(http_decision["selected_arm"]).startswith("http-")
    assert str(db_decision["selected_arm"]).startswith("mysql-")
    assert int(db_decision["total_selections"]) >= 3

    theater_session = orchestrator.theater_session(session_id=session_id, events_limit=200)
    assert theater_session is not None
    assert theater_session["session_id"] == session_id
    assert theater_session["narrative"]["context_id"] == ssh_context["context_id"]
    assert theater_session["narrative"]["world_id"] == ssh_context["world_id"]
    assert {"ssh", "http_admin", "mysql_db"} <= set(theater_session["narrative"]["touched_services"])
    assert 0.0 <= float(theater_session["recommendation"]["confidence"]) <= 1.0
    assert "explanation" in theater_session["recommendation"]

    recommendation_queue = orchestrator.theater_recommendations(
        limit=5,
        session_limit=10,
        events_per_session=200,
    )
    assert recommendation_queue["count"] >= 1
    assert recommendation_queue["recommendations"][0]["session_id"] == session_id
