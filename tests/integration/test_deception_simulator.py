import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from clownpeanuts.cli import main
from clownpeanuts.config.schema import BanditRewardWeightsConfig, parse_config
from clownpeanuts.core.orchestrator import Orchestrator
from clownpeanuts.intel.simulator import SimulationPolicy, simulate_bandit_counterfactual
from clownpeanuts.intel.store import IntelligenceStore


def _session(
    *,
    session_id: str,
    created_at: datetime,
    services: list[str],
    kill_chain: list[str],
    duration_seconds: float,
    alert_score: float,
    fingerprints: list[str],
    bandit_reward: float,
) -> dict[str, object]:
    return {
        "session_id": session_id,
        "source_ip": "198.51.100.20",
        "created_at": created_at.isoformat(timespec="seconds"),
        "event_count": 5,
        "classification": {"label": "Automated Scanner"},
        "engagement_score": {"score": alert_score},
        "timing": {"duration_seconds": duration_seconds},
        "kill_chain": kill_chain,
        "tool_fingerprints": fingerprints,
        "coherence_signals": {"observed_services": services},
        "coherence_score": 0.9,
        "coherence_violations": [],
        "bandit_reward": bandit_reward,
    }


def test_simulate_bandit_counterfactual_summarizes_baseline_and_candidate() -> None:
    now = datetime(2026, 2, 1, 12, 0, tzinfo=UTC)
    sessions = [
        _session(
            session_id="sim-a",
            created_at=now - timedelta(hours=1),
            services=["ssh"],
            kill_chain=["initial_access", "credential_access"],
            duration_seconds=240.0,
            alert_score=54.0,
            fingerprints=["hydra"],
            bandit_reward=0.42,
        ),
        _session(
            session_id="sim-b",
            created_at=now - timedelta(minutes=30),
            services=["http_admin", "mysql_db"],
            kill_chain=["initial_access", "discovery", "lateral_movement"],
            duration_seconds=620.0,
            alert_score=77.0,
            fingerprints=["sqlmap", "curl"],
            bandit_reward=0.66,
        ),
    ]
    report_rows = [
        {
            "report_id": 1,
            "created_at": (now - timedelta(minutes=20)).isoformat(timespec="seconds"),
            "report": {"sessions": sessions},
        }
    ]

    result = simulate_bandit_counterfactual(
        report_rows=report_rows,
        window_hours=24.0,
        baseline_policy=SimulationPolicy(name="baseline", algorithm="thompson", exploration_floor=0.1),
        candidate_policy=SimulationPolicy(name="candidate", algorithm="ucb", exploration_floor=0.2),
        reward_weights=BanditRewardWeightsConfig(),
        now_utc=now,
    )

    assert result["session_count"] == 2
    assert result["baseline"]["policy"]["algorithm"] == "thompson"
    assert result["candidate"]["policy"]["algorithm"] == "ucb"
    assert result["baseline"]["selection_count"] == 2
    assert result["candidate"]["selection_count"] == 2
    assert "reward_total" in result["delta"]
    assert "reward_avg_percent" in result["delta"]


def test_simulate_bandit_counterfactual_filters_old_sessions_outside_window() -> None:
    now = datetime(2026, 2, 1, 12, 0, tzinfo=UTC)
    report_rows = [
        {
            "report_id": 1,
            "created_at": (now - timedelta(hours=40)).isoformat(timespec="seconds"),
            "report": {
                "sessions": [
                    _session(
                        session_id="old-sim",
                        created_at=now - timedelta(hours=40),
                        services=["ssh"],
                        kill_chain=["initial_access"],
                        duration_seconds=120.0,
                        alert_score=35.0,
                        fingerprints=[],
                        bandit_reward=0.2,
                    )
                ]
            },
        },
        {
            "report_id": 2,
            "created_at": (now - timedelta(hours=1)).isoformat(timespec="seconds"),
            "report": {
                "sessions": [
                    _session(
                        session_id="new-sim",
                        created_at=now - timedelta(minutes=20),
                        services=["http_admin"],
                        kill_chain=["initial_access", "discovery"],
                        duration_seconds=300.0,
                        alert_score=60.0,
                        fingerprints=["curl"],
                        bandit_reward=0.55,
                    )
                ]
            },
        },
    ]

    result = simulate_bandit_counterfactual(
        report_rows=report_rows,
        window_hours=24.0,
        baseline_policy=SimulationPolicy(name="baseline", algorithm="thompson", exploration_floor=0.1),
        candidate_policy=SimulationPolicy(name="candidate", algorithm="ucb", exploration_floor=0.1),
        reward_weights=BanditRewardWeightsConfig(),
        now_utc=now,
    )

    assert result["session_count"] == 1
    assert result["baseline"]["session_count"] == 1
    assert result["candidate"]["session_count"] == 1


def test_simulator_is_deterministic_for_orchestrator_generated_workflow(tmp_path: Path) -> None:
    db_path = tmp_path / "cp903-sim.sqlite3"
    original_db = os.environ.get("CLOWNPEANUTS_INTEL_DB")
    os.environ["CLOWNPEANUTS_INTEL_DB"] = str(db_path)
    try:
        config = parse_config(
            {
                "narrative": {
                    "enabled": True,
                    "world_seed": "cp903-sim",
                    "entity_count": 72,
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
                "theater": {"enabled": True, "rollout_mode": "recommend-only"},
                "services": [],
            }
        )
        orchestrator = Orchestrator(config)
        orchestrator.bootstrap()

        session_id = "cp903-sim-1"
        source_ip = "198.51.100.177"
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
            reward=0.73,
            signals={"dwell_time": 0.8, "cross_protocol_pivot": 1.0, "technique_novelty": 0.6},
            metadata={"source": "cp903"},
        )
        assert reward is not None
        assert reward["decision_id"] == decision_id

        report = orchestrator.intelligence_report(limit=10, events_per_session=200)
        assert int(report.get("totals", {}).get("sessions", 0)) == 1
        rows = orchestrator.intel_store.recent_reports(limit=5)
        assert rows

        simulation_now = datetime.now(UTC)
        baseline = SimulationPolicy(name="baseline", algorithm="thompson", exploration_floor=0.0)
        candidate = SimulationPolicy(name="candidate", algorithm="ucb", exploration_floor=0.0)
        result_a = simulate_bandit_counterfactual(
            report_rows=rows,
            window_hours=24.0,
            baseline_policy=baseline,
            candidate_policy=candidate,
            reward_weights=BanditRewardWeightsConfig(),
            now_utc=simulation_now,
        )
        result_b = simulate_bandit_counterfactual(
            report_rows=rows,
            window_hours=24.0,
            baseline_policy=baseline,
            candidate_policy=candidate,
            reward_weights=BanditRewardWeightsConfig(),
            now_utc=simulation_now,
        )

        assert result_a == result_b
        assert result_a["session_count"] == 1
        assert result_a["baseline"]["selection_count"] == 1
        assert result_a["candidate"]["selection_count"] == 1
        assert "reward_total" in result_a["delta"]
    finally:
        if original_db is None:
            os.environ.pop("CLOWNPEANUTS_INTEL_DB", None)
        else:
            os.environ["CLOWNPEANUTS_INTEL_DB"] = original_db


def test_simulate_bandit_cli_uses_recent_reports_for_counterfactuals(tmp_path: Path, capsys) -> None:
    db_path = tmp_path / "intel.sqlite3"
    original_db = os.environ.get("CLOWNPEANUTS_INTEL_DB")
    os.environ["CLOWNPEANUTS_INTEL_DB"] = str(db_path)

    now = datetime.now(UTC)
    sessions = [
        _session(
            session_id="cli-sim-a",
            created_at=now - timedelta(hours=1),
            services=["ssh"],
            kill_chain=["initial_access", "credential_access"],
            duration_seconds=180.0,
            alert_score=52.0,
            fingerprints=["hydra"],
            bandit_reward=0.35,
        ),
        _session(
            session_id="cli-sim-b",
            created_at=now - timedelta(minutes=40),
            services=["postgres_db", "http_admin"],
            kill_chain=["initial_access", "discovery", "lateral_movement"],
            duration_seconds=480.0,
            alert_score=81.0,
            fingerprints=["nmap", "psql"],
            bandit_reward=0.74,
        ),
    ]

    store = IntelligenceStore(db_path=db_path)
    store.record_report(
        {
            "generated_at": now.isoformat(timespec="seconds"),
            "sessions": sessions,
            "totals": {
                "sessions": len(sessions),
                "events": 10,
                "engagement_score_avg": 66.5,
                "coherence_score_avg": 0.9,
                "bandit_reward_avg": 0.545,
            },
        }
    )

    try:
        rc = main(
            [
                "simulate-bandit",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--window-hours",
                "24",
                "--history-limit",
                "10",
                "--candidate-algorithm",
                "ucb",
            ]
        )
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["session_count"] == 2
        assert payload["baseline"]["policy"]["name"] == "baseline"
        assert payload["candidate"]["policy"]["algorithm"] == "ucb"
        assert payload["history_reports_considered"] >= 1
    finally:
        if original_db is None:
            os.environ.pop("CLOWNPEANUTS_INTEL_DB", None)
        else:
            os.environ["CLOWNPEANUTS_INTEL_DB"] = original_db
