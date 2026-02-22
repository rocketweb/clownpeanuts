from pathlib import Path
import sqlite3

import pytest

from clownpeanuts.intel.canary import token_identifier
from clownpeanuts.intel.store import IntelligenceStore


def test_intelligence_store_persists_report_and_session_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    store = IntelligenceStore(db_path=db_path)
    report = {
        "sessions": [
            {
                "session_id": "s1",
                "source_ip": "203.0.113.10",
                "event_count": 3,
                "classification": {"label": "Script Kiddie"},
                "engagement_score": {"score": 42.0},
                "coherence_score": 0.92,
                "coherence_violations": ["service_missing:mysql_db"],
                "bandit_reward": 0.66,
                "timing": {"duration_seconds": 12.5},
            }
        ],
        "totals": {
            "sessions": 1,
            "events": 3,
            "engagement_score_avg": 42.0,
            "coherence_score_avg": 0.92,
            "bandit_reward_avg": 0.66,
        },
    }

    report_id = store.record_report(report)
    assert report_id is not None

    reports = store.recent_reports(limit=10)
    assert reports
    assert reports[0]["report_id"] == report_id
    assert reports[0]["sessions"] == 1
    assert reports[0]["events"] == 3
    assert reports[0]["coherence_score_avg"] == 0.92
    assert reports[0]["bandit_reward_avg"] == 0.66

    detail = store.get_report(report_id=int(report_id))
    assert detail is not None
    assert detail["report_id"] == report_id
    assert detail["coherence_score_avg"] == 0.92
    assert detail["bandit_reward_avg"] == 0.66

    sessions = store.recent_sessions(limit=10)
    assert sessions
    assert sessions[0]["report_id"] == report_id
    assert sessions[0]["session_id"] == "s1"
    assert sessions[0]["classification_label"] == "Script Kiddie"
    assert sessions[0]["coherence_score"] == 0.92
    assert sessions[0]["coherence_violations"] == ["service_missing:mysql_db"]
    assert sessions[0]["bandit_reward"] == 0.66

    report_sessions = store.report_sessions(report_id=int(report_id), limit=10)
    assert report_sessions
    assert report_sessions[0]["report_id"] == report_id
    assert report_sessions[0]["coherence_score"] == 0.92
    assert report_sessions[0]["bandit_reward"] == 0.66


def test_intelligence_store_uses_wal_mode_and_normal_synchronous(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    store = IntelligenceStore(db_path=db_path)

    report_id = store.record_report({"sessions": [], "totals": {"sessions": 0, "events": 0}})
    assert report_id is not None

    with store._connect() as conn:  # noqa: SLF001 - validate sqlite runtime pragmas for performance profile
        journal_mode = str(conn.execute("PRAGMA journal_mode").fetchone()[0]).strip().lower()
        synchronous = int(conn.execute("PRAGMA synchronous").fetchone()[0])

    assert journal_mode == "wal"
    assert synchronous == 1


def test_intelligence_store_persists_bandit_decisions_and_delayed_rewards(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    store = IntelligenceStore(db_path=db_path)
    decision = store.record_bandit_decision(
        context_key="ssh:recon",
        selected_arm="arm-a",
        algorithm="thompson",
        candidates=["arm-a", "arm-b"],
        exploration_applied=False,
        blocked_arms={"arm-c": "denylist"},
        arm_scores={"arm-a": 0.9, "arm-b": 0.2},
        metadata={"tenant_id": "default"},
        created_at="2026-01-01T00:00:00+00:00",
    )
    assert decision is not None
    decision_id = int(decision["decision_id"])

    reward = store.record_bandit_reward(
        decision_id=decision_id,
        reward=0.85,
        signals={"dwell_time": 0.7, "cross_protocol_pivot": 1.0},
        metadata={"source": "unit"},
        created_at="2026-01-01T00:05:00+00:00",
    )
    assert reward is not None
    assert reward["decision_id"] == decision_id
    assert reward["reward"] == 0.85
    assert reward["delay_seconds"] == 300.0

    rewards = store.recent_bandit_rewards(limit=10, decision_id=decision_id)
    assert rewards
    assert rewards[0]["decision_id"] == decision_id
    assert rewards[0]["signals"]["cross_protocol_pivot"] == 1.0

    missing = store.record_bandit_reward(decision_id=999999, reward=0.5)
    assert missing is None


def test_intelligence_store_persists_canary_tokens_and_hits(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    store = IntelligenceStore(db_path=db_path)
    token = "corp-http-a1b2c3"
    token_id = token_identifier(token=token)

    token_row = store.record_canary_token(
        token_id=token_id,
        token=token,
        token_type="http",
        namespace="corp",
        metadata={"seed": "unit"},
    )
    assert token_row is not None
    assert token_row["token_id"] == token_id
    assert token_row["hit_count"] == 0

    hit_row = store.record_canary_hit(
        token=token,
        source_ip="203.0.113.40",
        service="http_admin",
        session_id="canary-s1",
        tenant_id="default",
        metadata={"channel": "dns"},
    )
    assert hit_row is not None
    assert hit_row["token_id"] == token_id
    assert hit_row["source_ip"] == "203.0.113.40"

    detail = store.canary_token(token_id=token_id)
    assert detail is not None
    assert detail["hit_count"] == 1
    assert detail["last_hit_at"]

    tokens = store.recent_canary_tokens(limit=10)
    assert tokens
    assert tokens[0]["token_id"] == token_id

    filtered_hits = store.recent_canary_hits(limit=10, token_id=token_id)
    assert filtered_hits
    assert filtered_hits[0]["token_id"] == token_id


def test_intelligence_store_persists_theater_actions(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    store = IntelligenceStore(db_path=db_path)

    apply_row = store.record_theater_action(
        action_type="apply-lure",
        session_id="s1",
        actor="analyst-1",
        recommendation_id="rec-001",
        payload={"lure_arm": "ssh-credential-bait", "context_key": "ssh:discovery"},
        metadata={"tenant_id": "default"},
    )
    assert apply_row is not None
    assert apply_row["action_type"] == "apply_lure"
    assert apply_row["session_id"] == "s1"
    assert apply_row["recommendation_id"] == "rec-001"
    assert apply_row["payload"]["lure_arm"] == "ssh-credential-bait"

    label_row = store.record_theater_action(
        action_type="label",
        session_id="s1",
        actor="analyst-1",
        recommendation_id="rec-001",
        payload={"label": "high_value_actor", "confidence": 0.9},
    )
    assert label_row is not None
    assert label_row["action_type"] == "label"

    all_rows = store.recent_theater_actions(limit=10, session_id="s1")
    assert len(all_rows) == 2

    label_rows = store.recent_theater_actions(limit=10, action_type="label")
    assert label_rows
    assert label_rows[0]["action_type"] == "label"


def test_intelligence_store_persists_campaign_graphs(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    store = IntelligenceStore(db_path=db_path)

    campaign = store.upsert_campaign_graph(
        campaign_id="corp-edge-q1",
        name="Corp Edge Q1",
        status="draft",
        nodes=[
            {"node_id": "host-1", "node_type": "host", "label": "Edge Host 1"},
            {"node_id": "svc-ssh", "node_type": "service", "label": "SSH Decoy"},
        ],
        edges=[
            {"source": "host-1", "target": "svc-ssh", "relation": "exposes"},
        ],
        metadata={"tenant_id": "default", "owner": "soc"},
    )
    assert campaign is not None
    assert campaign["campaign_id"] == "corp-edge-q1"
    assert campaign["name"] == "Corp Edge Q1"
    assert campaign["status"] == "draft"
    assert campaign["version"] == 1
    assert len(campaign["nodes"]) == 2
    assert campaign["metadata"]["owner"] == "soc"

    updated = store.upsert_campaign_graph(
        campaign_id="corp-edge-q1",
        name="Corp Edge Q1 Updated",
        status="active",
        nodes=[
            {"node_id": "host-1", "node_type": "host"},
            {"node_id": "svc-ssh", "node_type": "service"},
            {"node_id": "crumb-1", "node_type": "breadcrumb"},
        ],
        edges=[
            {"source": "host-1", "target": "svc-ssh", "relation": "exposes"},
            {"source": "svc-ssh", "target": "crumb-1", "relation": "leads_to"},
        ],
        metadata={"tenant_id": "default", "owner": "ops"},
    )
    assert updated is not None
    assert updated["status"] == "active"
    assert updated["name"] == "Corp Edge Q1 Updated"
    assert updated["version"] == 2
    assert len(updated["nodes"]) == 3
    assert updated["metadata"]["owner"] == "ops"

    transitioned = store.set_campaign_graph_status(
        campaign_id="corp-edge-q1",
        status="paused",
        metadata={"approved_by": "automation"},
    )
    assert transitioned is not None
    assert transitioned["status"] == "paused"
    assert transitioned["version"] == 3
    assert transitioned["metadata"]["approved_by"] == "automation"

    detail = store.campaign_graph(campaign_id="corp-edge-q1")
    assert detail is not None
    assert detail["campaign_id"] == "corp-edge-q1"
    assert detail["status"] == "paused"
    assert detail["version"] == 3
    assert len(detail["edges"]) == 2

    all_rows = store.recent_campaign_graphs(limit=10)
    assert len(all_rows) == 1
    assert all_rows[0]["campaign_id"] == "corp-edge-q1"
    assert all_rows[0]["version"] == 3

    active_rows = store.recent_campaign_graphs(limit=10, status="active")
    assert active_rows == []
    paused_rows = store.recent_campaign_graphs(limit=10, status="paused")
    assert len(paused_rows) == 1
    assert paused_rows[0]["campaign_id"] == "corp-edge-q1"
    assert paused_rows[0]["status"] == "paused"
    assert paused_rows[0]["version"] == 3

    versions = store.campaign_graph_versions(campaign_id="corp-edge-q1", limit=10)
    assert len(versions) == 3
    assert versions[0]["version"] == 3
    assert versions[0]["event_type"] == "status_change"
    assert versions[1]["version"] == 2
    assert versions[1]["event_type"] == "upsert"
    assert versions[2]["version"] == 1

    missing_status_change = store.set_campaign_graph_status(
        campaign_id="missing-campaign",
        status="active",
    )
    assert missing_status_change is None

    invalid_status_change = store.set_campaign_graph_status(
        campaign_id="corp-edge-q1",
        status="invalid",
    )
    assert invalid_status_change is None

    draft_rows = store.recent_campaign_graphs(limit=10, status="draft")
    assert draft_rows == []

    assert store.delete_campaign_graph(campaign_id="corp-edge-q1") is True
    assert store.delete_campaign_graph(campaign_id="corp-edge-q1") is False
    assert store.campaign_graph(campaign_id="corp-edge-q1") is None
    assert store.campaign_graph_versions(campaign_id="corp-edge-q1", limit=10) == []


def test_intelligence_store_ensure_column_rejects_invalid_identifiers(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE safe_table (id INTEGER PRIMARY KEY)")
        with pytest.raises(ValueError, match="invalid sql table identifier"):
            IntelligenceStore._ensure_column(
                conn=conn,
                table="safe_table;DROP TABLE safe_table;--",
                column="extra",
                definition="TEXT",
            )
        with pytest.raises(ValueError, match="invalid sql column identifier"):
            IntelligenceStore._ensure_column(
                conn=conn,
                table="safe_table",
                column="bad-column-name",
                definition="TEXT",
            )
        with pytest.raises(ValueError, match="invalid sql column definition"):
            IntelligenceStore._ensure_column(
                conn=conn,
                table="safe_table",
                column="safe_column",
                definition="TEXT; DROP TABLE safe_table;--",
            )
