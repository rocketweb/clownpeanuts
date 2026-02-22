import pytest

from clownpeanuts.config.schema import BanditConfig, BanditRewardWeightsConfig, BanditSafetyCapsConfig
from clownpeanuts.intel.behavior import predict_next_action
from clownpeanuts.intel.canary import canary_type_catalog, generate_canary_token
from clownpeanuts.intel.collector import build_intelligence_report
from clownpeanuts.intel.export import (
    build_attack_navigator_layer,
    build_stix_bundle,
    build_taxii_manifest,
    build_theater_action_export,
    find_stix_object,
    render_theater_action_export,
)
from clownpeanuts.intel.handoff import build_soc_handoff
from clownpeanuts.intel.lure_bandit import LureBandit
from clownpeanuts.intel.map import build_engagement_map
from clownpeanuts.intel.mitre import map_event_to_techniques, summarize_coverage, summarize_techniques
from clownpeanuts.intel.reward import compute_bandit_reward, normalize_reward_signals
from clownpeanuts.intel.scoring import score_narrative_coherence


def test_map_event_to_techniques_includes_bruteforce() -> None:
    matches = map_event_to_techniques(
        {
            "service": "ssh",
            "action": "auth_attempt",
            "payload": {"username": "root", "password": "toor"},
        }
    )
    ids = {item.technique_id for item in matches}
    assert "T1110" in ids


def test_generate_canary_token_builds_type_specific_artifacts() -> None:
    dns = generate_canary_token(namespace="corp", token_type="dns")
    assert dns["token_type"] == "dns"
    assert dns["artifact"]["artifact_type"] == "dns"
    assert "hostname" in dns["artifact"]

    aws = generate_canary_token(namespace="corp", token_type="aws")
    assert aws["token_type"] == "aws"
    assert aws["artifact"]["artifact_type"] == "aws"
    assert str(aws["artifact"]["access_key_id"]).startswith("AKIA")
    assert "AWS_ACCESS_KEY_ID=" in aws["artifact"]["env_lines"][0]


def test_generate_canary_token_rejects_invalid_namespace() -> None:
    with pytest.raises(ValueError):
        generate_canary_token(namespace="evil.attacker.com", token_type="dns")


def test_canary_type_catalog_contains_core_types() -> None:
    catalog = canary_type_catalog()
    names = {entry["token_type"] for entry in catalog}
    assert {"dns", "http", "email", "aws", "code"} <= names


def test_predict_next_action_returns_stage_action_and_confidence() -> None:
    prediction = predict_next_action(
        events=[
            {
                "service": "ssh",
                "action": "command",
                "payload": {"command": "whoami"},
            }
        ],
        kill_chain=["initial_access", "discovery"],
    )
    assert prediction["current_stage"] == "discovery"
    assert prediction["predicted_stage"] == "lateral_movement"
    assert prediction["predicted_action"] == "pivot_attempt"
    assert 0.0 <= float(prediction["confidence"]) <= 1.0


def test_summarize_techniques_deduplicates() -> None:
    events = [
        {"service": "ssh", "action": "auth_attempt", "payload": {"command": "whoami"}},
        {"service": "ssh", "action": "auth_attempt", "payload": {"command": "whoami"}},
    ]
    summary = summarize_techniques(events)
    brute = [item for item in summary if item["technique_id"] == "T1110"]
    assert brute
    assert brute[0]["count"] == 2


def test_build_intelligence_report_classifies_sessions() -> None:
    report = build_intelligence_report(
        [
            {
                "session_id": "s1",
                "source_ip": "10.0.0.4",
                "created_at": "2026-01-01T00:00:00+00:00",
                "event_count": 5,
                "events": [
                    {
                        "timestamp": "2026-01-01T00:00:00+00:00",
                        "service": "ssh",
                        "action": "auth_attempt",
                        "payload": {"username": "root"},
                    },
                    {
                        "timestamp": "2026-01-01T00:00:08+00:00",
                        "service": "ssh",
                        "action": "command",
                        "payload": {"command": "nmap -sV 10.0.0.0/24"},
                    },
                ],
            }
        ]
    )
    assert report["totals"]["sessions"] == 1
    assert report["sessions"][0]["classification"]["label"] in {
        "Script Kiddie",
        "Intermediate Attacker",
        "Automated Scanner",
    }
    assert report["techniques"]
    assert "profiles" in report
    assert "canaries" in report
    assert "fingerprints" in report
    assert report["sessions"][0]["timing"]["duration_seconds"] == 8.0
    assert report["sessions"][0]["kill_chain"]
    assert report["sessions"][0]["tool_fingerprints"]
    assert report["sessions"][0]["source_context"]["asn"]["label"].startswith("AS")
    assert report["sessions"][0]["biometrics"]["interaction_style"] in {"automated", "hybrid", "hands-on", "unknown"}
    assert 0.0 <= float(report["sessions"][0]["coherence_score"]) <= 1.0
    assert isinstance(report["sessions"][0]["coherence_violations"], list)
    assert "geography" in report
    assert "biometrics" in report
    assert "kill_chain_graph" in report
    assert "nodes" in report["kill_chain_graph"]
    assert "coverage" in report
    assert "coverage_percent" in report["coverage"]
    assert "coherence_score_avg" in report["totals"]
    assert "bandit_reward_avg" in report["totals"]
    assert 0.0 <= float(report["sessions"][0]["bandit_reward"]) <= 1.0
    assert report["totals"]["fingerprinted_sessions"] == 1


def test_score_narrative_coherence_reaches_full_score_with_consistent_context() -> None:
    scored = score_narrative_coherence(
        {
            "events": [
                {"service": "ssh", "action": "command", "payload": {"command": "whoami"}},
                {"service": "http_admin", "action": "http_request", "payload": {"path": "/admin"}},
            ],
            "narrative": {
                "context_id": "ctx-1234",
                "tenant_id": "default",
                "world_id": "world-abcd",
                "discovery_depth": 2,
                "touched_services": ["ssh", "http_admin"],
                "last_service": "http_admin",
                "last_action": "get_/admin",
            },
        }
    )
    assert scored["score"] == 1.0
    assert scored["violations"] == []


def test_score_narrative_coherence_flags_missing_context() -> None:
    scored = score_narrative_coherence(
        {
            "events": [
                {"service": "ssh", "action": "command", "payload": {"command": "id"}},
            ],
            "narrative": {},
        }
    )
    assert 0.0 <= scored["score"] <= 1.0
    assert scored["score"] < 0.6
    assert "missing_context_id" in scored["violations"]


def test_build_intelligence_report_detects_credential_reuse_across_sessions() -> None:
    report = build_intelligence_report(
        [
            {
                "session_id": "s1",
                "source_ip": "203.0.113.2",
                "created_at": "2026-01-01T00:00:00+00:00",
                "event_count": 1,
                "events": [
                    {
                        "timestamp": "2026-01-01T00:00:00+00:00",
                        "service": "ssh",
                        "action": "auth_attempt",
                        "payload": {"username": "admin", "password": "hunter2"},
                    }
                ],
            },
            {
                "session_id": "s2",
                "source_ip": "203.0.113.3",
                "created_at": "2026-01-01T00:00:10+00:00",
                "event_count": 1,
                "events": [
                    {
                        "timestamp": "2026-01-01T00:00:10+00:00",
                        "service": "http_admin",
                        "action": "credential_capture",
                        "payload": {"username": "admin", "password": "hunter2"},
                    }
                ],
            },
        ]
    )
    reuse = report["credential_reuse"]
    assert reuse["total_reused_credentials"] == 1
    assert reuse["impacted_sessions"] == 2
    assert reuse["patterns"][0]["username"] == "admin"
    assert reuse["patterns"][0]["password_mask"] == "h*****2"


def test_build_intelligence_report_estimates_automation_biometrics() -> None:
    report = build_intelligence_report(
        [
            {
                "session_id": "s-auto",
                "source_ip": "198.51.100.20",
                "created_at": "2026-01-01T00:00:00+00:00",
                "event_count": 6,
                "events": [
                    {
                        "timestamp": "2026-01-01T00:00:00+00:00",
                        "service": "ssh",
                        "action": "command",
                        "payload": {"command": "whoami"},
                    },
                    {
                        "timestamp": "2026-01-01T00:00:01+00:00",
                        "service": "ssh",
                        "action": "command",
                        "payload": {"command": "whoami"},
                    },
                    {
                        "timestamp": "2026-01-01T00:00:02+00:00",
                        "service": "ssh",
                        "action": "command",
                        "payload": {"command": "whoami"},
                    },
                    {
                        "timestamp": "2026-01-01T00:00:03+00:00",
                        "service": "ssh",
                        "action": "command",
                        "payload": {"command": "whoami"},
                    },
                    {
                        "timestamp": "2026-01-01T00:00:04+00:00",
                        "service": "ssh",
                        "action": "command",
                        "payload": {"command": "whoami"},
                    },
                    {
                        "timestamp": "2026-01-01T00:00:05+00:00",
                        "service": "ssh",
                        "action": "command",
                        "payload": {"command": "whoami"},
                    },
                ],
            }
        ]
    )
    session = report["sessions"][0]
    assert session["biometrics"]["automation_score"] >= 70.0
    assert session["biometrics"]["interaction_style"] == "automated"
    assert report["biometrics"]["automated_sessions"] == 1


def test_build_intelligence_report_marks_private_source_context() -> None:
    report = build_intelligence_report(
        [
            {
                "session_id": "s-private",
                "source_ip": "10.0.0.15",
                "created_at": "2026-01-01T00:00:00+00:00",
                "event_count": 1,
                "events": [
                    {
                        "timestamp": "2026-01-01T00:00:00+00:00",
                        "service": "ssh",
                        "action": "auth_attempt",
                        "payload": {"username": "root"},
                    }
                ],
            }
        ]
    )
    session = report["sessions"][0]
    assert session["source_context"]["asn"]["label"] == "AS-PRIVATE"
    assert session["source_context"]["geolocation"]["country_code"] == "ZZ"
    assert report["geography"]["private_sessions"] == 1


def test_build_engagement_map_derives_coordinates() -> None:
    payload = build_engagement_map(
        [{"session_id": "s1", "source_ip": "198.51.100.55", "event_count": 3}, {"session_id": "s2", "source_ip": ""}]
    )
    assert payload["count"] == 1
    assert payload["points"][0]["lat"] <= 70.0
    assert payload["points"][0]["lon"] <= 170.0


def test_build_stix_bundle_contains_indicator() -> None:
    report = {
        "sessions": [{"session_id": "s1", "source_ip": "203.0.113.7"}],
        "techniques": [{"technique_id": "T1110", "technique_name": "Brute Force", "count": 2, "confidence": 0.9}],
    }
    bundle = build_stix_bundle(report)
    assert bundle["type"] == "bundle"
    assert any(item.get("type") == "indicator" for item in bundle["objects"])
    assert any(item.get("type") == "attack-pattern" for item in bundle["objects"])

    manifest = build_taxii_manifest(bundle)
    assert manifest
    first_id = str(manifest[0]["id"])
    found = find_stix_object(bundle, object_id=first_id)
    assert found is not None
    assert found["id"] == first_id


def test_build_stix_bundle_sanitizes_invalid_source_ip_pattern() -> None:
    report = {
        "sessions": [{"session_id": "s-injection", "source_ip": "203.0.113.7'] OR [domain-name:value = 'evil"}],
        "techniques": [],
    }
    bundle = build_stix_bundle(report)
    indicator = next(item for item in bundle["objects"] if item.get("type") == "indicator")
    assert indicator["pattern"] == "[ipv4-addr:value = '0.0.0.0']"


def test_build_attack_navigator_layer_includes_technique_scores() -> None:
    report = {
        "techniques": [
            {"technique_id": "T1110", "technique_name": "Brute Force", "count": 3, "confidence": 0.91},
            {"technique_id": "T1110", "technique_name": "Brute Force", "count": 1, "confidence": 0.4},
            {"technique_id": "T1021", "technique_name": "Remote Services", "count": 2, "confidence": 0.72},
        ],
        "totals": {"sessions": 5, "events": 42, "mitre_coverage_percent": 12.5},
    }
    layer = build_attack_navigator_layer(report, layer_name="SOC Navigator", domain="enterprise-attack")
    assert layer["name"] == "SOC Navigator"
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert isinstance(layer["techniques"], list)
    assert len(layer["techniques"]) == 2
    brute = next(item for item in layer["techniques"] if item["techniqueID"] == "T1110")
    assert brute["score"] == 4
    assert brute["enabled"] is True
    assert "events=4" in brute["comment"]
    assert layer["gradient"]["maxValue"] >= 4


def test_build_soc_handoff_includes_cef_payload() -> None:
    report = {
        "totals": {
            "sessions": 2,
            "events": 8,
            "canary_hits": 1,
            "engagement_score_avg": 42.0,
            "mitre_coverage_percent": 10.5,
        },
        "techniques": [
            {"technique_id": "T1110", "technique_name": "Brute Force", "count": 3},
        ],
        "sessions": [
            {
                "session_id": "s1",
                "source_ip": "203.0.113.1",
                "event_count": 5,
                "engagement_score": {"score": 55.2},
                "classification": {"label": "Intermediate Attacker"},
            }
        ],
        "kill_chain": {"stage_counts": [{"stage": "discovery", "count": 3}]},
    }
    handoff = build_soc_handoff(report, max_techniques=2, max_sessions=2)
    cef_payload = str(handoff.get("cef", "")).strip()
    lines = [line for line in cef_payload.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("CEF:0|ClownPeanuts|SOC Handoff|0.1.0|cp-handoff-summary|")
    assert any("externalId=T1110" in line for line in lines)


def test_build_soc_handoff_includes_syslog_payload() -> None:
    report = {
        "totals": {
            "sessions": 1,
            "events": 4,
            "canary_hits": 0,
            "engagement_score_avg": 35.0,
            "mitre_coverage_percent": 6.2,
        },
        "techniques": [
            {"technique_id": "T1046", "technique_name": "Network Service Discovery", "count": 2},
        ],
        "sessions": [
            {
                "session_id": "s-syslog",
                "source_ip": "203.0.113.8",
                "event_count": 4,
                "engagement_score": {"score": 35.0},
                "classification": {"label": "Automated Scanner"},
            }
        ],
        "kill_chain": {"stage_counts": [{"stage": "discovery", "count": 2}]},
    }
    handoff = build_soc_handoff(report, max_techniques=2, max_sessions=2)
    syslog_payload = str(handoff.get("syslog", "")).strip()
    lines = [line for line in syslog_payload.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("<")
    assert "intel-handoff" in lines[0]
    assert "cp-handoff-summary" in lines[0]
    assert any("T1046" in line for line in lines)


def test_build_soc_handoff_includes_logfmt_payload() -> None:
    report = {
        "totals": {
            "sessions": 1,
            "events": 3,
            "canary_hits": 1,
            "engagement_score_avg": 50.0,
            "mitre_coverage_percent": 9.0,
        },
        "techniques": [
            {"technique_id": "T1110", "technique_name": "Brute Force", "count": 2},
        ],
        "sessions": [
            {
                "session_id": "s-logfmt",
                "source_ip": "198.51.100.22",
                "event_count": 3,
                "engagement_score": {"score": 50.0},
                "classification": {"label": "Intermediate Attacker"},
            }
        ],
        "kill_chain": {"stage_counts": [{"stage": "credential_access", "count": 2}]},
    }
    handoff = build_soc_handoff(report, max_techniques=2, max_sessions=2)
    logfmt_payload = str(handoff.get("logfmt", "")).strip()
    lines = [line for line in logfmt_payload.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("record=summary ")
    assert "sessions=1" in lines[0]
    assert any("record=technique" in line for line in lines)


def test_build_soc_handoff_includes_tsv_payload() -> None:
    report = {
        "totals": {
            "sessions": 1,
            "events": 2,
            "canary_hits": 0,
            "engagement_score_avg": 25.0,
            "mitre_coverage_percent": 3.5,
        },
        "techniques": [
            {"technique_id": "T1595", "technique_name": "Active Scanning", "count": 1},
        ],
        "sessions": [
            {
                "session_id": "s-tsv",
                "source_ip": "198.51.100.23",
                "event_count": 2,
                "engagement_score": {"score": 25.0},
                "classification": {"label": "Automated Scanner"},
            }
        ],
        "kill_chain": {"stage_counts": [{"stage": "reconnaissance", "count": 2}]},
    }
    handoff = build_soc_handoff(report, max_techniques=2, max_sessions=2)
    tsv_payload = str(handoff.get("tsv", "")).strip()
    lines = [line for line in tsv_payload.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("record_type\tgenerated_at\t")
    assert lines[1].startswith("summary\t")


def test_build_soc_handoff_includes_jsonl_alias_payload() -> None:
    report = {
        "totals": {
            "sessions": 1,
            "events": 2,
            "canary_hits": 0,
            "engagement_score_avg": 25.0,
            "mitre_coverage_percent": 3.5,
        },
        "techniques": [
            {"technique_id": "T1595", "technique_name": "Active Scanning", "count": 1},
        ],
        "sessions": [
            {
                "session_id": "s-jsonl",
                "source_ip": "198.51.100.24",
                "event_count": 2,
                "engagement_score": {"score": 25.0},
                "classification": {"label": "Automated Scanner"},
            }
        ],
        "kill_chain": {"stage_counts": [{"stage": "reconnaissance", "count": 2}]},
    }
    handoff = build_soc_handoff(report, max_techniques=2, max_sessions=2)
    jsonl_payload = str(handoff.get("jsonl", "")).strip()
    ndjson_payload = str(handoff.get("ndjson", "")).strip()
    assert jsonl_payload
    assert jsonl_payload == ndjson_payload


def test_build_theater_action_export_returns_schema_payload() -> None:
    export = build_theater_action_export(
        {
            "actions": [
                {
                    "row_id": 1,
                    "created_at": "2026-02-01T00:00:00+00:00",
                    "action_type": "apply_lure",
                    "session_id": "s1",
                    "recommendation_id": "rec-123",
                    "actor": "analyst-1",
                    "payload": {"lure_arm": "ssh-credential-bait"},
                    "metadata": {"tenant_id": "default"},
                }
            ]
        }
    )
    assert export["schema"] == "clownpeanuts.theater_actions.v1"
    assert export["count"] == 1
    assert export["actions"][0]["action_type"] == "apply_lure"


def test_render_theater_action_export_supports_csv() -> None:
    payload = build_theater_action_export(
        {
            "actions": [
                {
                    "row_id": 1,
                    "created_at": "2026-02-01T00:00:00+00:00",
                    "action_type": "apply_lure",
                    "session_id": "s1",
                    "recommendation_id": "rec-123",
                    "actor": "analyst-1",
                    "payload": {"lure_arm": "ssh-credential-bait"},
                    "metadata": {"tenant_id": "default"},
                }
            ]
        }
    )
    csv_payload = render_theater_action_export(payload, output_format="csv")
    lines = [line for line in csv_payload.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("row_id,created_at,action_type,session_id")
    assert "apply_lure" in lines[1]
    assert "analyst-1" in lines[1]


def test_render_theater_action_export_supports_tsv() -> None:
    payload = build_theater_action_export(
        {
            "actions": [
                {
                    "row_id": 2,
                    "created_at": "2026-02-01T00:00:01+00:00",
                    "action_type": "label",
                    "session_id": "s-tsv",
                    "recommendation_id": "rec-tsv",
                    "actor": "analyst-tsv",
                    "payload": {"label": "high_value_actor"},
                    "metadata": {"tenant_id": "default"},
                }
            ]
        }
    )
    tsv_payload = render_theater_action_export(payload, output_format="tsv")
    lines = [line for line in tsv_payload.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("row_id\tcreated_at\taction_type\tsession_id")
    assert "label" in lines[1]
    assert "analyst-tsv" in lines[1]


def test_render_theater_action_export_supports_logfmt() -> None:
    payload = build_theater_action_export(
        {
            "actions": [
                {
                    "row_id": 3,
                    "created_at": "2026-02-01T00:00:02+00:00",
                    "action_type": "apply_lure",
                    "session_id": "s-logfmt",
                    "recommendation_id": "rec-logfmt",
                    "actor": "analyst-logfmt",
                    "payload": {"lure_arm": "ssh-credential-bait"},
                    "metadata": {"tenant_id": "default"},
                }
            ]
        }
    )
    logfmt_payload = render_theater_action_export(payload, output_format="logfmt")
    lines = [line for line in logfmt_payload.splitlines() if line.strip()]
    assert lines
    assert "record_type=theater_action" in lines[0]
    assert "action_type=\"apply_lure\"" in lines[0]
    assert "actor=\"analyst-logfmt\"" in lines[0]


def test_render_theater_action_export_supports_cef() -> None:
    payload = build_theater_action_export(
        {
            "actions": [
                {
                    "row_id": 4,
                    "created_at": "2026-02-01T00:00:03+00:00",
                    "action_type": "apply_lure",
                    "session_id": "s-cef",
                    "recommendation_id": "rec-cef",
                    "actor": "analyst-cef",
                    "payload": {"lure_arm": "http-query-bait"},
                    "metadata": {"tenant_id": "default"},
                }
            ]
        }
    )
    cef_payload = render_theater_action_export(payload, output_format="cef")
    lines = [line for line in cef_payload.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("CEF:0|ClownPeanuts|Theater Actions|0.1.0|")
    assert "action_type=apply_lure" in lines[0]
    assert "session_id=s-cef" in lines[0]


def test_render_theater_action_export_supports_leef() -> None:
    payload = build_theater_action_export(
        {
            "actions": [
                {
                    "row_id": 5,
                    "created_at": "2026-02-01T00:00:04+00:00",
                    "action_type": "label",
                    "session_id": "s-leef",
                    "recommendation_id": "rec-leef",
                    "actor": "analyst-leef",
                    "payload": {"label": "high_value_actor"},
                    "metadata": {"tenant_id": "default"},
                }
            ]
        }
    )
    leef_payload = render_theater_action_export(payload, output_format="leef")
    lines = [line for line in leef_payload.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("LEEF:2.0|ClownPeanuts|Theater Actions|0.1.0|")
    assert "action_type=label" in lines[0]
    assert "session_id=s-leef" in lines[0]


def test_render_theater_action_export_supports_syslog() -> None:
    payload = build_theater_action_export(
        {
            "actions": [
                {
                    "row_id": 6,
                    "created_at": "2026-02-01T00:00:05+00:00",
                    "action_type": "apply_lure",
                    "session_id": "s-syslog",
                    "recommendation_id": "rec-syslog",
                    "actor": "analyst-syslog",
                    "payload": {"lure_arm": "http-query-bait"},
                    "metadata": {"ticket": "SOC-2006"},
                }
            ]
        }
    )
    syslog_payload = render_theater_action_export(payload, output_format="syslog")
    lines = [line for line in syslog_payload.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("<133>1 ")
    assert " clownpeanuts theater-actions " in lines[0]
    assert "record=theater_action" in lines[0]
    assert 'session_id="s-syslog"' in lines[0]


def test_render_theater_action_export_supports_jsonl_alias() -> None:
    payload = build_theater_action_export(
        {
            "actions": [
                {
                    "row_id": 1,
                    "created_at": "2026-02-01T00:00:00+00:00",
                    "action_type": "label",
                    "session_id": "s2",
                    "recommendation_id": "rec-456",
                    "actor": "analyst-2",
                    "payload": {"label": "high_value_actor"},
                    "metadata": {"tenant_id": "default"},
                }
            ]
        }
    )
    jsonl_payload = render_theater_action_export(payload, output_format="jsonl")
    ndjson_payload = render_theater_action_export(payload, output_format="ndjson")
    assert jsonl_payload
    assert jsonl_payload == ndjson_payload
    assert '"record_type":"theater_action"' in jsonl_payload


def test_summarize_coverage_marks_observed_and_gaps() -> None:
    coverage = summarize_coverage(
        [
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access",
                "count": 3,
                "confidence": 0.9,
            }
        ]
    )
    assert coverage["catalog_size"] >= 1
    assert coverage["observed_count"] == 1
    assert coverage["coverage_percent"] > 0.0
    assert coverage["gaps"]


def test_lure_bandit_thompson_selection_with_sparse_history() -> None:
    bandit = LureBandit(
        BanditConfig(
            enabled=True,
            algorithm="thompson",
            exploration_floor=0.0,
            safety_caps=BanditSafetyCapsConfig(max_arm_exposure_percent=1.0, cooldown_seconds=0.0, denylist=[]),
        )
    )

    first = bandit.select_arm(context_key="ssh:recon", candidates=["arm-b", "arm-a"], now_epoch=100.0)
    assert first.selected_arm in {"arm-a", "arm-b"}
    assert first.selected_arm is not None

    bandit.record_reward(context_key="ssh:recon", arm="arm-a", reward=1.0, now_epoch=101.0)
    bandit.record_reward(context_key="ssh:recon", arm="arm-b", reward=0.0, now_epoch=101.0)

    second = bandit.select_arm(context_key="ssh:recon", candidates=["arm-a", "arm-b"], now_epoch=102.0)
    assert second.selected_arm == "arm-a"
    assert second.exploration_applied is False


def test_lure_bandit_ucb_prefers_higher_mean_reward_arm() -> None:
    bandit = LureBandit(
        BanditConfig(
            enabled=True,
            algorithm="ucb",
            exploration_floor=0.0,
            safety_caps=BanditSafetyCapsConfig(max_arm_exposure_percent=1.0, cooldown_seconds=0.0, denylist=[]),
        )
    )

    decision_a = bandit.select_arm(context_key="http:discovery", candidates=["arm-a"], now_epoch=200.0)
    assert decision_a.selected_arm == "arm-a"
    bandit.record_reward(context_key="http:discovery", arm="arm-a", reward=0.9, now_epoch=201.0)

    decision_b = bandit.select_arm(context_key="http:discovery", candidates=["arm-b"], now_epoch=202.0)
    assert decision_b.selected_arm == "arm-b"
    bandit.record_reward(context_key="http:discovery", arm="arm-b", reward=0.1, now_epoch=203.0)

    decision = bandit.select_arm(context_key="http:discovery", candidates=["arm-a", "arm-b"], now_epoch=204.0)
    assert decision.selected_arm == "arm-a"


def test_lure_bandit_exploration_floor_is_respected() -> None:
    bandit = LureBandit(
        BanditConfig(
            enabled=True,
            algorithm="ucb",
            exploration_floor=1.0,
            safety_caps=BanditSafetyCapsConfig(max_arm_exposure_percent=1.0, cooldown_seconds=0.0, denylist=[]),
        )
    )

    decision = bandit.select_arm(context_key="db:query", candidates=["arm-a", "arm-b"], now_epoch=300.0)
    assert decision.selected_arm in {"arm-a", "arm-b"}
    assert decision.exploration_applied is True


def test_lure_bandit_safety_caps_enforce_denylist_cooldown_and_exposure() -> None:
    cooldown_bandit = LureBandit(
        BanditConfig(
            enabled=True,
            algorithm="thompson",
            exploration_floor=0.0,
            safety_caps=BanditSafetyCapsConfig(
                max_arm_exposure_percent=1.0,
                cooldown_seconds=60.0,
                denylist=["blocked"],
            ),
        )
    )

    first = cooldown_bandit.select_arm(
        context_key="ssh:auth",
        candidates=["blocked", "allowed"],
        now_epoch=400.0,
    )
    assert first.selected_arm == "allowed"
    second = cooldown_bandit.select_arm(
        context_key="ssh:auth",
        candidates=["blocked", "allowed"],
        now_epoch=430.0,
    )
    assert second.selected_arm is None
    assert second.blocked_arms["blocked"] == "denylist"
    assert second.blocked_arms["allowed"] == "cooldown"

    exposure_bandit = LureBandit(
        BanditConfig(
            enabled=True,
            algorithm="thompson",
            exploration_floor=0.0,
            safety_caps=BanditSafetyCapsConfig(
                max_arm_exposure_percent=0.5,
                cooldown_seconds=0.0,
                denylist=[],
            ),
        )
    )
    first_exposure = exposure_bandit.select_arm(
        context_key="ssh:auth",
        candidates=["arm-a", "arm-b"],
        now_epoch=500.0,
    )
    assert first_exposure.selected_arm in {"arm-a", "arm-b"}
    second_exposure = exposure_bandit.select_arm(
        context_key="ssh:auth",
        candidates=["arm-a", "arm-b"],
        now_epoch=501.0,
    )
    assert second_exposure.selected_arm is not None
    assert second_exposure.selected_arm != first_exposure.selected_arm


def test_lure_bandit_override_pins_arm_until_expiration() -> None:
    bandit = LureBandit(
        BanditConfig(
            enabled=True,
            algorithm="ucb",
            exploration_floor=0.0,
            safety_caps=BanditSafetyCapsConfig(max_arm_exposure_percent=1.0, cooldown_seconds=0.0, denylist=[]),
        )
    )
    override = bandit.set_override(context_key="ssh:recon", arm="arm-b", duration_seconds=60, now_epoch=700.0)
    assert override["applied"] is True

    pinned = bandit.select_arm(context_key="ssh:recon", candidates=["arm-a", "arm-b"], now_epoch=710.0)
    assert pinned.selected_arm == "arm-b"
    assert pinned.override_applied is True

    unpinned = bandit.select_arm(context_key="ssh:recon", candidates=["arm-a", "arm-b"], now_epoch=770.0)
    assert unpinned.override_applied is False


def test_lure_bandit_reset_clears_stats_and_overrides() -> None:
    bandit = LureBandit(
        BanditConfig(
            enabled=True,
            algorithm="thompson",
            exploration_floor=0.0,
            safety_caps=BanditSafetyCapsConfig(max_arm_exposure_percent=1.0, cooldown_seconds=0.0, denylist=[]),
        )
    )
    bandit.select_arm(context_key="ssh:recon", candidates=["arm-a", "arm-b"], now_epoch=800.0)
    bandit.set_override(context_key="ssh:recon", arm="arm-a", duration_seconds=60, now_epoch=801.0)
    reset = bandit.reset(reason="unit")
    assert reset["reason"] == "unit"
    snapshot = bandit.snapshot()
    assert snapshot["total_selections"] == 0
    assert snapshot["tracked_arm_count"] == 0
    assert snapshot["overrides"] == []


def test_lure_bandit_snapshot_includes_arm_confidence_map() -> None:
    bandit = LureBandit(
        BanditConfig(
            enabled=True,
            algorithm="thompson",
            exploration_floor=0.0,
            safety_caps=BanditSafetyCapsConfig(max_arm_exposure_percent=1.0, cooldown_seconds=0.0, denylist=[]),
        )
    )
    decision = bandit.select_arm(context_key="ssh:recon", candidates=["arm-a"], now_epoch=900.0)
    assert decision.selected_arm == "arm-a"
    bandit.record_reward(context_key="ssh:recon", arm="arm-a", reward=0.9, now_epoch=901.0)

    snapshot = bandit.snapshot()
    assert "arm_confidence" in snapshot
    arm_confidence = snapshot["arm_confidence"]
    assert isinstance(arm_confidence, dict)
    assert "arm-a" in arm_confidence
    assert 0.0 <= float(arm_confidence["arm-a"]) <= 1.0


def test_compute_bandit_reward_normalizes_and_clamps_signals() -> None:
    weights = BanditRewardWeightsConfig(
        dwell_time=1.0,
        cross_protocol_pivot=1.0,
        technique_novelty=1.0,
        alert_quality=1.0,
        analyst_feedback=1.0,
    )
    signals = normalize_reward_signals(
        {
            "dwell_time": 2.5,
            "cross_protocol_pivot": -1,
            "technique_novelty": "0.4",
            "alert_quality": 0.8,
            "analyst_feedback": "invalid",
        }
    )
    reward = compute_bandit_reward(weights=weights, signals=signals)
    assert signals["dwell_time"] == 1.0
    assert signals["cross_protocol_pivot"] == 0.0
    assert signals["technique_novelty"] == 0.4
    assert signals["analyst_feedback"] == 0.0
    assert 0.0 <= reward <= 1.0


def test_compute_bandit_reward_handles_missing_feedback_gracefully() -> None:
    reward = compute_bandit_reward(
        weights=BanditRewardWeightsConfig(),
        signals={"dwell_time": 0.6, "cross_protocol_pivot": 0.5},
    )
    assert 0.0 <= reward <= 1.0
