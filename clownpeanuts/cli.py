"""CLI entry point for ClownPeanuts."""

from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import time
from typing import Any, Sequence

from clownpeanuts.config.loader import initialize_config, load_config
from clownpeanuts.config.schema import VALID_BANDIT_ALGORITHMS
from clownpeanuts.core.doctor import run_diagnostics
from clownpeanuts.core.orchestrator import Orchestrator
from clownpeanuts.intel.canary import canary_type_catalog
from clownpeanuts.intel.export import (
    build_attack_navigator_layer,
    build_stix_bundle,
    build_taxii_manifest,
    build_theater_action_export,
    find_stix_object,
    render_theater_action_export,
)
from clownpeanuts.intel.handoff import build_soc_handoff
from clownpeanuts.intel.simulator import SimulationPolicy, simulate_bandit_counterfactual


DEFAULT_CONFIG = Path(__file__).parent / "config" / "defaults.yml"


def _websocket_runtime_available() -> bool:
    return importlib.util.find_spec("websockets") is not None or importlib.util.find_spec("wsproto") is not None


def _host_is_loopback(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    try:
        parsed = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return parsed.is_loopback


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="clownpeanuts")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create starter config")
    init_parser.add_argument("--config", type=Path, default=Path("./config/clownpeanuts.yml"))
    init_parser.add_argument("--force", action="store_true")

    up_parser = subparsers.add_parser("up", help="Start configured services")
    up_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    up_parser.add_argument("--tenant", type=str, default=None)
    up_parser.add_argument(
        "--once",
        action="store_true",
        help="Start services, print status, then stop immediately",
    )

    status_parser = subparsers.add_parser("status", help="Show orchestrator status")
    status_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    status_parser.add_argument("--tenant", type=str, default=None)

    logs_parser = subparsers.add_parser("logs", help="Show log sink configuration")
    logs_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)

    intel_parser = subparsers.add_parser("intel", help="Build ATT&CK-mapped intelligence snapshot")
    intel_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    intel_parser.add_argument("--tenant", type=str, default=None)
    intel_parser.add_argument("--limit", type=int, default=200)
    intel_parser.add_argument("--events-per-session", type=int, default=200)
    intel_parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="Bootstrap the orchestrator before collecting intelligence",
    )

    intel_history_parser = subparsers.add_parser("intel-history", help="Show stored intelligence report history")
    intel_history_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    intel_history_parser.add_argument("--limit", type=int, default=20)
    intel_history_parser.add_argument("--report-id", type=int, default=None)
    intel_history_parser.add_argument(
        "--sessions",
        action="store_true",
        help="Return per-session intelligence rows instead of report snapshots",
    )

    intel_handoff_parser = subparsers.add_parser(
        "intel-handoff",
        help="Render SOC handoff summary for current or historical intel",
    )
    intel_handoff_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    intel_handoff_parser.add_argument("--tenant", type=str, default=None)
    intel_handoff_parser.add_argument("--limit", type=int, default=200)
    intel_handoff_parser.add_argument("--events-per-session", type=int, default=200)
    intel_handoff_parser.add_argument("--report-id", type=int, default=None)
    intel_handoff_parser.add_argument("--max-techniques", type=int, default=5)
    intel_handoff_parser.add_argument("--max-sessions", type=int, default=5)
    intel_handoff_parser.add_argument(
        "--format",
        dest="output_format",
        type=str,
        choices=["json", "markdown", "csv", "tsv", "ndjson", "jsonl", "cef", "leef", "syslog", "logfmt"],
        default="json",
    )
    intel_handoff_parser.add_argument("--output", type=Path, default=None, help="Write handoff output to this file path")
    intel_handoff_parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="Bootstrap the orchestrator before collecting intelligence",
    )

    intel_coverage_parser = subparsers.add_parser("intel-coverage", help="Show ATT&CK coverage and gap analysis")
    intel_coverage_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    intel_coverage_parser.add_argument("--tenant", type=str, default=None)
    intel_coverage_parser.add_argument("--limit", type=int, default=200)
    intel_coverage_parser.add_argument("--events-per-session", type=int, default=200)
    intel_coverage_parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="Bootstrap the orchestrator before collecting coverage",
    )

    stix_export_parser = subparsers.add_parser("stix-export", help="Export STIX 2.1 intelligence bundle")
    stix_export_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    stix_export_parser.add_argument("--tenant", type=str, default=None)
    stix_export_parser.add_argument("--limit", type=int, default=200)
    stix_export_parser.add_argument("--events-per-session", type=int, default=200)
    stix_export_parser.add_argument("--report-id", type=int, default=None)
    stix_export_parser.add_argument("--output", type=Path, default=None, help="Write bundle JSON to this file path")
    stix_export_parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="Bootstrap the orchestrator before exporting bundle",
    )

    taxii_export_parser = subparsers.add_parser("taxii-export", help="Export TAXII manifest/object feeds")
    taxii_export_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    taxii_export_parser.add_argument("--tenant", type=str, default=None)
    taxii_export_parser.add_argument("--limit", type=int, default=200)
    taxii_export_parser.add_argument("--events-per-session", type=int, default=200)
    taxii_export_parser.add_argument("--report-id", type=int, default=None)
    taxii_export_parser.add_argument("--collection-id", type=str, default="clownpeanuts-intel")
    taxii_export_parser.add_argument(
        "--manifest",
        action="store_true",
        help="Export TAXII manifest entries instead of full STIX objects",
    )
    taxii_export_parser.add_argument(
        "--object-id",
        type=str,
        default=None,
        help="Export one specific STIX object by id",
    )
    taxii_export_parser.add_argument("--output", type=Path, default=None, help="Write TAXII JSON payload to this file")
    taxii_export_parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="Bootstrap the orchestrator before exporting TAXII payload",
    )

    navigator_export_parser = subparsers.add_parser(
        "navigator-export",
        help="Export ATT&CK Navigator layer JSON",
    )
    navigator_export_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    navigator_export_parser.add_argument("--tenant", type=str, default=None)
    navigator_export_parser.add_argument("--limit", type=int, default=200)
    navigator_export_parser.add_argument("--events-per-session", type=int, default=200)
    navigator_export_parser.add_argument("--report-id", type=int, default=None)
    navigator_export_parser.add_argument("--name", type=str, default="ClownPeanuts ATT&CK Observations")
    navigator_export_parser.add_argument("--domain", type=str, default="enterprise-attack")
    navigator_export_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write ATT&CK Navigator layer JSON to this file path",
    )
    navigator_export_parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="Bootstrap the orchestrator before exporting layer",
    )

    theater_history_parser = subparsers.add_parser(
        "theater-history",
        help="Export persisted theater operator action history",
    )
    theater_history_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    theater_history_parser.add_argument("--limit", type=int, default=200)
    theater_history_parser.add_argument("--session-id", type=str, default=None)
    theater_history_parser.add_argument(
        "--session-ids",
        type=str,
        default=None,
        help="Comma-separated session ids for multi-session export filters",
    )
    theater_history_parser.add_argument("--action-type", type=str, default=None)
    theater_history_parser.add_argument(
        "--format",
        dest="output_format",
        type=str,
        choices=["json", "csv", "tsv", "ndjson", "jsonl", "logfmt", "cef", "leef", "syslog"],
        default="json",
    )
    theater_history_parser.add_argument("--output", type=Path, default=None, help="Write export payload to this file path")

    rotate_parser = subparsers.add_parser("rotate", help="Trigger one immediate threat-intel bait rotation")
    rotate_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    rotate_parser.add_argument("--tenant", type=str, default=None)
    rotate_parser.add_argument(
        "--start-services",
        action="store_true",
        help="Start configured emulators before rotating profile",
    )

    rotate_preview_parser = subparsers.add_parser("rotate-preview", help="Preview threat-intel profile selection")
    rotate_preview_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    rotate_preview_parser.add_argument("--tenant", type=str, default=None)

    simulate_bandit_parser = subparsers.add_parser(
        "simulate-bandit",
        help="Replay recent session traces against alternate bandit policies",
    )
    simulate_bandit_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    simulate_bandit_parser.add_argument("--window-hours", type=float, default=24.0)
    simulate_bandit_parser.add_argument("--history-limit", type=int, default=200)
    simulate_bandit_parser.add_argument(
        "--baseline-algorithm",
        type=str,
        choices=sorted(VALID_BANDIT_ALGORITHMS),
        default=None,
    )
    simulate_bandit_parser.add_argument("--baseline-exploration-floor", type=float, default=None)
    simulate_bandit_parser.add_argument(
        "--candidate-algorithm",
        type=str,
        choices=sorted(VALID_BANDIT_ALGORITHMS),
        default=None,
    )
    simulate_bandit_parser.add_argument("--candidate-exploration-floor", type=float, default=None)

    templates_parser = subparsers.add_parser("templates", help="Show template inventory and effective service plan")
    templates_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    templates_parser.add_argument("--tenant", type=str, default=None)
    templates_parser.add_argument(
        "--no-threat-rotation",
        action="store_true",
        help="Disable threat-intel profile mutation when rendering service plan",
    )
    templates_parser.add_argument(
        "--all-tenants",
        action="store_true",
        help="Render effective service plans for all enabled tenants",
    )

    templates_validate_parser = subparsers.add_parser(
        "templates-validate",
        help="Validate deception-template files and return lint findings",
    )
    templates_validate_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    templates_validate_parser.add_argument("--tenant", type=str, default=None)
    templates_validate_parser.add_argument(
        "--all-tenants",
        action="store_true",
        help="Validate template overlays against all enabled tenants",
    )
    templates_validate_parser.add_argument(
        "--strict-warnings",
        action="store_true",
        help="Return non-zero when template warnings are present",
    )

    templates_diff_parser = subparsers.add_parser(
        "templates-diff",
        help="Compare effective template service plans between two tenants",
    )
    templates_diff_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    templates_diff_parser.add_argument("--left-tenant", type=str, default=None)
    templates_diff_parser.add_argument("--right-tenant", type=str, default=None)
    templates_diff_parser.add_argument(
        "--all-pairs",
        action="store_true",
        help="Compare all tenant pairs and return a diff matrix",
    )
    templates_diff_parser.add_argument(
        "--no-threat-rotation",
        action="store_true",
        help="Disable threat-intel profile mutation when comparing service plans",
    )
    templates_diff_parser.add_argument(
        "--fail-on-diff",
        action="store_true",
        help="Return non-zero when any plan differences are detected",
    )

    replay_parser = subparsers.add_parser("replay", help="Show session replay for one session id")
    replay_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    replay_parser.add_argument("--tenant", type=str, default=None)
    replay_parser.add_argument("--session-id", type=str, required=True)
    replay_parser.add_argument("--events-limit", type=int, default=500)
    replay_parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="Bootstrap orchestrator before replaying (required for in-memory runtime sessions)",
    )

    replay_compare_parser = subparsers.add_parser(
        "replay-compare",
        help="Compare replay outputs for two session ids",
    )
    replay_compare_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    replay_compare_parser.add_argument("--tenant", type=str, default=None)
    replay_compare_parser.add_argument("--left-session-id", type=str, required=True)
    replay_compare_parser.add_argument("--right-session-id", type=str, required=True)
    replay_compare_parser.add_argument("--events-limit", type=int, default=500)
    replay_compare_parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="Bootstrap orchestrator before replay comparison (required for in-memory runtime sessions)",
    )

    canary_hit_parser = subparsers.add_parser("canary-hit", help="Ingest a canary token hit event")
    canary_hit_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    canary_hit_parser.add_argument("--tenant", type=str, default=None)
    canary_hit_parser.add_argument("--token", type=str, required=True)
    canary_hit_parser.add_argument("--source-ip", type=str, required=True)
    canary_hit_parser.add_argument("--service", type=str, default="canary")
    canary_hit_parser.add_argument("--session-id", type=str, default=None)
    canary_hit_parser.add_argument(
        "--metadata-json",
        type=str,
        default=None,
        help="Optional JSON object string merged into canary event payload",
    )
    canary_hit_parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="Bootstrap orchestrator before ingesting hit",
    )

    canary_generate_parser = subparsers.add_parser("canary-generate", help="Generate a canary token")
    canary_generate_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    canary_generate_parser.add_argument("--namespace", type=str, default="cp")
    canary_generate_parser.add_argument("--token-type", type=str, default="http")
    canary_generate_parser.add_argument(
        "--metadata-json",
        type=str,
        default=None,
        help="Optional JSON object string persisted alongside token inventory metadata",
    )
    subparsers.add_parser("canary-types", help="List supported canary token artifact types")

    canary_tokens_parser = subparsers.add_parser("canary-tokens", help="Show persisted canary token inventory")
    canary_tokens_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    canary_tokens_parser.add_argument("--limit", type=int, default=100)
    canary_tokens_parser.add_argument("--namespace", type=str, default=None)
    canary_tokens_parser.add_argument("--token-type", type=str, default=None)

    canary_hits_parser = subparsers.add_parser("canary-hits", help="Show persisted canary hit history")
    canary_hits_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    canary_hits_parser.add_argument("--limit", type=int, default=200)
    canary_hits_parser.add_argument("--token-id", type=str, default=None)

    alerts_test_parser = subparsers.add_parser("alerts-test", help="Emit a synthetic alert through configured adapters")
    alerts_test_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    alerts_test_parser.add_argument("--severity", type=str, choices=["low", "medium", "high", "critical"], default="medium")
    alerts_test_parser.add_argument("--title", type=str, default="manual_alert_test")
    alerts_test_parser.add_argument("--summary", type=str, default="synthetic alert delivery test")
    alerts_test_parser.add_argument("--service", type=str, default="ops")
    alerts_test_parser.add_argument("--action", type=str, default="alert_test")
    alerts_test_parser.add_argument(
        "--metadata-json",
        type=str,
        default=None,
        help="Optional JSON object string merged into synthetic alert payload",
    )
    alerts_routes_parser = subparsers.add_parser("alerts-routes", help="Preview alert routing decisions per destination")
    alerts_routes_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    alerts_routes_parser.add_argument(
        "--severity",
        type=str,
        choices=["low", "medium", "high", "critical"],
        default="medium",
    )
    alerts_routes_parser.add_argument("--service", type=str, default="ops")
    alerts_routes_parser.add_argument("--action", type=str, default="alert_test")
    alerts_routes_parser.add_argument("--title", type=str, default="manual_alert_test")
    alerts_routes_parser.add_argument(
        "--apply-throttle",
        action="store_true",
        help="Apply throttle windows in route preview decisions",
    )

    doctor_parser = subparsers.add_parser("doctor", help="Run configuration and readiness diagnostics")
    doctor_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    doctor_parser.add_argument("--check-llm", action="store_true", help="Probe configured local LLM endpoint")

    api_parser = subparsers.add_parser("api", help="Run FastAPI operations backend")
    api_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    api_parser.add_argument("--tenant", type=str, default=None)
    api_parser.add_argument("--host", type=str, default="127.0.0.1")
    api_parser.add_argument("--port", type=int, default=8099)
    api_parser.add_argument(
        "--start-services",
        action="store_true",
        help="Start configured emulators before serving the API",
    )

    return parser


def cmd_init(config_path: Path, force: bool) -> int:
    initialize_config(config_path, force=force)
    print(f"wrote config: {config_path}")
    return 0


def cmd_up(config_path: Path, once: bool = False, tenant: str | None = None) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap(tenant_id=tenant)
    try:
        orchestrator.start_all()
        print(json.dumps(orchestrator.status(), indent=2))
        if once:
            return 0
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return 0
    finally:
        orchestrator.stop_all()
    return 0


def cmd_status(config_path: Path, tenant: str | None = None) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap(tenant_id=tenant)
    print(json.dumps(orchestrator.status(), indent=2))
    return 0


def cmd_logs(config_path: Path) -> int:
    config = load_config(config_path)
    payload = {
        "format": config.logging.fmt,
        "level": config.logging.level,
        "sink": config.logging.sink,
        "session_backend": config.session.backend,
        "event_bus_backend": config.event_bus.backend,
        "siem": {
            "enabled": config.logging.siem.enabled,
            "transport": config.logging.siem.transport,
            "endpoint": config.logging.siem.endpoint,
            "batch_size": config.logging.siem.batch_size,
            "flush_interval_seconds": config.logging.siem.flush_interval_seconds,
            "max_retries": config.logging.siem.max_retries,
            "retry_backoff_seconds": config.logging.siem.retry_backoff_seconds,
            "max_queue_size": config.logging.siem.max_queue_size,
            "dead_letter_path": config.logging.siem.dead_letter_path,
        },
    }
    print(json.dumps(payload, indent=2))
    return 0


def _normalized_exploration_floor(raw_value: float | None, *, fallback: float) -> float:
    if raw_value is None:
        return max(0.0, min(1.0, float(fallback)))
    return max(0.0, min(1.0, float(raw_value)))


def cmd_intel(
    config_path: Path,
    *,
    limit: int,
    events_per_session: int,
    bootstrap: bool,
    tenant: str | None,
) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    if bootstrap:
        orchestrator.bootstrap(tenant_id=tenant)
    report = orchestrator.intelligence_report(
        limit=max(1, int(limit)),
        events_per_session=max(0, int(events_per_session)),
    )
    print(json.dumps(report, indent=2))
    return 0


def cmd_intel_history(config_path: Path, *, limit: int, report_id: int | None, sessions: bool) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    if report_id is not None:
        if sessions:
            payload = orchestrator.intelligence_history_report_sessions(
                report_id=max(1, int(report_id)),
                limit=max(1, int(limit)),
            )
        else:
            payload = orchestrator.intelligence_history_report(report_id=max(1, int(report_id)))
    elif sessions:
        payload = orchestrator.intelligence_session_history(limit=max(1, int(limit)))
    else:
        payload = orchestrator.intelligence_history(limit=max(1, int(limit)))
    print(json.dumps(payload, indent=2))
    return 0


def cmd_intel_handoff(
    config_path: Path,
    *,
    limit: int,
    events_per_session: int,
    report_id: int | None,
    max_techniques: int,
    max_sessions: int,
    output_format: str,
    output: Path | None,
    bootstrap: bool,
    tenant: str | None,
) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    if bootstrap:
        orchestrator.bootstrap(tenant_id=tenant)
    if report_id is not None:
        report = orchestrator.intelligence_history_report_payload(report_id=max(1, int(report_id)))
        if report is None:
            print(json.dumps({"error": f"intelligence report not found: {report_id}"}, indent=2))
            return 1
    else:
        report = orchestrator.intelligence_report(
            limit=max(1, int(limit)),
            events_per_session=max(0, int(events_per_session)),
        )
    handoff = build_soc_handoff(
        report,
        max_techniques=max(1, int(max_techniques)),
        max_sessions=max(1, int(max_sessions)),
    )
    if output_format == "markdown":
        markdown = str(handoff.get("markdown", "")).strip()
        if output is None:
            print(markdown)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{markdown}\n", encoding="utf-8")
        print(json.dumps({"output": str(output), "format": "markdown"}, indent=2))
        return 0
    if output_format == "csv":
        csv_payload = str(handoff.get("csv", "")).strip()
        if output is None:
            print(csv_payload)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{csv_payload}\n", encoding="utf-8")
        print(json.dumps({"output": str(output), "format": "csv"}, indent=2))
        return 0
    if output_format == "tsv":
        tsv_payload = str(handoff.get("tsv", "")).strip()
        if output is None:
            print(tsv_payload)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{tsv_payload}\n", encoding="utf-8")
        print(json.dumps({"output": str(output), "format": "tsv"}, indent=2))
        return 0
    if output_format == "ndjson":
        ndjson_payload = str(handoff.get("ndjson", "")).strip()
        if output is None:
            print(ndjson_payload)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{ndjson_payload}\n", encoding="utf-8")
        print(json.dumps({"output": str(output), "format": "ndjson"}, indent=2))
        return 0
    if output_format == "jsonl":
        jsonl_payload = str(handoff.get("jsonl", "")).strip()
        if output is None:
            print(jsonl_payload)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{jsonl_payload}\n", encoding="utf-8")
        print(json.dumps({"output": str(output), "format": "jsonl"}, indent=2))
        return 0
    if output_format == "cef":
        cef_payload = str(handoff.get("cef", "")).strip()
        if output is None:
            print(cef_payload)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{cef_payload}\n", encoding="utf-8")
        print(json.dumps({"output": str(output), "format": "cef"}, indent=2))
        return 0
    if output_format == "leef":
        leef_payload = str(handoff.get("leef", "")).strip()
        if output is None:
            print(leef_payload)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{leef_payload}\n", encoding="utf-8")
        print(json.dumps({"output": str(output), "format": "leef"}, indent=2))
        return 0
    if output_format == "syslog":
        syslog_payload = str(handoff.get("syslog", "")).strip()
        if output is None:
            print(syslog_payload)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{syslog_payload}\n", encoding="utf-8")
        print(json.dumps({"output": str(output), "format": "syslog"}, indent=2))
        return 0
    if output_format == "logfmt":
        logfmt_payload = str(handoff.get("logfmt", "")).strip()
        if output is None:
            print(logfmt_payload)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{logfmt_payload}\n", encoding="utf-8")
        print(json.dumps({"output": str(output), "format": "logfmt"}, indent=2))
        return 0
    if output is None:
        print(json.dumps(handoff, indent=2))
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(handoff, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output), "format": "json"}, indent=2))
    return 0


def cmd_intel_coverage(
    config_path: Path,
    *,
    limit: int,
    events_per_session: int,
    bootstrap: bool,
    tenant: str | None,
) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    if bootstrap:
        orchestrator.bootstrap(tenant_id=tenant)
    report = orchestrator.intelligence_report(
        limit=max(1, int(limit)),
        events_per_session=max(0, int(events_per_session)),
    )
    coverage = report.get("coverage", {})
    if not isinstance(coverage, dict):
        coverage = {}
    print(json.dumps(coverage, indent=2))
    return 0


def cmd_stix_export(
    config_path: Path,
    *,
    limit: int,
    events_per_session: int,
    report_id: int | None,
    output: Path | None,
    bootstrap: bool,
    tenant: str | None,
) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    if bootstrap:
        orchestrator.bootstrap(tenant_id=tenant)
    if report_id is not None:
        report = orchestrator.intelligence_history_report_payload(report_id=max(1, int(report_id)))
        if report is None:
            print(json.dumps({"error": f"intelligence report not found: {report_id}"}, indent=2))
            return 1
    else:
        report = orchestrator.intelligence_report(
            limit=max(1, int(limit)),
            events_per_session=max(0, int(events_per_session)),
        )
    bundle = build_stix_bundle(report)
    if output is None:
        print(json.dumps(bundle, indent=2))
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output), "bundle_id": bundle.get("id", "")}, indent=2))
    return 0


def cmd_taxii_export(
    config_path: Path,
    *,
    limit: int,
    events_per_session: int,
    report_id: int | None,
    collection_id: str,
    manifest: bool,
    object_id: str | None,
    output: Path | None,
    bootstrap: bool,
    tenant: str | None,
) -> int:
    if collection_id.strip() != "clownpeanuts-intel":
        print(json.dumps({"error": f"unknown TAXII collection: {collection_id}"}, indent=2))
        return 1

    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    if bootstrap:
        orchestrator.bootstrap(tenant_id=tenant)

    if report_id is not None:
        report = orchestrator.intelligence_history_report_payload(report_id=max(1, int(report_id)))
        if report is None:
            print(json.dumps({"error": f"intelligence report not found: {report_id}"}, indent=2))
            return 1
    else:
        report = orchestrator.intelligence_report(
            limit=max(1, int(limit)),
            events_per_session=max(0, int(events_per_session)),
        )

    bundle = build_stix_bundle(report)
    bundle_id = str(bundle.get("id", ""))

    if object_id:
        obj = find_stix_object(bundle, object_id=object_id)
        if obj is None:
            print(json.dumps({"error": f"STIX object not found: {object_id}"}, indent=2))
            return 1
        payload: dict[str, object] = {
            "collection_id": "clownpeanuts-intel",
            "bundle_id": bundle_id,
            "object": obj,
        }
    elif manifest:
        payload = {
            "collection_id": "clownpeanuts-intel",
            "bundle_id": bundle_id,
            "manifest": build_taxii_manifest(bundle),
        }
    else:
        objects = bundle.get("objects", [])
        if not isinstance(objects, list):
            objects = []
        payload = {
            "collection_id": "clownpeanuts-intel",
            "bundle_id": bundle_id,
            "objects": objects,
        }

    if output is None:
        print(json.dumps(payload, indent=2))
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output), "bundle_id": bundle_id, "collection_id": "clownpeanuts-intel"}, indent=2))
    return 0


def cmd_navigator_export(
    config_path: Path,
    *,
    limit: int,
    events_per_session: int,
    report_id: int | None,
    name: str,
    domain: str,
    output: Path | None,
    bootstrap: bool,
    tenant: str | None,
) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    if bootstrap:
        orchestrator.bootstrap(tenant_id=tenant)
    if report_id is not None:
        report = orchestrator.intelligence_history_report_payload(report_id=max(1, int(report_id)))
        if report is None:
            print(json.dumps({"error": f"intelligence report not found: {report_id}"}, indent=2))
            return 1
    else:
        report = orchestrator.intelligence_report(
            limit=max(1, int(limit)),
            events_per_session=max(0, int(events_per_session)),
        )

    layer = build_attack_navigator_layer(
        report,
        layer_name=name,
        domain=domain,
    )
    if output is None:
        print(json.dumps(layer, indent=2))
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output), "name": layer.get("name", ""), "domain": layer.get("domain", "")}, indent=2))
    return 0


def cmd_theater_history(
    config_path: Path,
    *,
    limit: int,
    session_id: str | None,
    session_ids: str | None,
    action_type: str | None,
    output_format: str,
    output: Path | None,
) -> int:
    normalized_session_id = str(session_id or "").strip()
    normalized_session_ids = {
        token.strip().lower()
        for token in str(session_ids or "").split(",")
        if token.strip()
    }
    if normalized_session_id:
        normalized_session_ids.add(normalized_session_id.lower())
    base_session_id: str | None = None
    if len(normalized_session_ids) == 1:
        base_session_id = next(iter(normalized_session_ids))

    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    payload = orchestrator.theater_actions(
        limit=max(1, int(limit)),
        session_id=base_session_id,
        action_type=action_type,
    )
    export_payload = build_theater_action_export(payload)
    if normalized_session_ids:
        actions = export_payload.get("actions", [])
        if not isinstance(actions, list):
            actions = []
        filtered_actions: list[dict[str, Any]] = []
        for item in actions:
            if not isinstance(item, dict):
                continue
            action_session_id = str(item.get("session_id", "")).strip().lower()
            if action_session_id in normalized_session_ids:
                filtered_actions.append(item)
        export_payload["actions"] = filtered_actions
        export_payload["count"] = len(filtered_actions)
    if output_format == "csv":
        csv_payload = render_theater_action_export(export_payload, output_format="csv")
        if output is None:
            print(csv_payload)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{csv_payload}\n", encoding="utf-8")
        print(json.dumps({"output": str(output), "format": "csv", "count": int(export_payload.get("count", 0) or 0)}, indent=2))
        return 0
    if output_format == "tsv":
        tsv_payload = render_theater_action_export(export_payload, output_format="tsv")
        if output is None:
            print(tsv_payload)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{tsv_payload}\n", encoding="utf-8")
        print(json.dumps({"output": str(output), "format": "tsv", "count": int(export_payload.get("count", 0) or 0)}, indent=2))
        return 0
    if output_format == "ndjson":
        ndjson_payload = render_theater_action_export(export_payload, output_format="ndjson")
        if output is None:
            print(ndjson_payload)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{ndjson_payload}\n", encoding="utf-8")
        print(
            json.dumps(
                {"output": str(output), "format": "ndjson", "count": int(export_payload.get("count", 0) or 0)},
                indent=2,
            )
        )
        return 0
    if output_format == "jsonl":
        jsonl_payload = render_theater_action_export(export_payload, output_format="jsonl")
        if output is None:
            print(jsonl_payload)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{jsonl_payload}\n", encoding="utf-8")
        print(
            json.dumps(
                {"output": str(output), "format": "jsonl", "count": int(export_payload.get("count", 0) or 0)},
                indent=2,
            )
        )
        return 0
    if output_format == "logfmt":
        logfmt_payload = render_theater_action_export(export_payload, output_format="logfmt")
        if output is None:
            print(logfmt_payload)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{logfmt_payload}\n", encoding="utf-8")
        print(
            json.dumps(
                {"output": str(output), "format": "logfmt", "count": int(export_payload.get("count", 0) or 0)},
                indent=2,
            )
        )
        return 0
    if output_format == "cef":
        cef_payload = render_theater_action_export(export_payload, output_format="cef")
        if output is None:
            print(cef_payload)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{cef_payload}\n", encoding="utf-8")
        print(
            json.dumps(
                {"output": str(output), "format": "cef", "count": int(export_payload.get("count", 0) or 0)},
                indent=2,
            )
        )
        return 0
    if output_format == "leef":
        leef_payload = render_theater_action_export(export_payload, output_format="leef")
        if output is None:
            print(leef_payload)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{leef_payload}\n", encoding="utf-8")
        print(
            json.dumps(
                {"output": str(output), "format": "leef", "count": int(export_payload.get("count", 0) or 0)},
                indent=2,
            )
        )
        return 0
    if output_format == "syslog":
        syslog_payload = render_theater_action_export(export_payload, output_format="syslog")
        if output is None:
            print(syslog_payload)
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{syslog_payload}\n", encoding="utf-8")
        print(
            json.dumps(
                {"output": str(output), "format": "syslog", "count": int(export_payload.get("count", 0) or 0)},
                indent=2,
            )
        )
        return 0
    if output is None:
        print(json.dumps(export_payload, indent=2))
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(export_payload, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output), "count": int(export_payload.get("count", 0) or 0)}, indent=2))
    return 0


def cmd_api(config_path: Path, *, host: str, port: int, start_services: bool, tenant: str | None) -> int:
    config = load_config(config_path)
    if not _host_is_loopback(host) and not bool(getattr(config.api, "auth_enabled", False)):
        raise RuntimeError(
            "refusing to bind API to a non-loopback host without auth; set api.auth_enabled=true and configure tokens"
        )
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap(tenant_id=tenant)

    should_stop = False
    if start_services:
        orchestrator.start_all()
        should_stop = True
    try:
        from clownpeanuts.dashboard.api import create_app
        import uvicorn
    except Exception as exc:
        if should_stop:
            orchestrator.stop_all()
        raise RuntimeError("dashboard api dependencies are missing; install with 'clownpeanuts[api]'") from exc

    if not _websocket_runtime_available():
        if should_stop:
            orchestrator.stop_all()
        raise RuntimeError(
            "dashboard api websocket dependencies are missing; install with "
            "\"pip install -e .[api]\" or \"pip install 'uvicorn[standard]'\""
        )

    try:
        app = create_app(orchestrator)
        uvicorn.run(app, host=host, port=int(port), log_level=config.logging.level.lower())
    finally:
        if should_stop:
            orchestrator.stop_all()
    return 0


def cmd_rotate(config_path: Path, *, tenant: str | None, start_services: bool) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap(tenant_id=tenant)

    should_stop = False
    if start_services:
        orchestrator.start_all()
        should_stop = True
    try:
        snapshot = orchestrator.rotate_threat_intel()
        payload = {
            "tenant": orchestrator.status().get("tenant", config.multi_tenant.default_tenant),
            "threat_intel": snapshot,
        }
        print(json.dumps(payload, indent=2))
    finally:
        if should_stop:
            orchestrator.stop_all()
    return 0


def cmd_rotate_preview(config_path: Path, *, tenant: str | None) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap(tenant_id=tenant)
    payload = {
        "tenant": orchestrator.status().get("tenant", config.multi_tenant.default_tenant),
        "threat_intel": orchestrator.threat_intel_preview(),
    }
    print(json.dumps(payload, indent=2))
    return 0


def cmd_simulate_bandit(
    config_path: Path,
    *,
    window_hours: float,
    history_limit: int,
    baseline_algorithm: str | None,
    baseline_exploration_floor: float | None,
    candidate_algorithm: str | None,
    candidate_exploration_floor: float | None,
) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    history = orchestrator.intelligence_history(limit=max(1, int(history_limit)))
    report_rows = history.get("reports", [])
    if not isinstance(report_rows, list):
        report_rows = []

    baseline_policy = SimulationPolicy(
        name="baseline",
        algorithm=(baseline_algorithm or config.bandit.algorithm).strip().lower(),
        exploration_floor=_normalized_exploration_floor(
            baseline_exploration_floor,
            fallback=config.bandit.exploration_floor,
        ),
    )
    default_candidate_algorithm = "ucb" if baseline_policy.algorithm == "thompson" else "thompson"
    candidate_policy = SimulationPolicy(
        name="candidate",
        algorithm=(candidate_algorithm or default_candidate_algorithm).strip().lower(),
        exploration_floor=_normalized_exploration_floor(
            candidate_exploration_floor,
            fallback=baseline_policy.exploration_floor,
        ),
    )
    payload = simulate_bandit_counterfactual(
        report_rows=report_rows,
        window_hours=max(0.1, float(window_hours)),
        baseline_policy=baseline_policy,
        candidate_policy=candidate_policy,
        reward_weights=config.bandit.reward_weights,
    )
    payload["history_reports_considered"] = len(report_rows)
    payload["store"] = history.get("store", {})
    print(json.dumps(payload, indent=2))
    return 0


def cmd_templates(config_path: Path, *, tenant: str | None, no_threat_rotation: bool, all_tenants: bool) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    payload = {
        "inventory": orchestrator.template_inventory(),
        "plan": orchestrator.service_plan(
            tenant_id=tenant,
            apply_threat_rotation=not bool(no_threat_rotation),
            all_tenants=all_tenants,
        ),
    }
    print(json.dumps(payload, indent=2))
    return 0


def cmd_templates_validate(
    config_path: Path,
    *,
    tenant: str | None,
    all_tenants: bool,
    strict_warnings: bool,
) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    payload = orchestrator.template_validation(tenant_id=tenant, all_tenants=all_tenants)
    print(json.dumps(payload, indent=2))
    if not bool(payload.get("ok")):
        return 1
    warning_count = max(0, int(payload.get("warning_count", 0)))
    if strict_warnings and warning_count > 0:
        return 1
    return 0


def cmd_templates_diff(
    config_path: Path,
    *,
    left_tenant: str | None,
    right_tenant: str | None,
    all_pairs: bool,
    no_threat_rotation: bool,
    fail_on_diff: bool,
) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    if all_pairs:
        payload = orchestrator.service_plan_diff_matrix(
            tenant_id=left_tenant,
            apply_threat_rotation=not bool(no_threat_rotation),
        )
    else:
        payload = orchestrator.service_plan_diff(
            left_tenant_id=left_tenant,
            right_tenant_id=right_tenant,
            apply_threat_rotation=not bool(no_threat_rotation),
        )
    print(json.dumps(payload, indent=2))
    has_differences = (
        bool(payload.get("different"))
        if not all_pairs
        else max(0, int(payload.get("different_count", 0))) > 0
    )
    if fail_on_diff and has_differences:
        return 1
    return 0


def cmd_replay(
    config_path: Path,
    *,
    session_id: str,
    events_limit: int,
    bootstrap: bool,
    tenant: str | None,
) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    if bootstrap:
        orchestrator.bootstrap(tenant_id=tenant)
    payload = orchestrator.session_replay(session_id=session_id, events_limit=max(0, int(events_limit)))
    print(json.dumps(payload, indent=2))
    return 0


def cmd_replay_compare(
    config_path: Path,
    *,
    left_session_id: str,
    right_session_id: str,
    events_limit: int,
    bootstrap: bool,
    tenant: str | None,
) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    if bootstrap:
        orchestrator.bootstrap(tenant_id=tenant)
    payload = orchestrator.session_replay_compare(
        left_session_id=left_session_id,
        right_session_id=right_session_id,
        events_limit=max(0, int(events_limit)),
    )
    print(json.dumps(payload, indent=2))
    return 0 if bool(payload.get("found")) else 1


def _parse_metadata_json(raw: str | None) -> dict[str, object] | None:
    if raw is None:
        return None
    text = raw.strip()
    if not text:
        return None
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("metadata-json must be a JSON object")
    payload: dict[str, object] = {}
    for key, value in parsed.items():
        normalized = str(key).strip()
        if normalized:
            payload[normalized] = value
    return payload or None


def cmd_canary_hit(
    config_path: Path,
    *,
    token: str,
    source_ip: str,
    service: str,
    session_id: str | None,
    metadata_json: str | None,
    bootstrap: bool,
    tenant: str | None,
) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    if bootstrap:
        orchestrator.bootstrap(tenant_id=tenant)
    metadata = _parse_metadata_json(metadata_json)
    ingested = orchestrator.ingest_canary_hit(
        token=token,
        source_ip=source_ip,
        service=service,
        session_id=session_id,
        tenant_id=tenant,
        metadata=metadata,
    )
    payload = {
        "ingested": ingested,
        "replay": orchestrator.session_replay(session_id=ingested["session_id"], events_limit=50),
    }
    print(json.dumps(payload, indent=2))
    return 0


def cmd_canary_generate(
    config_path: Path,
    *,
    namespace: str,
    token_type: str,
    metadata_json: str | None,
) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    metadata = _parse_metadata_json(metadata_json)
    try:
        payload = orchestrator.generate_canary_token(
            namespace=namespace,
            token_type=token_type,
            metadata=metadata,
        )
    except ValueError as exc:
        print(str(exc))
        return 1
    print(json.dumps({"token": payload}, indent=2))
    return 0


def cmd_canary_types() -> int:
    types = canary_type_catalog()
    print(json.dumps({"types": types, "count": len(types)}, indent=2))
    return 0


def cmd_canary_tokens(
    config_path: Path,
    *,
    limit: int,
    namespace: str | None,
    token_type: str | None,
) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    payload = orchestrator.canary_tokens(
        limit=max(1, int(limit)),
        namespace=namespace,
        token_type=token_type,
    )
    print(json.dumps(payload, indent=2))
    return 0


def cmd_canary_hits(
    config_path: Path,
    *,
    limit: int,
    token_id: str | None,
) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    payload = orchestrator.canary_hits(limit=max(1, int(limit)), token_id=token_id)
    print(json.dumps(payload, indent=2))
    return 0


def cmd_alerts_test(
    config_path: Path,
    *,
    severity: str,
    title: str,
    summary: str,
    service: str,
    action: str,
    metadata_json: str | None,
) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    metadata = _parse_metadata_json(metadata_json)
    payload = orchestrator.alert_test(
        severity=severity,
        title=title,
        summary=summary,
        service=service,
        action=action,
        metadata=metadata,
    )
    print(json.dumps(payload, indent=2))
    return 0 if bool(payload.get("queued")) else 1


def cmd_alerts_routes(
    config_path: Path,
    *,
    severity: str,
    service: str,
    action: str,
    title: str,
    apply_throttle: bool,
) -> int:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    payload = orchestrator.alert_routes(
        severity=severity,
        service=service,
        action=action,
        title=title,
        apply_throttle=apply_throttle,
    )
    print(json.dumps(payload, indent=2))
    return 0


def cmd_doctor(config_path: Path, *, check_llm: bool) -> int:
    config = load_config(config_path)
    report = run_diagnostics(config, check_llm=check_llm)
    print(json.dumps(report, indent=2))
    return 0 if bool(report.get("ok")) else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "init":
        return cmd_init(args.config, args.force)
    if args.command == "up":
        return cmd_up(args.config, once=args.once, tenant=args.tenant)
    if args.command == "status":
        return cmd_status(args.config, tenant=args.tenant)
    if args.command == "logs":
        return cmd_logs(args.config)
    if args.command == "intel":
        return cmd_intel(
            args.config,
            limit=args.limit,
            events_per_session=args.events_per_session,
            bootstrap=args.bootstrap,
            tenant=args.tenant,
        )
    if args.command == "intel-history":
        return cmd_intel_history(
            args.config,
            limit=args.limit,
            report_id=args.report_id,
            sessions=args.sessions,
        )
    if args.command == "intel-handoff":
        return cmd_intel_handoff(
            args.config,
            limit=args.limit,
            events_per_session=args.events_per_session,
            report_id=args.report_id,
            max_techniques=args.max_techniques,
            max_sessions=args.max_sessions,
            output_format=args.output_format,
            output=args.output,
            bootstrap=args.bootstrap,
            tenant=args.tenant,
        )
    if args.command == "intel-coverage":
        return cmd_intel_coverage(
            args.config,
            limit=args.limit,
            events_per_session=args.events_per_session,
            bootstrap=args.bootstrap,
            tenant=args.tenant,
        )
    if args.command == "stix-export":
        return cmd_stix_export(
            args.config,
            limit=args.limit,
            events_per_session=args.events_per_session,
            report_id=args.report_id,
            output=args.output,
            bootstrap=args.bootstrap,
            tenant=args.tenant,
        )
    if args.command == "taxii-export":
        return cmd_taxii_export(
            args.config,
            limit=args.limit,
            events_per_session=args.events_per_session,
            report_id=args.report_id,
            collection_id=args.collection_id,
            manifest=args.manifest,
            object_id=args.object_id,
            output=args.output,
            bootstrap=args.bootstrap,
            tenant=args.tenant,
        )
    if args.command == "navigator-export":
        return cmd_navigator_export(
            args.config,
            limit=args.limit,
            events_per_session=args.events_per_session,
            report_id=args.report_id,
            name=args.name,
            domain=args.domain,
            output=args.output,
            bootstrap=args.bootstrap,
            tenant=args.tenant,
        )
    if args.command == "theater-history":
        return cmd_theater_history(
            args.config,
            limit=args.limit,
            session_id=args.session_id,
            session_ids=args.session_ids,
            action_type=args.action_type,
            output_format=args.output_format,
            output=args.output,
        )
    if args.command == "api":
        return cmd_api(
            args.config,
            host=args.host,
            port=args.port,
            start_services=args.start_services,
            tenant=args.tenant,
        )
    if args.command == "rotate":
        return cmd_rotate(
            args.config,
            tenant=args.tenant,
            start_services=args.start_services,
        )
    if args.command == "rotate-preview":
        return cmd_rotate_preview(
            args.config,
            tenant=args.tenant,
        )
    if args.command == "simulate-bandit":
        return cmd_simulate_bandit(
            args.config,
            window_hours=args.window_hours,
            history_limit=args.history_limit,
            baseline_algorithm=args.baseline_algorithm,
            baseline_exploration_floor=args.baseline_exploration_floor,
            candidate_algorithm=args.candidate_algorithm,
            candidate_exploration_floor=args.candidate_exploration_floor,
        )
    if args.command == "templates":
        return cmd_templates(
            args.config,
            tenant=args.tenant,
            no_threat_rotation=args.no_threat_rotation,
            all_tenants=args.all_tenants,
        )
    if args.command == "templates-validate":
        return cmd_templates_validate(
            args.config,
            tenant=args.tenant,
            all_tenants=args.all_tenants,
            strict_warnings=args.strict_warnings,
        )
    if args.command == "templates-diff":
        return cmd_templates_diff(
            args.config,
            left_tenant=args.left_tenant,
            right_tenant=args.right_tenant,
            all_pairs=args.all_pairs,
            no_threat_rotation=args.no_threat_rotation,
            fail_on_diff=args.fail_on_diff,
        )
    if args.command == "replay":
        return cmd_replay(
            args.config,
            session_id=args.session_id,
            events_limit=args.events_limit,
            bootstrap=args.bootstrap,
            tenant=args.tenant,
        )
    if args.command == "replay-compare":
        return cmd_replay_compare(
            args.config,
            left_session_id=args.left_session_id,
            right_session_id=args.right_session_id,
            events_limit=args.events_limit,
            bootstrap=args.bootstrap,
            tenant=args.tenant,
        )
    if args.command == "canary-hit":
        return cmd_canary_hit(
            args.config,
            token=args.token,
            source_ip=args.source_ip,
            service=args.service,
            session_id=args.session_id,
            metadata_json=args.metadata_json,
            bootstrap=args.bootstrap,
            tenant=args.tenant,
        )
    if args.command == "canary-generate":
        return cmd_canary_generate(
            args.config,
            namespace=args.namespace,
            token_type=args.token_type,
            metadata_json=args.metadata_json,
        )
    if args.command == "canary-types":
        return cmd_canary_types()
    if args.command == "canary-tokens":
        return cmd_canary_tokens(
            args.config,
            limit=args.limit,
            namespace=args.namespace,
            token_type=args.token_type,
        )
    if args.command == "canary-hits":
        return cmd_canary_hits(
            args.config,
            limit=args.limit,
            token_id=args.token_id,
        )
    if args.command == "alerts-test":
        return cmd_alerts_test(
            args.config,
            severity=args.severity,
            title=args.title,
            summary=args.summary,
            service=args.service,
            action=args.action,
            metadata_json=args.metadata_json,
        )
    if args.command == "alerts-routes":
        return cmd_alerts_routes(
            args.config,
            severity=args.severity,
            service=args.service,
            action=args.action,
            title=args.title,
            apply_throttle=args.apply_throttle,
        )
    if args.command == "doctor":
        return cmd_doctor(
            args.config,
            check_llm=args.check_llm,
        )

    parser.error(f"unknown command: {args.command}")
    return 2
