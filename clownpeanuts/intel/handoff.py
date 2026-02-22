"""SOC handoff report rendering utilities."""

from __future__ import annotations

import csv
from datetime import UTC, datetime
import io
import json
from typing import Any


def build_soc_handoff(
    report: dict[str, Any],
    *,
    max_techniques: int = 5,
    max_sessions: int = 5,
) -> dict[str, Any]:
    totals_raw = report.get("totals", {})
    totals = totals_raw if isinstance(totals_raw, dict) else {}

    techniques_raw = report.get("techniques", [])
    techniques = techniques_raw if isinstance(techniques_raw, list) else []
    top_techniques: list[dict[str, Any]] = []
    for item in techniques[: max(0, int(max_techniques))]:
        if isinstance(item, dict):
            top_techniques.append(
                {
                    "technique_id": str(item.get("technique_id", "")).strip(),
                    "technique_name": str(item.get("technique_name", "")).strip(),
                    "count": int(item.get("count", 0) or 0),
                }
            )

    sessions_raw = report.get("sessions", [])
    sessions = sessions_raw if isinstance(sessions_raw, list) else []
    top_sessions: list[dict[str, Any]] = []
    for item in sessions[: max(0, int(max_sessions))]:
        if isinstance(item, dict):
            engagement_raw = item.get("engagement_score", 0.0)
            if isinstance(engagement_raw, dict):
                engagement_raw = engagement_raw.get("score", 0.0)
            try:
                engagement_score = float(engagement_raw or 0.0)
            except (TypeError, ValueError):
                engagement_score = 0.0
            classification_raw = item.get("classification", "unknown")
            if isinstance(classification_raw, dict):
                classification_raw = classification_raw.get("label", "unknown")
            top_sessions.append(
                {
                    "session_id": str(item.get("session_id", "")).strip(),
                    "source_ip": str(item.get("source_ip", "")).strip(),
                    "event_count": int(item.get("event_count", 0) or 0),
                    "engagement_score": engagement_score,
                    "classification": str(classification_raw).strip() or "unknown",
                }
            )

    kill_chain_raw = report.get("kill_chain", {})
    kill_chain = kill_chain_raw if isinstance(kill_chain_raw, dict) else {}
    stage_counts_raw = kill_chain.get("stage_counts", [])
    stage_counts = stage_counts_raw if isinstance(stage_counts_raw, list) else []
    top_stage = "none"
    top_stage_count = 0
    if stage_counts:
        for item in stage_counts:
            if not isinstance(item, dict):
                continue
            count = int(item.get("count", 0) or 0)
            if count > top_stage_count:
                top_stage_count = count
                top_stage = str(item.get("stage", "none")).strip() or "none"

    generated_at = datetime.now(UTC).isoformat(timespec="seconds")
    summary = {
        "sessions": int(totals.get("sessions", 0) or 0),
        "events": int(totals.get("events", 0) or 0),
        "canary_hits": int(totals.get("canary_hits", 0) or 0),
        "engagement_score_avg": float(totals.get("engagement_score_avg", 0.0) or 0.0),
        "mitre_coverage_percent": float(totals.get("mitre_coverage_percent", 0.0) or 0.0),
        "top_kill_chain_stage": top_stage,
        "top_kill_chain_stage_count": top_stage_count,
    }

    markdown_lines = [
        f"# ClownPeanuts SOC Handoff ({generated_at})",
        "",
        "## Executive Snapshot",
        f"- Sessions observed: {summary['sessions']}",
        f"- Events observed: {summary['events']}",
        f"- Canary hits: {summary['canary_hits']}",
        f"- Avg engagement score: {summary['engagement_score_avg']:.2f}",
        f"- ATT&CK coverage: {summary['mitre_coverage_percent']:.1f}%",
        f"- Dominant kill-chain stage: {summary['top_kill_chain_stage']} ({summary['top_kill_chain_stage_count']})",
        "",
        "## Top Techniques",
    ]
    if top_techniques:
        for item in top_techniques:
            name = item["technique_name"] or "unknown-technique"
            tech_id = item["technique_id"] or "n/a"
            markdown_lines.append(f"- {tech_id} {name}: {item['count']}")
    else:
        markdown_lines.append("- None observed")

    markdown_lines.append("")
    markdown_lines.append("## Priority Sessions")
    if top_sessions:
        for item in top_sessions:
            markdown_lines.append(
                f"- {item['session_id']} ({item['source_ip']}), "
                f"events={item['event_count']}, score={item['engagement_score']:.2f}, "
                f"classification={item['classification']}"
            )
    else:
        markdown_lines.append("- None available")

    csv_output = io.StringIO()
    fieldnames = [
        "record_type",
        "generated_at",
        "sessions",
        "events",
        "canary_hits",
        "engagement_score_avg",
        "mitre_coverage_percent",
        "top_kill_chain_stage",
        "top_kill_chain_stage_count",
        "technique_id",
        "technique_name",
        "technique_count",
        "session_id",
        "source_ip",
        "session_event_count",
        "session_engagement_score",
        "session_classification",
    ]
    writer = csv.DictWriter(csv_output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerow(
        {
            "record_type": "summary",
            "generated_at": generated_at,
            "sessions": summary["sessions"],
            "events": summary["events"],
            "canary_hits": summary["canary_hits"],
            "engagement_score_avg": summary["engagement_score_avg"],
            "mitre_coverage_percent": summary["mitre_coverage_percent"],
            "top_kill_chain_stage": summary["top_kill_chain_stage"],
            "top_kill_chain_stage_count": summary["top_kill_chain_stage_count"],
        }
    )
    for item in top_techniques:
        writer.writerow(
            {
                "record_type": "technique",
                "generated_at": generated_at,
                "technique_id": item.get("technique_id", ""),
                "technique_name": item.get("technique_name", ""),
                "technique_count": int(item.get("count", 0) or 0),
            }
        )
    for item in top_sessions:
        writer.writerow(
            {
                "record_type": "session",
                "generated_at": generated_at,
                "session_id": item.get("session_id", ""),
                "source_ip": item.get("source_ip", ""),
                "session_event_count": int(item.get("event_count", 0) or 0),
                "session_engagement_score": float(item.get("engagement_score", 0.0) or 0.0),
                "session_classification": item.get("classification", ""),
            }
        )
    tsv_output = io.StringIO()
    tsv_writer = csv.DictWriter(tsv_output, fieldnames=fieldnames, delimiter="\t")
    tsv_writer.writeheader()
    tsv_writer.writerow(
        {
            "record_type": "summary",
            "generated_at": generated_at,
            "sessions": summary["sessions"],
            "events": summary["events"],
            "canary_hits": summary["canary_hits"],
            "engagement_score_avg": summary["engagement_score_avg"],
            "mitre_coverage_percent": summary["mitre_coverage_percent"],
            "top_kill_chain_stage": summary["top_kill_chain_stage"],
            "top_kill_chain_stage_count": summary["top_kill_chain_stage_count"],
        }
    )
    for item in top_techniques:
        tsv_writer.writerow(
            {
                "record_type": "technique",
                "generated_at": generated_at,
                "technique_id": item.get("technique_id", ""),
                "technique_name": item.get("technique_name", ""),
                "technique_count": int(item.get("count", 0) or 0),
            }
        )
    for item in top_sessions:
        tsv_writer.writerow(
            {
                "record_type": "session",
                "generated_at": generated_at,
                "session_id": item.get("session_id", ""),
                "source_ip": item.get("source_ip", ""),
                "session_event_count": int(item.get("event_count", 0) or 0),
                "session_engagement_score": float(item.get("engagement_score", 0.0) or 0.0),
                "session_classification": item.get("classification", ""),
            }
        )

    ndjson_records: list[dict[str, Any]] = [
        {
            "record_type": "summary",
            "generated_at": generated_at,
            **summary,
        }
    ]
    for item in top_techniques:
        ndjson_records.append(
            {
                "record_type": "technique",
                "generated_at": generated_at,
                "technique_id": item.get("technique_id", ""),
                "technique_name": item.get("technique_name", ""),
                "technique_count": int(item.get("count", 0) or 0),
            }
        )
    for item in top_sessions:
        ndjson_records.append(
            {
                "record_type": "session",
                "generated_at": generated_at,
                "session_id": item.get("session_id", ""),
                "source_ip": item.get("source_ip", ""),
                "session_event_count": int(item.get("event_count", 0) or 0),
                "session_engagement_score": float(item.get("engagement_score", 0.0) or 0.0),
                "session_classification": item.get("classification", ""),
            }
        )
    ndjson_payload = "\n".join(
        json.dumps(record, separators=(",", ":"), ensure_ascii=True)
        for record in ndjson_records
    ).strip()
    cef_records: list[str] = []
    summary_severity = max(0, min(10, int(round(float(summary["engagement_score_avg"]) / 10.0))))
    cef_records.append(
        _build_cef_line(
            signature="cp-handoff-summary",
            name="SOC Handoff Summary",
            severity=summary_severity,
            extension={
                "rt": generated_at,
                "cpSessions": summary["sessions"],
                "cpEvents": summary["events"],
                "cpCanaryHits": summary["canary_hits"],
                "cpEngagementAvg": f"{float(summary['engagement_score_avg']):.2f}",
                "cpMitreCoverage": f"{float(summary['mitre_coverage_percent']):.2f}",
                "cpTopStage": summary["top_kill_chain_stage"],
                "cpTopStageCount": summary["top_kill_chain_stage_count"],
            },
        )
    )
    for item in top_techniques:
        technique_id = str(item.get("technique_id", "")).strip() or "cp-technique"
        technique_name = str(item.get("technique_name", "")).strip() or technique_id
        count = max(0, int(item.get("count", 0) or 0))
        cef_records.append(
            _build_cef_line(
                signature=technique_id,
                name=f"Technique {technique_name}",
                severity=max(1, min(10, count)),
                extension={
                    "rt": generated_at,
                    "externalId": technique_id,
                    "msg": technique_name,
                    "cnt": count,
                },
            )
        )
    for item in top_sessions:
        session_id = str(item.get("session_id", "")).strip() or "unknown-session"
        source_ip = str(item.get("source_ip", "")).strip() or "0.0.0.0"
        event_count = max(0, int(item.get("event_count", 0) or 0))
        engagement_score = max(0.0, float(item.get("engagement_score", 0.0) or 0.0))
        severity = max(0, min(10, int(round(engagement_score / 10.0))))
        cef_records.append(
            _build_cef_line(
                signature="cp-priority-session",
                name="Priority Session",
                severity=severity,
                extension={
                    "rt": generated_at,
                    "src": source_ip,
                    "suid": session_id,
                    "cpEventCount": event_count,
                    "cpEngagementScore": f"{engagement_score:.2f}",
                    "cpClassification": str(item.get("classification", "")).strip() or "unknown",
                },
            )
        )
    cef_payload = "\n".join(item for item in cef_records if item).strip()
    leef_records: list[str] = []
    leef_records.append(
        _build_leef_line(
            event_id="cp-handoff-summary",
            extension={
                "devTime": generated_at,
                "cpSessions": summary["sessions"],
                "cpEvents": summary["events"],
                "cpCanaryHits": summary["canary_hits"],
                "cpEngagementAvg": f"{float(summary['engagement_score_avg']):.2f}",
                "cpMitreCoverage": f"{float(summary['mitre_coverage_percent']):.2f}",
                "cpTopStage": summary["top_kill_chain_stage"],
                "cpTopStageCount": summary["top_kill_chain_stage_count"],
            },
        )
    )
    for item in top_techniques:
        technique_id = str(item.get("technique_id", "")).strip() or "cp-technique"
        technique_name = str(item.get("technique_name", "")).strip() or technique_id
        count = max(0, int(item.get("count", 0) or 0))
        leef_records.append(
            _build_leef_line(
                event_id=technique_id,
                extension={
                    "devTime": generated_at,
                    "externalId": technique_id,
                    "msg": technique_name,
                    "cnt": count,
                },
            )
        )
    for item in top_sessions:
        session_id = str(item.get("session_id", "")).strip() or "unknown-session"
        source_ip = str(item.get("source_ip", "")).strip() or "0.0.0.0"
        event_count = max(0, int(item.get("event_count", 0) or 0))
        engagement_score = max(0.0, float(item.get("engagement_score", 0.0) or 0.0))
        leef_records.append(
            _build_leef_line(
                event_id="cp-priority-session",
                extension={
                    "devTime": generated_at,
                    "src": source_ip,
                    "sessionId": session_id,
                    "cpEventCount": event_count,
                    "cpEngagementScore": f"{engagement_score:.2f}",
                    "cpClassification": str(item.get("classification", "")).strip() or "unknown",
                },
            )
        )
    leef_payload = "\n".join(item for item in leef_records if item).strip()
    syslog_records: list[str] = []
    syslog_records.append(
        _build_syslog_line(
            timestamp=generated_at,
            event_id="cp-handoff-summary",
            message=(
                f"sessions={summary['sessions']} events={summary['events']} "
                f"canary_hits={summary['canary_hits']} engagement_avg={float(summary['engagement_score_avg']):.2f} "
                f"mitre_coverage={float(summary['mitre_coverage_percent']):.2f} "
                f"top_stage={summary['top_kill_chain_stage']} top_stage_count={summary['top_kill_chain_stage_count']}"
            ),
            severity=5,
        )
    )
    for item in top_techniques:
        technique_id = str(item.get("technique_id", "")).strip() or "cp-technique"
        technique_name = str(item.get("technique_name", "")).strip() or technique_id
        count = max(0, int(item.get("count", 0) or 0))
        syslog_records.append(
            _build_syslog_line(
                timestamp=generated_at,
                event_id=technique_id,
                message=f"record=technique technique_id={technique_id} name={technique_name} count={count}",
                severity=5,
            )
        )
    for item in top_sessions:
        session_id = str(item.get("session_id", "")).strip() or "unknown-session"
        source_ip = str(item.get("source_ip", "")).strip() or "0.0.0.0"
        event_count = max(0, int(item.get("event_count", 0) or 0))
        engagement_score = max(0.0, float(item.get("engagement_score", 0.0) or 0.0))
        syslog_records.append(
            _build_syslog_line(
                timestamp=generated_at,
                event_id="cp-priority-session",
                message=(
                    f"record=session session_id={session_id} src={source_ip} "
                    f"event_count={event_count} engagement_score={engagement_score:.2f} "
                    f"classification={str(item.get('classification', '')).strip() or 'unknown'}"
                ),
                severity=5,
            )
        )
    syslog_payload = "\n".join(item for item in syslog_records if item).strip()
    logfmt_records: list[str] = []
    logfmt_records.append(
        _build_logfmt_line(
            {
                "record": "summary",
                "generated_at": generated_at,
                "sessions": summary["sessions"],
                "events": summary["events"],
                "canary_hits": summary["canary_hits"],
                "engagement_score_avg": f"{float(summary['engagement_score_avg']):.2f}",
                "mitre_coverage_percent": f"{float(summary['mitre_coverage_percent']):.2f}",
                "top_kill_chain_stage": summary["top_kill_chain_stage"],
                "top_kill_chain_stage_count": summary["top_kill_chain_stage_count"],
            }
        )
    )
    for item in top_techniques:
        technique_id = str(item.get("technique_id", "")).strip() or "cp-technique"
        technique_name = str(item.get("technique_name", "")).strip() or technique_id
        count = max(0, int(item.get("count", 0) or 0))
        logfmt_records.append(
            _build_logfmt_line(
                {
                    "record": "technique",
                    "generated_at": generated_at,
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "count": count,
                }
            )
        )
    for item in top_sessions:
        session_id = str(item.get("session_id", "")).strip() or "unknown-session"
        source_ip = str(item.get("source_ip", "")).strip() or "0.0.0.0"
        event_count = max(0, int(item.get("event_count", 0) or 0))
        engagement_score = max(0.0, float(item.get("engagement_score", 0.0) or 0.0))
        classification = str(item.get("classification", "")).strip() or "unknown"
        logfmt_records.append(
            _build_logfmt_line(
                {
                    "record": "session",
                    "generated_at": generated_at,
                    "session_id": session_id,
                    "source_ip": source_ip,
                    "event_count": event_count,
                    "engagement_score": f"{engagement_score:.2f}",
                    "classification": classification,
                }
            )
        )
    logfmt_payload = "\n".join(item for item in logfmt_records if item).strip()

    return {
        "generated_at": generated_at,
        "summary": summary,
        "top_techniques": top_techniques,
        "priority_sessions": top_sessions,
        "markdown": "\n".join(markdown_lines).strip(),
        "csv": csv_output.getvalue().strip(),
        "tsv": tsv_output.getvalue().strip(),
        "ndjson": ndjson_payload,
        "jsonl": ndjson_payload,
        "cef": cef_payload,
        "leef": leef_payload,
        "syslog": syslog_payload,
        "logfmt": logfmt_payload,
    }


def _build_cef_line(
    *,
    signature: str,
    name: str,
    severity: int,
    extension: dict[str, Any],
) -> str:
    extension_payload = " ".join(
        f"{str(key).strip()}={_cef_escape(str(value))}"
        for key, value in extension.items()
        if str(key).strip() and str(value).strip()
    ).strip()
    safe_signature = _cef_escape(signature.strip() or "cp")
    safe_name = _cef_escape(name.strip() or "ClownPeanuts Event")
    safe_severity = max(0, min(10, int(severity)))
    return (
        "CEF:0|ClownPeanuts|SOC Handoff|0.1.0|"
        f"{safe_signature}|{safe_name}|{safe_severity}|{extension_payload}"
    ).rstrip()


def _cef_escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("=", "\\=")
        .replace("\r", " ")
        .replace("\n", "\\n")
    )


def _build_leef_line(
    *,
    event_id: str,
    extension: dict[str, Any],
) -> str:
    extension_payload = "\t".join(
        f"{str(key).strip()}={_leef_escape(str(value))}"
        for key, value in extension.items()
        if str(key).strip() and str(value).strip()
    ).strip()
    safe_event_id = _leef_escape(event_id.strip() or "cp")
    return f"LEEF:2.0|ClownPeanuts|SOC Handoff|0.1.0|{safe_event_id}\t{extension_payload}".rstrip()


def _leef_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\t", "\\t").replace("\r", " ").replace("\n", "\\n")


def _build_syslog_line(
    *,
    timestamp: str,
    event_id: str,
    message: str,
    severity: int = 5,
) -> str:
    # local0 facility keeps this in a dedicated app stream for downstream syslog routing.
    normalized_severity = max(0, min(7, int(severity)))
    priority = (16 * 8) + normalized_severity
    safe_event_id = "".join(ch for ch in event_id if ch.isalnum() or ch in {"-", "_", "."}) or "cp"
    safe_message = str(message).replace("\r", " ").replace("\n", "\\n").strip() or "event"
    return f"<{priority}>1 {timestamp} clownpeanuts intel-handoff - {safe_event_id} - {safe_message}"


def _build_logfmt_line(values: dict[str, Any]) -> str:
    parts: list[str] = []
    for key, value in values.items():
        token = str(key).strip()
        if not token:
            continue
        parts.append(f"{token}={_logfmt_escape(value)}")
    return " ".join(parts).strip()


def _logfmt_escape(value: Any) -> str:
    raw = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\r", " ").replace("\n", "\\n")
    if raw == "" or any(ch.isspace() for ch in raw) or "=" in raw:
        return f'"{raw}"'
    return raw
