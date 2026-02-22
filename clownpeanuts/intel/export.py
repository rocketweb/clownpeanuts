"""Threat intelligence export helpers."""

from __future__ import annotations

import csv
from datetime import UTC, datetime
import io
import ipaddress
import json
from typing import Any
from uuid import NAMESPACE_URL, uuid5


def build_stix_bundle(report: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    sessions = report.get("sessions", [])
    if not isinstance(sessions, list):
        sessions = []
    techniques = report.get("techniques", [])
    if not isinstance(techniques, list):
        techniques = []

    objects: list[dict[str, Any]] = []
    source_refs: list[str] = []
    for session in sessions:
        if not isinstance(session, dict):
            continue
        source_ip = str(session.get("source_ip", "")).strip() or "unknown"
        normalized_ip = _safe_stix_ip(source_ip)
        object_type = "ipv6-addr" if ":" in normalized_ip else "ipv4-addr"
        sid = str(session.get("session_id", "")).strip() or "unknown"
        indicator_id = f"indicator--{_stable_id(f'indicator:{source_ip}:{sid}')}"
        source_refs.append(indicator_id)
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": now,
                "modified": now,
                "name": f"Honeypot Session {sid}",
                "description": f"Observed source {normalized_ip} engaging deception services.",
                "pattern_type": "stix",
                "pattern": f"[{object_type}:value = '{normalized_ip}']",
                "valid_from": now,
                "labels": ["honeypot", "clownpeanuts"],
            }
        )

    for technique in techniques:
        if not isinstance(technique, dict):
            continue
        technique_id = str(technique.get("technique_id", "T0000"))
        name = str(technique.get("technique_name", "Unknown Technique"))
        attack_pattern_id = f"attack-pattern--{_stable_id(f'attack:{technique_id}')}"
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": attack_pattern_id,
                "created": now,
                "modified": now,
                "name": name,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique_id,
                    }
                ],
                "x_clownpeanuts_count": int(technique.get("count", 0) or 0),
                "x_clownpeanuts_confidence": float(technique.get("confidence", 0.0) or 0.0),
            }
        )
        if source_refs:
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{_stable_id(f'rel:{attack_pattern_id}:{source_refs[0]}')}",
                    "created": now,
                    "modified": now,
                    "relationship_type": "indicates",
                    "source_ref": source_refs[0],
                    "target_ref": attack_pattern_id,
                    "description": "Observed in ClownPeanuts honeypot telemetry.",
                }
            )

    return {"type": "bundle", "id": f"bundle--{_stable_id(f'bundle:{now}')}", "objects": objects}


def build_attack_navigator_layer(
    report: dict[str, Any],
    *,
    layer_name: str = "ClownPeanuts ATT&CK Observations",
    domain: str = "enterprise-attack",
) -> dict[str, Any]:
    generated_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    techniques_raw = report.get("techniques", [])
    if not isinstance(techniques_raw, list):
        techniques_raw = []
    totals_raw = report.get("totals", {})
    totals = totals_raw if isinstance(totals_raw, dict) else {}
    sessions = max(0, int(totals.get("sessions", 0) or 0))
    events = max(0, int(totals.get("events", 0) or 0))
    coverage_percent = max(0.0, float(totals.get("mitre_coverage_percent", 0.0) or 0.0))

    aggregated: dict[str, dict[str, Any]] = {}
    for item in techniques_raw:
        if not isinstance(item, dict):
            continue
        technique_id = str(item.get("technique_id", "")).strip().upper()
        if not technique_id.startswith("T"):
            continue
        technique_name = str(item.get("technique_name", "")).strip()
        count = max(0, int(item.get("count", 0) or 0))
        confidence = max(0.0, min(1.0, float(item.get("confidence", 0.0) or 0.0)))

        existing = aggregated.get(technique_id)
        if existing is None:
            aggregated[technique_id] = {
                "technique_id": technique_id,
                "technique_name": technique_name,
                "count": count,
                "confidence": confidence,
            }
            continue
        existing["count"] = int(existing.get("count", 0) or 0) + count
        existing["confidence"] = max(float(existing.get("confidence", 0.0) or 0.0), confidence)
        if not str(existing.get("technique_name", "")).strip() and technique_name:
            existing["technique_name"] = technique_name

    ordered = sorted(
        aggregated.values(),
        key=lambda item: (-int(item.get("count", 0) or 0), str(item.get("technique_id", ""))),
    )
    max_count = 1
    if ordered:
        max_count = max(1, max(int(item.get("count", 0) or 0) for item in ordered))

    layer_techniques: list[dict[str, Any]] = []
    for item in ordered:
        technique_id = str(item.get("technique_id", "")).strip().upper()
        technique_name = str(item.get("technique_name", "")).strip()
        count = max(0, int(item.get("count", 0) or 0))
        confidence = max(0.0, min(1.0, float(item.get("confidence", 0.0) or 0.0)))
        label = technique_name or technique_id
        layer_techniques.append(
            {
                "techniqueID": technique_id,
                "score": count,
                "enabled": True,
                "color": _navigator_color(confidence),
                "comment": f"{label} | events={count} | confidence={confidence:.2f}",
                "metadata": [
                    {"name": "technique_name", "value": label},
                    {"name": "event_count", "value": str(count)},
                    {"name": "confidence", "value": f"{confidence:.2f}"},
                ],
            }
        )

    return {
        "name": layer_name.strip() or "ClownPeanuts ATT&CK Observations",
        "description": (
            "Observed ATT&CK techniques from ClownPeanuts telemetry. "
            f"Sessions={sessions}, Events={events}, Coverage={coverage_percent:.2f}%."
        ),
        "domain": domain.strip() or "enterprise-attack",
        "versions": {
            "attack": "16",
            "navigator": "4.9.1",
            "layer": "4.5",
        },
        "filters": {"platforms": ["Linux", "Windows", "macOS", "Containers", "Network"]},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "sum",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "selectTechniquesAcrossTactics": True,
        "gradient": {
            "colors": ["#cfe2ff", "#7aa6ff", "#2f78ff", "#0e4fbf"],
            "minValue": 0,
            "maxValue": max_count,
        },
        "legendItems": [
            {"label": "Observed in ClownPeanuts telemetry", "color": "#0e4fbf"},
        ],
        "metadata": [
            {"name": "generator", "value": "clownpeanuts"},
            {"name": "generated_at", "value": generated_at},
            {"name": "session_count", "value": str(sessions)},
            {"name": "event_count", "value": str(events)},
            {"name": "coverage_percent", "value": f"{coverage_percent:.2f}"},
        ],
        "techniques": layer_techniques,
    }


def build_taxii_manifest(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    objects = bundle.get("objects", [])
    if not isinstance(objects, list):
        objects = []
    manifest: list[dict[str, Any]] = []
    for item in objects:
        if not isinstance(item, dict):
            continue
        object_id = str(item.get("id", "")).strip()
        if not object_id:
            continue
        version = str(item.get("modified", item.get("created", ""))).strip()
        if not version:
            version = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        manifest.append(
            {
                "id": object_id,
                "date_added": version,
                "version": version,
                "media_type": "application/stix+json;version=2.1",
            }
        )
    return manifest


def find_stix_object(bundle: dict[str, Any], *, object_id: str) -> dict[str, Any] | None:
    target = object_id.strip()
    if not target:
        return None
    objects = bundle.get("objects", [])
    if not isinstance(objects, list):
        return None
    for item in objects:
        if not isinstance(item, dict):
            continue
        if str(item.get("id", "")).strip() == target:
            return item
    return None


def build_theater_action_export(actions_payload: dict[str, Any]) -> dict[str, Any]:
    actions = actions_payload.get("actions", [])
    if not isinstance(actions, list):
        actions = []
    exported_actions: list[dict[str, Any]] = []
    for item in actions:
        if not isinstance(item, dict):
            continue
        payload = item.get("payload", {})
        if not isinstance(payload, dict):
            payload = {}
        metadata = item.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        exported_actions.append(
            {
                "row_id": int(item.get("row_id", 0) or 0),
                "created_at": str(item.get("created_at", "")),
                "action_type": str(item.get("action_type", "")),
                "session_id": str(item.get("session_id", "")),
                "recommendation_id": str(item.get("recommendation_id", "")),
                "actor": str(item.get("actor", "")),
                "payload": payload,
                "metadata": metadata,
            }
        )
    generated_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "schema": "clownpeanuts.theater_actions.v1",
        "generated_at": generated_at,
        "count": len(exported_actions),
        "actions": exported_actions,
    }


def render_theater_action_export(payload: dict[str, Any], *, output_format: str) -> str:
    def _logfmt_quote(value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace("\"", "\\\"")
        return f"\"{escaped}\""

    def _syslog_escape(value: str) -> str:
        return value.replace("\r", " ").replace("\n", "\\n")

    def _syslog_event_id(value: str) -> str:
        safe = "".join(ch for ch in value if ch.isalnum() or ch in {"-", "_", "."})
        return safe or "theater-action"

    def _cef_escape(value: str) -> str:
        return (
            value.replace("\\", "\\\\")
            .replace("|", "\\|")
            .replace("=", "\\=")
            .replace("\r", " ")
            .replace("\n", "\\n")
        )

    def _leef_escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace("\t", "\\t").replace("\r", " ").replace("\n", "\\n")

    normalized_format = output_format.strip().lower()
    if normalized_format in {"ndjson", "jsonl"}:
        schema = str(payload.get("schema", "clownpeanuts.theater_actions.v1"))
        generated_at = str(payload.get("generated_at", ""))
        actions = payload.get("actions", [])
        if not isinstance(actions, list):
            actions = []
        records: list[str] = []
        for item in actions:
            if not isinstance(item, dict):
                continue
            record = {
                "schema": schema,
                "generated_at": generated_at,
                "record_type": "theater_action",
                "action": item,
            }
            records.append(json.dumps(record, separators=(",", ":"), ensure_ascii=True))
        return "\n".join(records).strip()
    if normalized_format in {"csv", "tsv"}:
        actions = payload.get("actions", [])
        if not isinstance(actions, list):
            actions = []
        delimiter = "," if normalized_format == "csv" else "\t"
        fieldnames = [
            "row_id",
            "created_at",
            "action_type",
            "session_id",
            "recommendation_id",
            "actor",
            "payload_json",
            "metadata_json",
        ]
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames, delimiter=delimiter, lineterminator="\n")
        writer.writeheader()
        for item in actions:
            if not isinstance(item, dict):
                continue
            payload_value = item.get("payload", {})
            if not isinstance(payload_value, dict):
                payload_value = {}
            metadata_value = item.get("metadata", {})
            if not isinstance(metadata_value, dict):
                metadata_value = {}
            writer.writerow(
                {
                    "row_id": int(item.get("row_id", 0) or 0),
                    "created_at": str(item.get("created_at", "")),
                    "action_type": str(item.get("action_type", "")),
                    "session_id": str(item.get("session_id", "")),
                    "recommendation_id": str(item.get("recommendation_id", "")),
                    "actor": str(item.get("actor", "")),
                    "payload_json": json.dumps(payload_value, separators=(",", ":"), ensure_ascii=True),
                    "metadata_json": json.dumps(metadata_value, separators=(",", ":"), ensure_ascii=True),
                }
            )
        return output.getvalue().strip()
    if normalized_format == "logfmt":
        schema = str(payload.get("schema", "clownpeanuts.theater_actions.v1"))
        generated_at = str(payload.get("generated_at", ""))
        actions = payload.get("actions", [])
        if not isinstance(actions, list):
            actions = []
        records: list[str] = []
        for item in actions:
            if not isinstance(item, dict):
                continue
            payload_value = item.get("payload", {})
            if not isinstance(payload_value, dict):
                payload_value = {}
            metadata_value = item.get("metadata", {})
            if not isinstance(metadata_value, dict):
                metadata_value = {}
            parts = [
                f"schema={_logfmt_quote(schema)}",
                f"generated_at={_logfmt_quote(generated_at)}",
                "record_type=theater_action",
                f"row_id={int(item.get('row_id', 0) or 0)}",
                f"created_at={_logfmt_quote(str(item.get('created_at', '')))}",
                f"action_type={_logfmt_quote(str(item.get('action_type', '')))}",
                f"session_id={_logfmt_quote(str(item.get('session_id', '')))}",
                f"recommendation_id={_logfmt_quote(str(item.get('recommendation_id', '')))}",
                f"actor={_logfmt_quote(str(item.get('actor', '')))}",
                f"payload_json={_logfmt_quote(json.dumps(payload_value, separators=(',', ':'), ensure_ascii=True))}",
                f"metadata_json={_logfmt_quote(json.dumps(metadata_value, separators=(',', ':'), ensure_ascii=True))}",
            ]
            records.append(" ".join(parts))
        return "\n".join(records).strip()
    if normalized_format == "cef":
        schema = str(payload.get("schema", "clownpeanuts.theater_actions.v1"))
        generated_at = str(payload.get("generated_at", ""))
        actions = payload.get("actions", [])
        if not isinstance(actions, list):
            actions = []
        records: list[str] = []
        for item in actions:
            if not isinstance(item, dict):
                continue
            payload_value = item.get("payload", {})
            if not isinstance(payload_value, dict):
                payload_value = {}
            metadata_value = item.get("metadata", {})
            if not isinstance(metadata_value, dict):
                metadata_value = {}
            action_type = str(item.get("action_type", "")).strip() or "theater_action"
            signature = _cef_escape(action_type)
            name = _cef_escape(f"Theater Action {action_type}")
            extension = {
                "schema": schema,
                "generated_at": generated_at,
                "row_id": int(item.get("row_id", 0) or 0),
                "created_at": str(item.get("created_at", "")),
                "action_type": action_type,
                "session_id": str(item.get("session_id", "")),
                "recommendation_id": str(item.get("recommendation_id", "")),
                "actor": str(item.get("actor", "")),
                "payload_json": json.dumps(payload_value, separators=(",", ":"), ensure_ascii=True),
                "metadata_json": json.dumps(metadata_value, separators=(",", ":"), ensure_ascii=True),
            }
            extension_payload = " ".join(
                f"{key}={_cef_escape(str(value))}"
                for key, value in extension.items()
                if str(key).strip() and str(value).strip()
            ).strip()
            records.append(f"CEF:0|ClownPeanuts|Theater Actions|0.1.0|{signature}|{name}|5|{extension_payload}".rstrip())
        return "\n".join(records).strip()
    if normalized_format == "leef":
        schema = str(payload.get("schema", "clownpeanuts.theater_actions.v1"))
        generated_at = str(payload.get("generated_at", ""))
        actions = payload.get("actions", [])
        if not isinstance(actions, list):
            actions = []
        records: list[str] = []
        for item in actions:
            if not isinstance(item, dict):
                continue
            payload_value = item.get("payload", {})
            if not isinstance(payload_value, dict):
                payload_value = {}
            metadata_value = item.get("metadata", {})
            if not isinstance(metadata_value, dict):
                metadata_value = {}
            action_type = str(item.get("action_type", "")).strip() or "theater_action"
            extension = {
                "schema": schema,
                "generated_at": generated_at,
                "row_id": int(item.get("row_id", 0) or 0),
                "created_at": str(item.get("created_at", "")),
                "action_type": action_type,
                "session_id": str(item.get("session_id", "")),
                "recommendation_id": str(item.get("recommendation_id", "")),
                "actor": str(item.get("actor", "")),
                "payload_json": json.dumps(payload_value, separators=(",", ":"), ensure_ascii=True),
                "metadata_json": json.dumps(metadata_value, separators=(",", ":"), ensure_ascii=True),
            }
            extension_payload = "\t".join(
                f"{key}={_leef_escape(str(value))}"
                for key, value in extension.items()
                if str(key).strip() and str(value).strip()
            ).strip()
            event_id = _leef_escape(action_type)
            records.append(f"LEEF:2.0|ClownPeanuts|Theater Actions|0.1.0|{event_id}\t{extension_payload}".rstrip())
        return "\n".join(records).strip()
    if normalized_format == "syslog":
        schema = str(payload.get("schema", "clownpeanuts.theater_actions.v1"))
        generated_at_raw = str(payload.get("generated_at", "")).strip()
        generated_at = (
            generated_at_raw
            or datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )
        actions = payload.get("actions", [])
        if not isinstance(actions, list):
            actions = []
        records: list[str] = []
        priority = (16 * 8) + 5
        for item in actions:
            if not isinstance(item, dict):
                continue
            payload_value = item.get("payload", {})
            if not isinstance(payload_value, dict):
                payload_value = {}
            metadata_value = item.get("metadata", {})
            if not isinstance(metadata_value, dict):
                metadata_value = {}
            action_type = str(item.get("action_type", "")).strip() or "theater_action"
            message = " ".join(
                [
                    "record=theater_action",
                    f"schema={_logfmt_quote(_syslog_escape(schema))}",
                    f"generated_at={_logfmt_quote(_syslog_escape(generated_at))}",
                    f"row_id={int(item.get('row_id', 0) or 0)}",
                    f"created_at={_logfmt_quote(_syslog_escape(str(item.get('created_at', ''))))}",
                    f"action_type={_logfmt_quote(_syslog_escape(action_type))}",
                    f"session_id={_logfmt_quote(_syslog_escape(str(item.get('session_id', ''))))}",
                    f"recommendation_id={_logfmt_quote(_syslog_escape(str(item.get('recommendation_id', ''))))}",
                    f"actor={_logfmt_quote(_syslog_escape(str(item.get('actor', ''))))}",
                    f"payload_json={_logfmt_quote(_syslog_escape(json.dumps(payload_value, separators=(',', ':'), ensure_ascii=True)))}",
                    f"metadata_json={_logfmt_quote(_syslog_escape(json.dumps(metadata_value, separators=(',', ':'), ensure_ascii=True)))}",
                ]
            ).strip()
            event_id = _syslog_event_id(action_type)
            records.append(f"<{priority}>1 {generated_at} clownpeanuts theater-actions - {event_id} - {message}".rstrip())
        return "\n".join(records).strip()
    raise ValueError(f"unsupported theater action export format: {output_format}")


def _stable_id(value: str) -> str:
    return str(uuid5(NAMESPACE_URL, value))


def _safe_stix_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return "0.0.0.0"


def _navigator_color(confidence: float) -> str:
    if confidence >= 0.85:
        return "#0e4fbf"
    if confidence >= 0.6:
        return "#2f78ff"
    return "#7aa6ff"
