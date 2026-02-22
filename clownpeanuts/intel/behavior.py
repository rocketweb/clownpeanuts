"""Behavioral analytics helpers."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any


_STAGE_ORDER = (
    "reconnaissance",
    "initial_access",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "exfiltration",
    "execution",
)
_NEXT_STAGE_MAP = {
    "reconnaissance": "initial_access",
    "initial_access": "credential_access",
    "credential_access": "discovery",
    "discovery": "lateral_movement",
    "lateral_movement": "collection",
    "collection": "exfiltration",
    "exfiltration": "execution",
    "execution": "collection",
}
_STAGE_ACTION_MAP = {
    "reconnaissance": "scan",
    "initial_access": "auth_attempt",
    "credential_access": "credential_dump",
    "discovery": "command",
    "lateral_movement": "pivot_attempt",
    "collection": "data_staging",
    "exfiltration": "exfil_attempt",
    "execution": "command",
}


def summarize_timing(events: list[dict[str, Any]]) -> dict[str, Any]:
    parsed_timestamps = [_parse_timestamp(str(item.get("timestamp", ""))) for item in events]
    timestamps = sorted(item for item in parsed_timestamps if item is not None)
    if not timestamps:
        return {
            "first_seen": "",
            "last_seen": "",
            "duration_seconds": 0.0,
            "events_per_minute": 0.0,
            "avg_interarrival_seconds": 0.0,
        }

    first_seen = timestamps[0]
    last_seen = timestamps[-1]
    duration_seconds = max(0.0, float((last_seen - first_seen).total_seconds()))
    if len(timestamps) <= 1:
        avg_interarrival_seconds = 0.0
    else:
        avg_interarrival_seconds = duration_seconds / (len(timestamps) - 1)
    minutes = max(duration_seconds / 60.0, 1.0 / 60.0)
    events_per_minute = len(events) / minutes
    return {
        "first_seen": first_seen.isoformat(timespec="seconds"),
        "last_seen": last_seen.isoformat(timespec="seconds"),
        "duration_seconds": round(duration_seconds, 3),
        "events_per_minute": round(events_per_minute, 3),
        "avg_interarrival_seconds": round(avg_interarrival_seconds, 3),
    }


def infer_kill_chain(events: list[dict[str, Any]]) -> list[str]:
    sequence: list[str] = []
    for event in events:
        stage = map_event_to_stage(event)
        if not stage:
            continue
        if not sequence or sequence[-1] != stage:
            sequence.append(stage)
    return sequence


def summarize_kill_chain(sequences: list[list[str]]) -> dict[str, Any]:
    counter: Counter[str] = Counter()
    depths: list[int] = []
    progressed_sessions = 0

    for sequence in sequences:
        if not sequence:
            continue
        counter.update(sequence)
        depth = len(sequence)
        depths.append(depth)
        if depth >= 3:
            progressed_sessions += 1

    stage_counts = [{"stage": stage, "count": counter[stage]} for stage in _STAGE_ORDER if counter[stage] > 0]
    avg_depth = round(sum(depths) / len(depths), 3) if depths else 0.0
    return {
        "stage_counts": stage_counts,
        "max_depth": max(depths) if depths else 0,
        "avg_depth": avg_depth,
        "sessions_with_progression": progressed_sessions,
    }


def summarize_kill_chain_graph(sequences: list[list[str]]) -> dict[str, Any]:
    node_counter: Counter[str] = Counter()
    edge_counter: Counter[tuple[str, str]] = Counter()
    for sequence in sequences:
        if not sequence:
            continue
        node_counter.update(sequence)
        for idx in range(len(sequence) - 1):
            source = sequence[idx]
            target = sequence[idx + 1]
            if source and target:
                edge_counter[(source, target)] += 1

    nodes = [
        {"id": stage, "label": stage.replace("_", " "), "count": count}
        for stage, count in node_counter.most_common()
    ]
    edges = [
        {"source": source, "target": target, "count": count}
        for (source, target), count in sorted(
            edge_counter.items(),
            key=lambda item: (-item[1], item[0][0], item[0][1]),
        )
    ]
    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }


def map_event_to_stage(event: dict[str, Any]) -> str:
    action = str(event.get("action", "")).lower()
    service = str(event.get("service", "")).lower()
    payload = event.get("payload", {})
    if not isinstance(payload, dict):
        payload = {}
    command = str(payload.get("command", payload.get("query", ""))).lower()
    message = str(payload.get("message", payload.get("request", ""))).lower()
    text = f"{service} {action} {command} {message}"

    if any(token in text for token in ("nmap", "masscan", "nikto", "gobuster", "dirb", "ffuf", "scan")):
        return "reconnaissance"
    if action in {"auth_attempt", "credential_capture", "login_attempt"}:
        return "initial_access"
    if any(token in text for token in ("mimikatz", "hashdump", "sekurlsa::", "lsass")):
        return "credential_access"
    if any(
        token in text
        for token in (
            "whoami",
            "id ",
            "uname",
            "ifconfig",
            "ip a",
            "netstat",
            "ps -",
            "ls ",
            "cat /etc/passwd",
        )
    ):
        return "discovery"
    if any(token in text for token in ("pivot", "ssh ", "scp ", "psexec", "wmic ", "crackmapexec")):
        return "lateral_movement"
    if any(token in text for token in ("mysqldump", "pg_dump", "mongodump", "tar ", "zip ", "backup")):
        return "collection"
    if any(token in text for token in ("curl ", "wget ", "ftp ", "rsync ", "s3 cp", "exfil", "/dev/tcp/")):
        return "exfiltration"
    if action in {"command", "command_attempt", "exec"}:
        return "execution"
    return ""


def predict_next_action(
    *,
    events: list[dict[str, Any]],
    kill_chain: list[str] | None = None,
) -> dict[str, Any]:
    sequence = kill_chain if isinstance(kill_chain, list) else infer_kill_chain(events)
    normalized_sequence = [str(item).strip().lower() for item in sequence if str(item).strip()]
    current_stage = normalized_sequence[-1] if normalized_sequence else ""
    if not current_stage and events:
        current_stage = map_event_to_stage(events[-1])
    if not current_stage:
        current_stage = "reconnaissance"

    next_stage = _NEXT_STAGE_MAP.get(current_stage, "discovery")
    next_action = _STAGE_ACTION_MAP.get(next_stage, "command")

    event_volume_bonus = min(0.25, float(len(events)) / 40.0)
    chain_consistency_bonus = 0.0
    if len(normalized_sequence) >= 2:
        unique_recent = len(set(normalized_sequence[-3:]))
        chain_consistency_bonus = 0.15 if unique_recent <= 2 else 0.05
    base_confidence = 0.45
    confidence = max(0.1, min(0.98, base_confidence + event_volume_bonus + chain_consistency_bonus))

    return {
        "current_stage": current_stage,
        "predicted_stage": next_stage,
        "predicted_action": next_action,
        "confidence": round(confidence, 3),
    }


def _parse_timestamp(raw: str) -> datetime | None:
    if not raw:
        return None
    normalized = raw.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None
