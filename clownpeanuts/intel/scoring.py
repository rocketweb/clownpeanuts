"""Engagement scoring model."""

from __future__ import annotations

from typing import Any


def score_session(session: dict[str, Any]) -> dict[str, Any]:
    events = session.get("events", [])
    if not isinstance(events, list):
        events = []
    event_count = int(session.get("event_count", len(events)) or 0)
    credential_events = sum(1 for event in events if isinstance(event, dict) and event.get("action") in {"auth_attempt", "credential_capture"})
    command_events = sum(1 for event in events if isinstance(event, dict) and event.get("action") == "command")
    pivot_events = sum(1 for event in events if isinstance(event, dict) and event.get("action") in {"pivot", "lateral_move"})

    score = min(100.0, (event_count * 1.5) + (credential_events * 8.0) + (command_events * 3.0) + (pivot_events * 12.0))
    band = "low"
    if score >= 35:
        band = "medium"
    if score >= 65:
        band = "high"
    if score >= 85:
        band = "critical"
    return {
        "score": round(score, 2),
        "band": band,
        "signals": {
            "events": event_count,
            "credential_events": credential_events,
            "command_events": command_events,
            "pivot_events": pivot_events,
        },
    }


def score_narrative_coherence(session: dict[str, Any]) -> dict[str, Any]:
    events = _session_events(session)
    narrative_raw = session.get("narrative", {})
    narrative = narrative_raw if isinstance(narrative_raw, dict) else {}
    violations: list[str] = []
    penalties = 0.0

    context_id = str(narrative.get("context_id", "")).strip()
    if not context_id:
        penalties += 0.35
        violations.append("missing_context_id")

    tenant_id = str(narrative.get("tenant_id", "")).strip()
    if not tenant_id:
        penalties += 0.15
        violations.append("missing_tenant_id")

    world_id = str(narrative.get("world_id", "")).strip()
    if not world_id:
        penalties += 0.1
        violations.append("missing_world_id")

    touched_services = _string_list(narrative.get("touched_services", []))
    touched_set = set(touched_services)
    observed_services = {
        str(event.get("service", "")).strip().lower()
        for event in events
        if isinstance(event, dict) and str(event.get("service", "")).strip()
    }
    if observed_services and not touched_services:
        penalties += 0.2
        violations.append("missing_touched_services")
    elif observed_services:
        missing_services = sorted(service for service in observed_services if service not in touched_set)
        if missing_services:
            penalties += min(0.4, 0.1 * len(missing_services))
            for service in missing_services:
                violations.append(f"service_missing:{service}")

    discovery_depth = max(0, int(narrative.get("discovery_depth", 0) or 0))
    if events and discovery_depth == 0:
        penalties += 0.15
        violations.append("stale_discovery_depth")
    elif events and discovery_depth < len(events):
        penalties += 0.05
        violations.append("shallow_discovery_depth")

    last_service = str(narrative.get("last_service", "")).strip().lower()
    if events and not last_service:
        penalties += 0.05
        violations.append("missing_last_service")
    elif events:
        event_last_service = str(events[-1].get("service", "")).strip().lower()
        if event_last_service and last_service and event_last_service != last_service:
            penalties += 0.1
            violations.append("last_service_mismatch")

    last_action = str(narrative.get("last_action", "")).strip().lower()
    if events and not last_action:
        penalties += 0.05
        violations.append("missing_last_action")
    elif events:
        event_last_action = str(events[-1].get("action", "")).strip().lower()
        if event_last_action and last_action and not _action_is_compatible(last_action, event_last_action):
            penalties += 0.05
            violations.append("last_action_mismatch")

    score = max(0.0, min(1.0, 1.0 - penalties))
    return {
        "score": round(score, 3),
        "violations": violations,
        "signals": {
            "event_count": len(events),
            "discovery_depth": discovery_depth,
            "observed_services": sorted(observed_services),
            "touched_services": touched_services,
            "penalty_total": round(min(1.0, penalties), 3),
        },
    }


def _session_events(session: dict[str, Any]) -> list[dict[str, Any]]:
    events_raw = session.get("events", [])
    if not isinstance(events_raw, list):
        return []
    return [event for event in events_raw if isinstance(event, dict)]


def _string_list(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    values: list[str] = []
    for item in raw:
        normalized = str(item).strip().lower()
        if normalized and normalized not in values:
            values.append(normalized)
    return values


def _action_is_compatible(last_action: str, event_action: str) -> bool:
    if last_action == event_action:
        return True
    if event_action == "http_request":
        return last_action.startswith(("get_", "post_", "put_", "patch_", "delete_", "head_", "options_"))
    if event_action == "command":
        return True
    return False
