"""Import/export helpers for optional profile-sharing workflows."""

from __future__ import annotations

from datetime import UTC, datetime
import json
from typing import Any
from urllib import request
from uuid import NAMESPACE_URL, uuid4, uuid5

from .profiles import AdversaryProfile, ProfileStore

_NATIVE_SCHEMA = "clownpeanuts.dirtylaundry.profile_share.v1"
_STIX_CUSTOM_TYPE = "x-clownpeanuts-adversary-profile"


def _stix_timestamp(value: str | None = None) -> str:
    raw = str(value or "").strip()
    if raw:
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return dt.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        except ValueError:
            pass
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _stable_profile_object_id(profile_id: str) -> str:
    deterministic = uuid5(NAMESPACE_URL, f"clownpeanuts:dirtylaundry:{profile_id}")
    return f"{_STIX_CUSTOM_TYPE}--{deterministic}"


def _coerce_metrics(metrics_raw: Any) -> dict[str, float]:
    if not isinstance(metrics_raw, dict):
        return {}
    metrics: dict[str, float] = {}
    for key, value in metrics_raw.items():
        metric_name = str(key).strip()
        if not metric_name:
            continue
        try:
            metric_value = float(value)
        except (TypeError, ValueError):
            continue
        metrics[metric_name] = metric_value
    return metrics


def export_profiles(profiles: list[AdversaryProfile]) -> dict[str, Any]:
    """Export profile summaries using a stable schema envelope."""

    return {
        "schema": _NATIVE_SCHEMA,
        "count": len(profiles),
        "profiles": [
            {
                "profile_id": profile.profile_id,
                "skill": profile.skill,
                "created_at": profile.created_at,
                "last_seen_at": profile.last_seen_at,
                "metrics": dict(profile.metrics),
            }
            for profile in profiles
        ],
    }


def export_profiles_stix(profiles: list[AdversaryProfile]) -> dict[str, Any]:
    """Export profile summaries as a STIX 2.1 custom-object bundle."""

    now = _stix_timestamp()
    identity_id = f"identity--{uuid5(NAMESPACE_URL, 'clownpeanuts:dirtylaundry:identity')}"
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "ClownPeanuts DirtyLaundry",
            "identity_class": "system",
            "sectors": ["technology"],
        }
    ]
    for profile in profiles:
        objects.append(
            {
                "type": _STIX_CUSTOM_TYPE,
                "spec_version": "2.1",
                "id": _stable_profile_object_id(profile.profile_id),
                "created_by_ref": identity_id,
                "created": _stix_timestamp(profile.created_at),
                "modified": _stix_timestamp(profile.last_seen_at),
                "name": f"adversary-profile-{profile.profile_id}",
                "labels": ["dirtylaundry", "adversary-profile"],
                "x_clownpeanuts_profile_id": profile.profile_id,
                "x_clownpeanuts_skill": profile.skill,
                "x_clownpeanuts_metrics": dict(profile.metrics),
                "x_clownpeanuts_last_seen_at": profile.last_seen_at,
                "x_clownpeanuts_session_count": len(profile.sessions),
            }
        )
    return {
        "type": "bundle",
        "id": f"bundle--{uuid4()}",
        "objects": objects,
    }


def _import_native_profiles(payload: dict[str, Any], *, store: ProfileStore) -> dict[str, Any]:
    if str(payload.get("schema", "")).strip() != _NATIVE_SCHEMA:
        return {"status": "rejected", "reason": "unsupported schema", "imported": 0}
    rows = payload.get("profiles", [])
    if not isinstance(rows, list):
        return {"status": "rejected", "reason": "profiles must be a list", "imported": 0}

    imported = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        metrics = _coerce_metrics(row.get("metrics", {}))
        skill = str(row.get("skill", "intermediate")).strip() or "intermediate"
        source_profile_id = str(row.get("profile_id", "")).strip()
        created_at = str(row.get("created_at", "")).strip()
        last_seen_at = str(row.get("last_seen_at", "")).strip()
        profile = store.upsert_profile(
            profile_id=source_profile_id,
            skill=skill,
            metrics=metrics,
            created_at=created_at,
            last_seen_at=last_seen_at,
        )
        store.add_note(profile_id=profile.profile_id, note="imported_profile")
        imported += 1
    return {"status": "imported", "imported": imported, "format": "native"}


def _import_stix_profiles(payload: dict[str, Any], *, store: ProfileStore) -> dict[str, Any]:
    if str(payload.get("type", "")).strip().lower() != "bundle":
        return {"status": "rejected", "reason": "not a stix bundle", "imported": 0}
    rows = payload.get("objects", [])
    if not isinstance(rows, list):
        return {"status": "rejected", "reason": "stix bundle objects must be a list", "imported": 0}

    imported = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("type", "")).strip().lower() != _STIX_CUSTOM_TYPE:
            continue
        profile_id = str(row.get("x_clownpeanuts_profile_id", "")).strip()
        if not profile_id:
            profile_id = str(row.get("id", "")).strip()
        if not profile_id:
            continue
        skill = str(row.get("x_clownpeanuts_skill", "intermediate")).strip() or "intermediate"
        metrics = _coerce_metrics(row.get("x_clownpeanuts_metrics", {}))
        created_at = str(row.get("created", "")).strip()
        last_seen_at = str(row.get("x_clownpeanuts_last_seen_at", "")).strip() or str(row.get("modified", "")).strip()
        profile = store.upsert_profile(
            profile_id=profile_id,
            skill=skill,
            metrics=metrics,
            created_at=created_at,
            last_seen_at=last_seen_at,
        )
        store.add_note(profile_id=profile.profile_id, note="imported_profile_stix")
        imported += 1
    return {"status": "imported", "imported": imported, "format": "stix"}


def import_profiles(payload: dict[str, Any], *, store: ProfileStore) -> dict[str, Any]:
    """Import profile summaries into the local profile store."""

    native_result = _import_native_profiles(payload, store=store)
    if native_result.get("status") == "imported":
        return native_result
    stix_result = _import_stix_profiles(payload, store=store)
    if stix_result.get("status") == "imported":
        return stix_result
    return {"status": "rejected", "reason": "unsupported share payload format", "imported": 0}


def _read_json_response(response: Any) -> dict[str, Any]:
    raw = response.read()
    if not raw:
        return {"status": "ok"}
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("share endpoint returned invalid JSON payload") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError("share endpoint response must be a JSON object")
    return decoded


def push_share_payload(
    *,
    endpoint: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    normalized_endpoint = endpoint.strip()
    if not normalized_endpoint:
        raise RuntimeError("share endpoint is required")
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    req = request.Request(
        normalized_endpoint,
        data=body,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            return _read_json_response(response)
    except Exception as exc:
        raise RuntimeError(f"share push failed: {exc}") from exc


def pull_share_payload(
    *,
    endpoint: str,
    headers: dict[str, str] | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    normalized_endpoint = endpoint.strip()
    if not normalized_endpoint:
        raise RuntimeError("share endpoint is required")
    req = request.Request(
        normalized_endpoint,
        headers={"Accept": "application/json", **(headers or {})},
        method="GET",
    )
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            return _read_json_response(response)
    except Exception as exc:
        raise RuntimeError(f"share pull failed: {exc}") from exc
