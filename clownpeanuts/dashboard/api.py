"""FastAPI foundation for operations and intel endpoints."""

from __future__ import annotations

import asyncio
import base64
import copy
import csv
import io
import json
from datetime import datetime, timezone
import re
import threading
import time
from typing import Any, Callable, Literal
import yaml

try:
    from fastapi import FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from starlette.middleware.trustedhost import TrustedHostMiddleware
except Exception:  # pragma: no cover - optional dependency
    FastAPI = None  # type: ignore[assignment]
    HTTPException = RuntimeError  # type: ignore[assignment]
    Query = None  # type: ignore[assignment]
    Request = Any  # type: ignore[assignment]
    Response = Any  # type: ignore[assignment]
    WebSocket = None  # type: ignore[assignment]
    WebSocketDisconnect = Exception  # type: ignore[assignment]
    CORSMiddleware = None  # type: ignore[assignment]
    JSONResponse = Any  # type: ignore[assignment]
    TrustedHostMiddleware = None  # type: ignore[assignment]

from clownpeanuts.intel.export import (
    build_attack_navigator_layer,
    build_theater_action_export,
    build_stix_bundle,
    build_taxii_manifest,
    find_stix_object,
    render_theater_action_export,
)
from clownpeanuts.intel.handoff import build_soc_handoff
from clownpeanuts.intel.map import build_engagement_map
from clownpeanuts.intel.canary import canary_type_catalog
from clownpeanuts.agents.adlibs import ADLibsError, ADLibsManager, ADLibsNotFoundError
from clownpeanuts.agents.dirtylaundry import (
    DirtyLaundryError,
    DirtyLaundryManager,
    DirtyLaundryNotFoundError,
)
from clownpeanuts.agents.pripyatsprings import PripyatSpringsError, PripyatSpringsManager
from clownpeanuts.core.doctor import run_diagnostics
from clownpeanuts.ecosystem import (
    EcosystemActivityError,
    EcosystemActivityManager,
    EcosystemActivityNotFoundError,
    EcosystemDeploymentConflictError,
    EcosystemDeploymentError,
    EcosystemDriftEngine,
    EcosystemJITError,
    EcosystemJITManager,
    EcosystemDeploymentManager,
    EcosystemDeploymentNotFoundError,
    EcosystemWitchbaitConflictError,
    EcosystemWitchbaitError,
    EcosystemWitchbaitManager,
    EcosystemWitchbaitNotFoundError,
)


DEFAULT_API_CORS_ALLOW_ORIGINS = [
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:3001",
    "http://localhost:3001",
]
DEFAULT_API_RATE_LIMIT_EXEMPT_PATHS = ["/health"]
MAX_RATE_LIMIT_TRACKED_CLIENTS = 50_000
CAMPAIGN_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,80}$")
CAMPAIGN_NODE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,120}$")
VALID_CAMPAIGN_STATUSES = {"draft", "active", "paused", "archived"}
CAMPAIGN_EXPORT_SCHEMA = "clownpeanuts.campaign_graph.v1"
WS_BASE_PROTOCOL = "cp-events-v1"
WS_AUTH_PROTOCOL_PREFIX = "cp-auth."
API_TOKEN_COOKIE_NAME = "cp_api_token"


def create_app(orchestrator: Any) -> Any:
    if FastAPI is None or Query is None:
        raise RuntimeError("FastAPI is not installed. Install with: pip install 'clownpeanuts[api]'")

    api_config = getattr(orchestrator.config, "api", None)
    docs_enabled = bool(getattr(api_config, "docs_enabled", False))
    cors_allow_origins = [str(item).strip() for item in getattr(api_config, "cors_allow_origins", DEFAULT_API_CORS_ALLOW_ORIGINS)]
    cors_allow_origins = [item for item in cors_allow_origins if item] or list(DEFAULT_API_CORS_ALLOW_ORIGINS)
    cors_allow_credentials = bool(getattr(api_config, "cors_allow_credentials", False))
    trusted_hosts = list(getattr(api_config, "trusted_hosts", ["*"])) or ["*"]
    auth_enabled = bool(getattr(api_config, "auth_enabled", False))
    operator_tokens = {
        str(token).strip() for token in getattr(api_config, "auth_operator_tokens", []) if str(token).strip()
    }
    viewer_tokens = {str(token).strip() for token in getattr(api_config, "auth_viewer_tokens", []) if str(token).strip()}
    allow_unauthenticated_health = bool(getattr(api_config, "allow_unauthenticated_health", True))
    rate_limit_enabled = bool(getattr(api_config, "rate_limit_enabled", False))
    rate_limit_requests_per_minute = max(1, int(getattr(api_config, "rate_limit_requests_per_minute", 240)))
    rate_limit_burst = max(0, int(getattr(api_config, "rate_limit_burst", 60)))
    max_request_body_bytes = max(1024, int(getattr(api_config, "max_request_body_bytes", 262144)))
    rate_limit_exempt_paths_raw = getattr(api_config, "rate_limit_exempt_paths", DEFAULT_API_RATE_LIMIT_EXEMPT_PATHS)
    rate_limit_exempt_paths = {
        f"/{str(path).strip().lstrip('/')}".rstrip("/") or "/"
        for path in (rate_limit_exempt_paths_raw or DEFAULT_API_RATE_LIMIT_EXEMPT_PATHS)
        if str(path).strip()
    }
    if not rate_limit_exempt_paths:
        rate_limit_exempt_paths = {"/health"}
    if auth_enabled and not operator_tokens and not viewer_tokens:
        raise RuntimeError("api auth is enabled but no operator/viewer tokens are configured")
    if cors_allow_credentials and "*" in cors_allow_origins:
        raise RuntimeError("api cors_allow_credentials cannot be true when cors_allow_origins includes '*'")

    app = FastAPI(
        title="ClownPeanuts API",
        version="0.1.0",
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    ecosystem_config = getattr(orchestrator.config, "ecosystem", None)
    ecosystem_enabled = bool(getattr(ecosystem_config, "enabled", False))
    agents_config = getattr(orchestrator.config, "agents", None)
    pripyatsprings_config = getattr(agents_config, "pripyatsprings", None)
    adlibs_config = getattr(agents_config, "adlibs", None)
    dirtylaundry_config = getattr(agents_config, "dirtylaundry", None)
    pripyatsprings_enabled = ecosystem_enabled and bool(getattr(pripyatsprings_config, "enabled", False))
    adlibs_enabled = ecosystem_enabled and bool(getattr(adlibs_config, "enabled", False))
    dirtylaundry_enabled = ecosystem_enabled and bool(getattr(dirtylaundry_config, "enabled", False))
    pripyatsprings_manager: PripyatSpringsManager | None = None
    if pripyatsprings_enabled and pripyatsprings_config is not None:
        pripyatsprings_manager = PripyatSpringsManager(
            pripyatsprings_config,
            emit_hook=lambda item: orchestrator.event_logger.emit(
                message="pripyatsprings tracking hit detected",
                service="ecosystem",
                action="pripyatsprings_tracking_hit",
                event_type="alert",
                outcome="success",
                session_id=str(item.get("session_id", "")).strip() or None,
                source_ip=str(item.get("source_ip", "")).strip() or None,
                payload={
                    "hit_id": str(item.get("hit_id", "")).strip(),
                    "fingerprint_id": str(item.get("fingerprint_id", "")).strip(),
                    "deployment_id": str(item.get("deployment_id", "")).strip(),
                    "user_agent": str(item.get("user_agent", "")).strip(),
                    "metadata": dict(item.get("metadata", {})) if isinstance(item.get("metadata"), dict) else {},
                },
                level="WARNING",
            ),
        )
    adlibs_manager: ADLibsManager | None = None
    dirtylaundry_manager: DirtyLaundryManager | None = None
    if dirtylaundry_enabled and dirtylaundry_config is not None:
        dirtylaundry_manager = DirtyLaundryManager(
            dirtylaundry_config,
            emit_hook=lambda item: orchestrator.event_logger.emit(
                message="dirtylaundry apt profile detected",
                service="ecosystem",
                action="dirtylaundry_apt_profile",
                event_type="alert",
                outcome="warning",
                payload={
                    "profile_id": str(item.get("profile_id", "")),
                    "skill": str(item.get("skill", "")),
                    "session_count": int(item.get("session_count", 0) or 0),
                    "auto_theater_recommended": True,
                },
                level="WARNING",
            ),
        )
    ecosystem_activity = EcosystemActivityManager(orchestrator=orchestrator)
    ecosystem_deployments = EcosystemDeploymentManager(orchestrator=orchestrator)
    ecosystem_drift = EcosystemDriftEngine(
        orchestrator=orchestrator,
        alert_threshold=float(getattr(ecosystem_config, "drift_alert_threshold", 0.7)),
    )
    ecosystem_jit_config = getattr(ecosystem_config, "jit", None)
    ecosystem_jit_enabled = ecosystem_enabled and bool(getattr(ecosystem_jit_config, "enabled", False))
    ecosystem_jit: EcosystemJITManager | None = None
    if ecosystem_jit_enabled:
        ecosystem_jit = EcosystemJITManager(
            deployment_manager=ecosystem_deployments,
            pool_size=int(getattr(ecosystem_jit_config, "pool_size", 10)),
            ttl_idle_seconds=int(getattr(ecosystem_jit_config, "ttl_idle_seconds", 14_400)),
            ttl_max_seconds=int(getattr(ecosystem_jit_config, "ttl_max_seconds", 86_400)),
        )

        def _jit_touch_from_event(envelope: dict[str, Any]) -> None:
            payload = envelope.get("payload")
            if isinstance(payload, dict):
                ecosystem_jit.touch_from_event(payload)

        orchestrator.event_bus.subscribe("events", _jit_touch_from_event)
    ecosystem_witchbait: EcosystemWitchbaitManager | None = None
    if ecosystem_enabled:
        seed_credentials = getattr(ecosystem_config, "witchbait_credentials", []) or []
        if not isinstance(seed_credentials, list):
            seed_credentials = []
        ecosystem_witchbait = EcosystemWitchbaitManager(
            orchestrator=orchestrator,
            seed_credentials=[item for item in seed_credentials if isinstance(item, dict)],
        )
    if adlibs_enabled and adlibs_config is not None:
        register_credential = None
        if ecosystem_witchbait is not None and bool(getattr(adlibs_config, "witchbait_integration", False)):
            register_credential = lambda payload: ecosystem_witchbait.register_credential(  # noqa: E731
                payload,
                source="adlibs",
                allow_existing=True,
            )
        adlibs_manager = ADLibsManager(
            adlibs_config,
            register_credential=register_credential,
            emit_hook=lambda item: orchestrator.event_logger.emit(
                message="adlibs trip detected",
                service="ecosystem",
                action="adlibs_trip",
                event_type="alert",
                outcome="warning",
                source_ip=None,
                payload={
                    "trip_id": str(item.get("trip_id", "")).strip(),
                    "object_id": str(item.get("object_id", "")).strip(),
                    "event_type": str(item.get("event_type", "")).strip(),
                    "source_host": str(item.get("source_host", "")).strip(),
                    "source_user": str(item.get("source_user", "")).strip(),
                    "metadata": dict(item.get("metadata", {})) if isinstance(item.get("metadata"), dict) else {},
                },
                level="WARNING",
            ),
        )
    if TrustedHostMiddleware is not None:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=trusted_hosts,
        )
    if CORSMiddleware is not None:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_allow_origins,
            allow_credentials=cors_allow_credentials,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    taxii_collection_id = "clownpeanuts-intel"
    taxii_media_type = "application/stix+json;version=2.1"
    taxii_content_type = "application/taxii+json;version=2.1"
    summary_cache_lock = threading.RLock()
    summary_cache: dict[str, tuple[float, Any]] = {}
    canary_types = canary_type_catalog()
    canary_types_payload = {"types": canary_types, "count": len(canary_types)}
    default_intel_report_cache_ttl_seconds = max(
        0.0,
        float(getattr(api_config, "intel_report_cache_ttl_seconds", 1.5)),
    )
    rate_limit_lock = threading.RLock()
    # client_id -> (token_count, last_refill_monotonic, last_seen_monotonic)
    rate_limit_state: dict[str, tuple[float, float, float]] = {}
    rate_limit_capacity = max(1.0, float(rate_limit_requests_per_minute + rate_limit_burst))
    rate_limit_refill_per_second = float(rate_limit_requests_per_minute) / 60.0

    def _summary_cache_get(key: str, *, ttl_seconds: float, build: Callable[[], Any]) -> Any:
        now = time.monotonic()
        with summary_cache_lock:
            cached = summary_cache.get(key)
            if cached and (now - cached[0]) <= ttl_seconds:
                return copy.deepcopy(cached[1])
        value = build()
        with summary_cache_lock:
            summary_cache[key] = (time.monotonic(), value)
        return copy.deepcopy(value)

    def _normalize_path(path: str) -> str:
        normalized = f"/{str(path).strip().lstrip('/')}"
        normalized = normalized.rstrip("/")
        return normalized or "/"

    def _is_rate_limit_exempt(path: str) -> bool:
        normalized = _normalize_path(path)
        return normalized in rate_limit_exempt_paths

    def _trim_event_payload(event: dict[str, Any]) -> dict[str, Any]:
        trimmed = dict(event)
        payload = trimmed.get("payload", {})
        if not isinstance(payload, dict):
            return trimmed
        trimmed_payload = dict(payload)
        nested_payload = trimmed_payload.get("payload")
        if isinstance(nested_payload, dict):
            trimmed_payload["payload"] = {
                "redacted": True,
                "field_count": len(nested_payload),
            }
        elif nested_payload is not None:
            trimmed_payload["payload"] = {"redacted": True}
        trimmed["payload"] = trimmed_payload
        return trimmed

    def _event_matches_filters(
        event: dict[str, Any],
        *,
        topic_filter: set[str],
        service_filter: set[str],
        action_filter: set[str],
        session_filter: set[str],
    ) -> bool:
        topic = str(event.get("topic", "")).strip().lower()
        if topic_filter and topic not in topic_filter:
            return False
        payload = event.get("payload", {})
        if not isinstance(payload, dict):
            return not (service_filter or action_filter or session_filter)
        service = str(payload.get("service", "")).strip().lower()
        if service_filter and service not in service_filter:
            return False
        action = str(payload.get("action", "")).strip().lower()
        if action_filter and action not in action_filter:
            return False
        session_id = str(payload.get("session_id", "")).strip().lower()
        if session_filter and session_id not in session_filter:
            return False
        return True

    def _client_identity_from_headers(*, x_forwarded_for: str | None, fallback: str) -> str:
        if x_forwarded_for:
            first = x_forwarded_for.split(",")[0].strip()
            if first:
                return first
        normalized_fallback = fallback.strip()
        return normalized_fallback or "unknown"

    def _request_client_identity(request: Request) -> str:
        fallback = request.client.host if request.client else "unknown"
        return _client_identity_from_headers(
            x_forwarded_for=request.headers.get("x-forwarded-for"),
            fallback=fallback,
        )

    def _websocket_client_identity(websocket: WebSocket) -> str:
        fallback = websocket.client.host if websocket.client else "unknown"
        return _client_identity_from_headers(
            x_forwarded_for=websocket.headers.get("x-forwarded-for"),
            fallback=fallback,
        )

    def _trim_rate_limit_state(now: float) -> None:
        if len(rate_limit_state) <= MAX_RATE_LIMIT_TRACKED_CLIENTS:
            return
        stale_cutoff = now - 600.0
        stale_clients = [
            client_id
            for client_id, (_tokens, _refill, last_seen) in rate_limit_state.items()
            if last_seen < stale_cutoff
        ]
        for client_id in stale_clients:
            rate_limit_state.pop(client_id, None)
            if len(rate_limit_state) <= MAX_RATE_LIMIT_TRACKED_CLIENTS:
                return
        if len(rate_limit_state) <= MAX_RATE_LIMIT_TRACKED_CLIENTS:
            return
        overflow = len(rate_limit_state) - MAX_RATE_LIMIT_TRACKED_CLIENTS
        oldest_clients = sorted(rate_limit_state.items(), key=lambda item: item[1][2])[:overflow]
        for client_id, _ in oldest_clients:
            rate_limit_state.pop(client_id, None)

    def _rate_limit_consume(client_id: str) -> tuple[bool, int, int]:
        now = time.monotonic()
        with rate_limit_lock:
            _trim_rate_limit_state(now)
            tokens, last_refill, _last_seen = rate_limit_state.get(client_id, (rate_limit_capacity, now, now))
            elapsed = max(0.0, now - last_refill)
            tokens = min(rate_limit_capacity, tokens + (elapsed * rate_limit_refill_per_second))
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            rate_limit_state[client_id] = (tokens, now, now)
        remaining = max(0, int(tokens))
        if allowed:
            return (True, remaining, 0)
        needed_tokens = max(0.0, 1.0 - tokens)
        retry_after_seconds = max(1, int((needed_tokens / rate_limit_refill_per_second) + 0.999))
        return (False, remaining, retry_after_seconds)

    def _resolve_live_report(
        *,
        limit: int,
        events_per_session: int,
        ttl_seconds: float = default_intel_report_cache_ttl_seconds,
    ) -> dict[str, Any]:
        normalized_ttl_seconds = max(0.0, float(ttl_seconds))
        if normalized_ttl_seconds <= 0:
            return orchestrator.intelligence_report(limit=limit, events_per_session=events_per_session)
        return _summary_cache_get(
            f"intel:report:{limit}:{events_per_session}",
            ttl_seconds=normalized_ttl_seconds,
            build=lambda: orchestrator.intelligence_report(limit=limit, events_per_session=events_per_session),
        )

    def _resolve_export_report(
        *,
        limit: int,
        events_per_session: int,
        report_id: int | None = None,
    ) -> dict[str, Any]:
        if report_id is not None:
            report = orchestrator.intelligence_history_report_payload(report_id=max(1, int(report_id)))
            if report is None:
                raise HTTPException(status_code=404, detail="intelligence report not found")
            return report
        return _resolve_live_report(limit=limit, events_per_session=events_per_session)

    def _resolve_handoff_payload(
        *,
        limit: int,
        events_per_session: int,
        report_id: int | None,
        max_techniques: int,
        max_sessions: int,
    ) -> dict[str, Any]:
        normalized_limit = max(1, int(limit))
        normalized_events = max(0, int(events_per_session))
        normalized_report_id = max(1, int(report_id)) if report_id is not None else None
        normalized_max_techniques = max(1, int(max_techniques))
        normalized_max_sessions = max(1, int(max_sessions))
        if normalized_report_id is not None:
            key = (
                f"intel:handoff:history:{normalized_report_id}:"
                f"{normalized_max_techniques}:{normalized_max_sessions}"
            )
            return _summary_cache_get(
                key,
                ttl_seconds=5.0,
                build=lambda: build_soc_handoff(
                    _resolve_export_report(
                        limit=normalized_limit,
                        events_per_session=normalized_events,
                        report_id=normalized_report_id,
                    ),
                    max_techniques=normalized_max_techniques,
                    max_sessions=normalized_max_sessions,
                ),
            )
        key = (
            f"intel:handoff:live:{normalized_limit}:{normalized_events}:"
            f"{normalized_max_techniques}:{normalized_max_sessions}"
        )
        ttl_seconds = max(0.0, min(5.0, default_intel_report_cache_ttl_seconds))
        if ttl_seconds <= 0:
            return build_soc_handoff(
                _resolve_export_report(
                    limit=normalized_limit,
                    events_per_session=normalized_events,
                    report_id=None,
                ),
                max_techniques=normalized_max_techniques,
                max_sessions=normalized_max_sessions,
            )
        return _summary_cache_get(
            key,
            ttl_seconds=ttl_seconds,
            build=lambda: build_soc_handoff(
                _resolve_export_report(
                    limit=normalized_limit,
                    events_per_session=normalized_events,
                    report_id=None,
                ),
                max_techniques=normalized_max_techniques,
                max_sessions=normalized_max_sessions,
            ),
        )

    def _require_ecosystem_enabled() -> None:
        if not ecosystem_enabled:
            raise HTTPException(status_code=404, detail="ecosystem integration is disabled")

    def _witchbait_manager() -> EcosystemWitchbaitManager:
        _require_ecosystem_enabled()
        if ecosystem_witchbait is None:  # pragma: no cover - defensive guard
            raise HTTPException(status_code=500, detail="ecosystem witchbait manager unavailable")
        return ecosystem_witchbait

    def _jit_manager() -> EcosystemJITManager:
        _require_ecosystem_enabled()
        if not ecosystem_jit_enabled or ecosystem_jit is None:
            raise HTTPException(status_code=404, detail="ecosystem jit deployment mode is disabled")
        return ecosystem_jit

    def _pripyatsprings_manager() -> PripyatSpringsManager:
        _require_ecosystem_enabled()
        if not pripyatsprings_enabled or pripyatsprings_manager is None:
            raise HTTPException(status_code=404, detail="pripyatsprings module is disabled")
        return pripyatsprings_manager

    def _adlibs_manager() -> ADLibsManager:
        _require_ecosystem_enabled()
        if not adlibs_enabled or adlibs_manager is None:
            raise HTTPException(status_code=404, detail="adlibs module is disabled")
        return adlibs_manager

    def _dirtylaundry_manager() -> DirtyLaundryManager:
        _require_ecosystem_enabled()
        if not dirtylaundry_enabled or dirtylaundry_manager is None:
            raise HTTPException(status_code=404, detail="dirtylaundry module is disabled")
        return dirtylaundry_manager

    async def _read_manifest_payload(request: Request) -> dict[str, Any]:
        content_type = str(request.headers.get("content-type", "")).lower()
        if "application/json" in content_type:
            payload = await request.json()
        else:
            raw = await request.body()
            if not raw:
                payload = {}
            else:
                text = raw.decode("utf-8")
                if "application/yaml" in content_type or "text/yaml" in content_type:
                    payload = yaml.safe_load(text)
                else:
                    try:
                        payload = json.loads(text)
                    except json.JSONDecodeError:
                        payload = yaml.safe_load(text)
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="deployment manifest payload must be an object")
        return payload

    def _parse_taxii_timestamp(value: str | None) -> datetime | None:
        if value is None:
            return None
        raw = value.strip()
        if raw == "":
            return None
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid TAXII timestamp") from exc
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _taxii_collection_payload() -> dict[str, Any]:
        return {
            "id": taxii_collection_id,
            "title": "ClownPeanuts Intelligence Collection",
            "description": "STIX 2.1 bundle export generated from honeypot telemetry.",
            "can_read": True,
            "can_write": False,
            "media_types": [taxii_media_type],
        }

    def _taxii_response(payload: dict[str, Any]) -> Response:
        return Response(
            content=json.dumps(payload, default=str),
            media_type=taxii_content_type,
        )

    def _require_taxii_collection(collection_id: str) -> None:
        if collection_id != taxii_collection_id:
            raise HTTPException(status_code=404, detail="unknown TAXII collection")

    def _taxii_export_bundle(*, limit: int, events_per_session: int, report_id: int | None = None) -> dict[str, Any]:
        report = _resolve_export_report(limit=limit, events_per_session=events_per_session, report_id=report_id)
        return build_stix_bundle(report)

    def _taxii_filter_objects(
        *,
        objects: list[dict[str, Any]],
        manifest: list[dict[str, Any]],
        added_after: datetime | None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        if added_after is None:
            return objects, manifest

        allowed_ids: set[str] = set()
        filtered_manifest: list[dict[str, Any]] = []
        for item in manifest:
            if not isinstance(item, dict):
                continue
            version_value = str(item.get("version", "")).strip()
            stamp = _parse_taxii_timestamp(version_value) if version_value else None
            if stamp is None:
                continue
            if stamp > added_after:
                object_id = str(item.get("id", "")).strip()
                if object_id:
                    allowed_ids.add(object_id)
                filtered_manifest.append(item)

        filtered_objects: list[dict[str, Any]] = []
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            object_id = str(obj.get("id", "")).strip()
            if object_id in allowed_ids:
                filtered_objects.append(obj)
        return filtered_objects, filtered_manifest

    def _paginate_taxii(items: list[dict[str, Any]], *, limit: int, next_cursor: str | None) -> dict[str, Any]:
        if limit < 1:
            limit = 1
        if limit > 1000:
            limit = 1000

        start = 0
        if next_cursor:
            try:
                start = max(0, int(next_cursor))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="invalid TAXII cursor") from exc

        selected = items[start : start + limit]
        more = (start + len(selected)) < len(items)

        payload: dict[str, Any] = {"more": more, "objects": selected}
        if more:
            payload["next"] = str(start + len(selected))
        return payload

    mutation_methods = {"POST", "PUT", "PATCH", "DELETE"}

    def _is_health_path(path: str) -> bool:
        return _normalize_path(path) == "/health"

    def _parse_bearer_token(value: str | None) -> str | None:
        if value is None:
            return None
        raw = value.strip()
        if not raw:
            return None
        parts = raw.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        token = parts[1].strip()
        return token or None

    def _resolve_role_for_token(token: str | None) -> str | None:
        if token is None:
            return None
        if token in operator_tokens:
            return "operator"
        if token in viewer_tokens:
            return "viewer"
        return None

    def _http_auth_role(request: Request) -> str | None:
        role = _resolve_role_for_token(_parse_bearer_token(request.headers.get("authorization")))
        if role is not None:
            return role
        api_key = request.headers.get("x-api-key")
        if api_key:
            role = _resolve_role_for_token(api_key.strip())
            if role is not None:
                return role
        cookie_token = request.cookies.get(API_TOKEN_COOKIE_NAME)
        if cookie_token:
            role = _resolve_role_for_token(cookie_token.strip())
            if role is not None:
                return role
        return None

    def _websocket_auth_role(websocket: WebSocket) -> str | None:
        role = _resolve_role_for_token(_parse_bearer_token(websocket.headers.get("authorization")))
        if role is not None:
            return role
        header_key = websocket.headers.get("x-api-key")
        if header_key:
            role = _resolve_role_for_token(header_key.strip())
            if role is not None:
                return role
        cookie_token = websocket.cookies.get(API_TOKEN_COOKIE_NAME)
        if cookie_token:
            role = _resolve_role_for_token(cookie_token.strip())
            if role is not None:
                return role
        protocols_header = str(websocket.headers.get("sec-websocket-protocol", "")).strip()
        if protocols_header:
            for raw_protocol in protocols_header.split(","):
                protocol = raw_protocol.strip()
                if not protocol.startswith(WS_AUTH_PROTOCOL_PREFIX):
                    continue
                encoded_token = protocol[len(WS_AUTH_PROTOCOL_PREFIX) :].strip()
                if not encoded_token:
                    continue
                # Dashboard clients send auth token via base64url subprotocol to avoid URL query leakage.
                try:
                    padding = "=" * ((4 - (len(encoded_token) % 4)) % 4)
                    decoded_token = base64.urlsafe_b64decode(f"{encoded_token}{padding}").decode(
                        "utf-8",
                        errors="strict",
                    )
                except Exception:
                    continue
                role = _resolve_role_for_token(decoded_token.strip())
                if role is not None:
                    return role
        return None

    def _websocket_accept_subprotocol(websocket: WebSocket) -> str | None:
        protocols_header = str(websocket.headers.get("sec-websocket-protocol", "")).strip()
        if not protocols_header:
            return None
        offered = {item.strip() for item in protocols_header.split(",") if item.strip()}
        if WS_BASE_PROTOCOL in offered:
            return WS_BASE_PROTOCOL
        return None

    def _http_auth_required_response() -> Response:
        return JSONResponse(
            status_code=401,
            content={"detail": "authentication required"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    def _http_operator_required_response() -> Response:
        return JSONResponse(status_code=403, content={"detail": "operator token required"})

    def _http_rate_limited_response(*, retry_after_seconds: int) -> Response:
        return JSONResponse(
            status_code=429,
            content={"detail": "rate limit exceeded"},
            headers={"Retry-After": str(max(1, int(retry_after_seconds)))},
        )

    def _http_request_too_large_response() -> Response:
        return JSONResponse(
            status_code=413,
            content={"detail": "request body too large"},
        )

    async def _request_body_too_large(request: Request) -> bool:
        if request.method.upper() not in mutation_methods:
            return False
        raw_content_length = request.headers.get("content-length")
        if raw_content_length is not None:
            try:
                content_length = int(raw_content_length)
            except ValueError:
                content_length = -1
            if content_length > max_request_body_bytes:
                return True
            if content_length >= 0:
                return False
        body = await request.body()
        return len(body) > max_request_body_bytes

    def _normalize_campaign_id(raw_campaign_id: str) -> str:
        normalized = str(raw_campaign_id).strip()
        if CAMPAIGN_ID_RE.fullmatch(normalized) is None:
            raise HTTPException(
                status_code=400,
                detail="campaign_id must match ^[A-Za-z0-9._:-]{1,80}$",
            )
        return normalized

    def _normalize_campaign_metadata(raw_metadata: Any) -> dict[str, Any]:
        if raw_metadata is None:
            return {}
        if not isinstance(raw_metadata, dict):
            raise HTTPException(status_code=400, detail="campaign metadata must be an object")
        return dict(raw_metadata)

    def _normalize_campaign_nodes(raw_nodes: Any) -> tuple[list[dict[str, Any]], set[str]]:
        if raw_nodes is None:
            return ([], set())
        if not isinstance(raw_nodes, list):
            raise HTTPException(status_code=400, detail="campaign nodes must be a list")
        if len(raw_nodes) > 1000:
            raise HTTPException(status_code=400, detail="campaign nodes cannot exceed 1000")
        nodes: list[dict[str, Any]] = []
        node_ids: set[str] = set()
        for index, raw_node in enumerate(raw_nodes, start=1):
            if not isinstance(raw_node, dict):
                raise HTTPException(status_code=400, detail=f"campaign node {index} must be an object")
            node_id = str(raw_node.get("node_id") or raw_node.get("id") or "").strip()
            if CAMPAIGN_NODE_ID_RE.fullmatch(node_id) is None:
                raise HTTPException(
                    status_code=400,
                    detail=f"campaign node {index} id must match ^[A-Za-z0-9._:-]{{1,120}}$",
                )
            if node_id in node_ids:
                raise HTTPException(status_code=400, detail=f"campaign node id '{node_id}' is duplicated")
            node_type = str(raw_node.get("node_type") or raw_node.get("type") or "service").strip().lower()
            if not node_type or len(node_type) > 64:
                raise HTTPException(status_code=400, detail=f"campaign node {index} type must be 1-64 chars")
            label = str(raw_node.get("label", "")).strip()
            if len(label) > 200:
                raise HTTPException(status_code=400, detail=f"campaign node {index} label exceeds 200 chars")
            metadata = _normalize_campaign_metadata(raw_node.get("metadata", {}))
            node_payload: dict[str, Any] = {
                "node_id": node_id,
                "node_type": node_type,
            }
            if label:
                node_payload["label"] = label
            if metadata:
                node_payload["metadata"] = metadata
            nodes.append(node_payload)
            node_ids.add(node_id)
        return (nodes, node_ids)

    def _normalize_campaign_edges(raw_edges: Any, *, node_ids: set[str]) -> list[dict[str, Any]]:
        if raw_edges is None:
            return []
        if not isinstance(raw_edges, list):
            raise HTTPException(status_code=400, detail="campaign edges must be a list")
        if len(raw_edges) > 4000:
            raise HTTPException(status_code=400, detail="campaign edges cannot exceed 4000")
        edges: list[dict[str, Any]] = []
        for index, raw_edge in enumerate(raw_edges, start=1):
            if not isinstance(raw_edge, dict):
                raise HTTPException(status_code=400, detail=f"campaign edge {index} must be an object")
            source = str(raw_edge.get("source") or raw_edge.get("source_id") or "").strip()
            target = str(raw_edge.get("target") or raw_edge.get("target_id") or "").strip()
            if CAMPAIGN_NODE_ID_RE.fullmatch(source) is None:
                raise HTTPException(
                    status_code=400,
                    detail=f"campaign edge {index} source must match ^[A-Za-z0-9._:-]{{1,120}}$",
                )
            if CAMPAIGN_NODE_ID_RE.fullmatch(target) is None:
                raise HTTPException(
                    status_code=400,
                    detail=f"campaign edge {index} target must match ^[A-Za-z0-9._:-]{{1,120}}$",
                )
            if node_ids and source not in node_ids:
                raise HTTPException(status_code=400, detail=f"campaign edge {index} source '{source}' is unknown")
            if node_ids and target not in node_ids:
                raise HTTPException(status_code=400, detail=f"campaign edge {index} target '{target}' is unknown")
            relation = str(raw_edge.get("relation", "links_to")).strip().lower() or "links_to"
            if len(relation) > 64:
                raise HTTPException(status_code=400, detail=f"campaign edge {index} relation exceeds 64 chars")
            metadata = _normalize_campaign_metadata(raw_edge.get("metadata", {}))
            edge_payload: dict[str, Any] = {
                "source": source,
                "target": target,
                "relation": relation,
            }
            if metadata:
                edge_payload["metadata"] = metadata
            edges.append(edge_payload)
        return edges

    def _normalize_campaign_payload(raw_payload: Any) -> dict[str, Any]:
        if not isinstance(raw_payload, dict):
            raise HTTPException(status_code=400, detail="campaign payload must be an object")
        name = str(raw_payload.get("name", "")).strip()
        if not name:
            raise HTTPException(status_code=400, detail="campaign name must be non-empty")
        if len(name) > 160:
            raise HTTPException(status_code=400, detail="campaign name exceeds 160 chars")
        status = str(raw_payload.get("status", "draft")).strip().lower() or "draft"
        if status not in VALID_CAMPAIGN_STATUSES:
            raise HTTPException(status_code=400, detail="invalid campaign status")
        nodes, node_ids = _normalize_campaign_nodes(raw_payload.get("nodes", []))
        edges = _normalize_campaign_edges(raw_payload.get("edges", []), node_ids=node_ids)
        metadata = _normalize_campaign_metadata(raw_payload.get("metadata", {}))
        return {
            "name": name,
            "status": status,
            "nodes": nodes,
            "edges": edges,
            "metadata": metadata,
        }

    def _campaign_versions_export_rows(versions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for item in versions:
            if not isinstance(item, dict):
                continue
            metadata = item.get("metadata")
            rows.append(
                {
                    "campaign_id": str(item.get("campaign_id", "")).strip(),
                    "version": int(item.get("version", 0) or 0),
                    "status": str(item.get("status", "")).strip(),
                    "event_type": str(item.get("event_type", "")).strip(),
                    "created_at": str(item.get("created_at", "")).strip(),
                    "node_count": int(item.get("node_count", 0) or 0),
                    "edge_count": int(item.get("edge_count", 0) or 0),
                    "metadata_json": json.dumps(
                        metadata if isinstance(metadata, dict) else {},
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ),
                }
            )
        return rows

    def _campaign_inventory_export_rows(campaigns: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for item in campaigns:
            if not isinstance(item, dict):
                continue
            metadata = item.get("metadata")
            rows.append(
                {
                    "campaign_id": str(item.get("campaign_id", "")).strip(),
                    "name": str(item.get("name", "")).strip(),
                    "status": str(item.get("status", "")).strip(),
                    "version": int(item.get("version", 0) or 0),
                    "created_at": str(item.get("created_at", "")).strip(),
                    "updated_at": str(item.get("updated_at", "")).strip(),
                    "node_count": int(item.get("node_count", 0) or 0),
                    "edge_count": int(item.get("edge_count", 0) or 0),
                    "metadata_json": json.dumps(
                        metadata if isinstance(metadata, dict) else {},
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ),
                }
            )
        return rows

    def _render_campaign_versions_export(*, rows: list[dict[str, Any]], output_format: str) -> str:
        normalized = output_format.strip().lower() or "json"
        if normalized == "json":
            return json.dumps(rows, separators=(",", ":"), ensure_ascii=True)
        if normalized in {"ndjson", "jsonl"}:
            return "\n".join(
                json.dumps(row, separators=(",", ":"), ensure_ascii=True)
                for row in rows
            )
        if normalized in {"csv", "tsv"}:
            fieldnames = [
                "campaign_id",
                "version",
                "status",
                "event_type",
                "created_at",
                "node_count",
                "edge_count",
                "metadata_json",
            ]
            stream = io.StringIO()
            writer = csv.DictWriter(stream, fieldnames=fieldnames, delimiter="," if normalized == "csv" else "\t")
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
            return stream.getvalue()
        if normalized == "logfmt":
            return "\n".join(
                " ".join(
                    [
                        f"campaign_id={json.dumps(str(row.get('campaign_id', '')).strip(), ensure_ascii=True)}",
                        f"version={int(row.get('version', 0) or 0)}",
                        f"status={json.dumps(str(row.get('status', '')).strip(), ensure_ascii=True)}",
                        f"event_type={json.dumps(str(row.get('event_type', '')).strip(), ensure_ascii=True)}",
                        f"created_at={json.dumps(str(row.get('created_at', '')).strip(), ensure_ascii=True)}",
                        f"node_count={int(row.get('node_count', 0) or 0)}",
                        f"edge_count={int(row.get('edge_count', 0) or 0)}",
                        f"metadata_json={json.dumps(str(row.get('metadata_json', '')).strip(), ensure_ascii=True)}",
                    ]
                )
                for row in rows
            )
        raise ValueError("format must be one of: json, csv, tsv, ndjson, jsonl, logfmt")

    def _render_campaign_inventory_export(*, rows: list[dict[str, Any]], output_format: str) -> str:
        normalized = output_format.strip().lower() or "json"
        if normalized == "json":
            return json.dumps(rows, separators=(",", ":"), ensure_ascii=True)
        if normalized in {"ndjson", "jsonl"}:
            return "\n".join(
                json.dumps(row, separators=(",", ":"), ensure_ascii=True)
                for row in rows
            )
        if normalized in {"csv", "tsv"}:
            fieldnames = [
                "campaign_id",
                "name",
                "status",
                "version",
                "created_at",
                "updated_at",
                "node_count",
                "edge_count",
                "metadata_json",
            ]
            stream = io.StringIO()
            writer = csv.DictWriter(stream, fieldnames=fieldnames, delimiter="," if normalized == "csv" else "\t")
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
            return stream.getvalue()
        if normalized == "logfmt":
            return "\n".join(
                " ".join(
                    [
                        f"campaign_id={json.dumps(str(row.get('campaign_id', '')).strip(), ensure_ascii=True)}",
                        f"name={json.dumps(str(row.get('name', '')).strip(), ensure_ascii=True)}",
                        f"status={json.dumps(str(row.get('status', '')).strip(), ensure_ascii=True)}",
                        f"version={int(row.get('version', 0) or 0)}",
                        f"created_at={json.dumps(str(row.get('created_at', '')).strip(), ensure_ascii=True)}",
                        f"updated_at={json.dumps(str(row.get('updated_at', '')).strip(), ensure_ascii=True)}",
                        f"node_count={int(row.get('node_count', 0) or 0)}",
                        f"edge_count={int(row.get('edge_count', 0) or 0)}",
                        f"metadata_json={json.dumps(str(row.get('metadata_json', '')).strip(), ensure_ascii=True)}",
                    ]
                )
                for row in rows
            )
        raise ValueError("format must be one of: json, csv, tsv, ndjson, jsonl, logfmt")

    def _campaign_versions_export_media_type(output_format: str) -> str:
        normalized = output_format.strip().lower() or "json"
        if normalized == "json":
            return "application/json"
        if normalized in {"ndjson", "jsonl"}:
            return "application/x-ndjson"
        if normalized == "csv":
            return "text/csv; charset=utf-8"
        if normalized == "tsv":
            return "text/tab-separated-values; charset=utf-8"
        if normalized == "logfmt":
            return "text/plain; charset=utf-8"
        raise ValueError("format must be one of: json, csv, tsv, ndjson, jsonl, logfmt")

    @app.middleware("http")
    async def api_auth_middleware(request: Request, call_next: Any) -> Response:
        method = request.method.upper()
        if await _request_body_too_large(request):
            return _http_request_too_large_response()
        apply_rate_limit = (
            rate_limit_enabled
            and method != "OPTIONS"
            and not _is_rate_limit_exempt(request.url.path)
        )
        if apply_rate_limit:
            allowed, remaining, retry_after_seconds = _rate_limit_consume(_request_client_identity(request))
            if not allowed:
                response = _http_rate_limited_response(retry_after_seconds=retry_after_seconds)
                response.headers["X-RateLimit-Limit"] = str(int(rate_limit_capacity))
                response.headers["X-RateLimit-Remaining"] = str(remaining)
                return response
            setattr(request.state, "rate_limit_remaining", remaining)

        if not auth_enabled:
            response = await call_next(request)
        elif method == "OPTIONS":
            response = await call_next(request)
        elif allow_unauthenticated_health and _is_health_path(request.url.path):
            response = await call_next(request)
        else:
            role = _http_auth_role(request)
            if role is None:
                response = _http_auth_required_response()
            else:
                setattr(request.state, "api_auth_role", role)
                if method in mutation_methods and role != "operator":
                    response = _http_operator_required_response()
                else:
                    response = await call_next(request)

        if apply_rate_limit:
            remaining = max(0, int(getattr(request.state, "rate_limit_remaining", 0)))
            response.headers["X-RateLimit-Limit"] = str(int(rate_limit_capacity))
            response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/status")
    def status() -> dict[str, Any]:
        return orchestrator.status()

    @app.post("/ecosystem/deployments")
    async def ecosystem_register_deployment(request: Request) -> dict[str, Any]:
        _require_ecosystem_enabled()
        payload = await _read_manifest_payload(request)
        source = str(payload.get("source", "api")).strip() or "api"
        try:
            return ecosystem_deployments.register_manifest(payload, source=source)
        except EcosystemDeploymentConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except EcosystemDeploymentError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/deployments/{deployment_id}/activate")
    def ecosystem_activate_deployment(deployment_id: str) -> dict[str, Any]:
        _require_ecosystem_enabled()
        try:
            return ecosystem_deployments.activate(deployment_id)
        except EcosystemDeploymentNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except EcosystemDeploymentConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except EcosystemDeploymentError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.delete("/ecosystem/deployments/{deployment_id}")
    def ecosystem_delete_deployment(deployment_id: str) -> dict[str, Any]:
        _require_ecosystem_enabled()
        try:
            return ecosystem_deployments.delete(deployment_id)
        except EcosystemDeploymentNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except EcosystemDeploymentError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/deployments")
    def ecosystem_list_deployments(
        status: str = Query(default=""),
        source: str = Query(default=""),
        deployment_id_prefix: str = Query(default=""),
        service_name: str = Query(default=""),
        min_session_count: int = Query(default=0, ge=0, le=100000),
        query: str = Query(default=""),
        sort_by: str = Query(default="created_at"),
        sort_order: str = Query(default="desc"),
    ) -> dict[str, Any]:
        _require_ecosystem_enabled()
        try:
            return ecosystem_deployments.list_deployments(
                status=status,
                source=source,
                deployment_id_prefix=deployment_id_prefix,
                service_name=service_name,
                min_session_count=min_session_count,
                query=query,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        except EcosystemDeploymentError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/deployments/{deployment_id}")
    def ecosystem_deployment_detail(deployment_id: str) -> dict[str, Any]:
        _require_ecosystem_enabled()
        try:
            return ecosystem_deployments.deployment_detail(deployment_id)
        except EcosystemDeploymentNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/ecosystem/state")
    def ecosystem_state(
        status: str = Query(default=""),
        source: str = Query(default=""),
        deployment_id_prefix: str = Query(default=""),
        service_name: str = Query(default=""),
        min_session_count: int = Query(default=0, ge=0, le=100000),
        query: str = Query(default=""),
        sort_by: str = Query(default="created_at"),
        sort_order: str = Query(default="desc"),
        include_active_services: bool = Query(default=True),
        include_runtime_deployments: bool = Query(default=True),
    ) -> dict[str, Any]:
        _require_ecosystem_enabled()
        try:
            return ecosystem_deployments.state_snapshot(
                status=status,
                source=source,
                deployment_id_prefix=deployment_id_prefix,
                service_name=service_name,
                min_session_count=min_session_count,
                query=query,
                sort_by=sort_by,
                sort_order=sort_order,
                include_active_services=include_active_services,
                include_runtime_deployments=include_runtime_deployments,
            )
        except EcosystemDeploymentError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/agents/status")
    def ecosystem_agents_status() -> dict[str, Any]:
        _require_ecosystem_enabled()
        return orchestrator.agents_status()

    @app.get("/ecosystem/pripyatsprings/status")
    def ecosystem_pripyatsprings_status() -> dict[str, Any]:
        manager = _pripyatsprings_manager()
        return manager.status()

    @app.post("/ecosystem/pripyatsprings/fingerprints")
    def ecosystem_pripyatsprings_register_fingerprint(payload: dict[str, Any]) -> dict[str, Any]:
        manager = _pripyatsprings_manager()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="pripyatsprings fingerprint payload must be an object")
        try:
            return manager.register_fingerprint(payload)
        except PripyatSpringsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/pripyatsprings/fingerprints")
    def ecosystem_pripyatsprings_fingerprints(
        limit: int = Query(default=200, ge=1, le=2000),
        session_id: str = Query(default=""),
        deployment_id: str = Query(default=""),
        query: str = Query(default=""),
        sort_by: str = Query(default="created_at"),
        sort_order: str = Query(default="desc"),
    ) -> dict[str, Any]:
        manager = _pripyatsprings_manager()
        try:
            return manager.list_fingerprints_filtered(
                limit=limit,
                session_id=session_id,
                deployment_id=deployment_id,
                query=query,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        except PripyatSpringsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/pripyatsprings/hits")
    def ecosystem_pripyatsprings_record_hit(payload: dict[str, Any]) -> dict[str, Any]:
        manager = _pripyatsprings_manager()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="pripyatsprings hit payload must be an object")
        try:
            return manager.record_hit(payload)
        except PripyatSpringsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/pripyatsprings/hits")
    def ecosystem_pripyatsprings_hits(
        limit: int = Query(default=200, ge=1, le=2000),
        fingerprint_id: str = Query(default=""),
        source_ip_prefix: str = Query(default=""),
        session_id: str = Query(default=""),
        deployment_id: str = Query(default=""),
        query: str = Query(default=""),
        created_after: str = Query(default=""),
        created_before: str = Query(default=""),
        sort_by: str = Query(default="created_at"),
        sort_order: str = Query(default="desc"),
    ) -> dict[str, Any]:
        manager = _pripyatsprings_manager()
        try:
            return manager.list_hits_filtered(
                limit=limit,
                fingerprint_id=fingerprint_id,
                source_ip_prefix=source_ip_prefix,
                session_id=session_id,
                deployment_id=deployment_id,
                query=query,
                created_after=created_after,
                created_before=created_before,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        except PripyatSpringsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/pripyatsprings/hits/summary")
    def ecosystem_pripyatsprings_hits_summary(
        limit: int = Query(default=500, ge=1, le=2000),
        fingerprint_id: str = Query(default=""),
        source_ip_prefix: str = Query(default=""),
        session_id: str = Query(default=""),
        deployment_id: str = Query(default=""),
        query: str = Query(default=""),
        created_after: str = Query(default=""),
        created_before: str = Query(default=""),
        sort_by: str = Query(default="created_at"),
        sort_order: str = Query(default="desc"),
    ) -> dict[str, Any]:
        manager = _pripyatsprings_manager()
        try:
            return manager.hit_summary(
                limit=limit,
                fingerprint_id=fingerprint_id,
                source_ip_prefix=source_ip_prefix,
                session_id=session_id,
                deployment_id=deployment_id,
                query=query,
                created_after=created_after,
                created_before=created_before,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        except PripyatSpringsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/adlibs/validate")
    def ecosystem_adlibs_validate() -> dict[str, Any]:
        manager = _adlibs_manager()
        return manager.validate()

    @app.post("/ecosystem/adlibs/seed")
    def ecosystem_adlibs_seed() -> dict[str, Any]:
        manager = _adlibs_manager()
        try:
            return manager.seed()
        except ADLibsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/adlibs/objects")
    def ecosystem_adlibs_objects(
        limit: int = Query(default=200, ge=1, le=2000),
        object_type: str = Query(default=""),
        object_id_prefix: str = Query(default=""),
        name_prefix: str = Query(default=""),
        query: str = Query(default=""),
        sort_by: str = Query(default="created_at"),
        sort_order: str = Query(default="desc"),
    ) -> dict[str, Any]:
        manager = _adlibs_manager()
        try:
            return manager.list_objects_filtered(
                limit=limit,
                object_type=object_type,
                object_id_prefix=object_id_prefix,
                name_prefix=name_prefix,
                query=query,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        except ADLibsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.delete("/ecosystem/adlibs/objects/{object_id}")
    def ecosystem_adlibs_delete_object(object_id: str) -> dict[str, Any]:
        manager = _adlibs_manager()
        try:
            return manager.delete_object(object_id)
        except ADLibsNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ADLibsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/adlibs/trips")
    def ecosystem_adlibs_trips(
        limit: int = Query(default=200, ge=1, le=2000),
        event_type: str = Query(default=""),
        query: str = Query(default=""),
        object_id_prefix: str = Query(default=""),
        source_host_prefix: str = Query(default=""),
        source_user_prefix: str = Query(default=""),
        created_after: str = Query(default=""),
        created_before: str = Query(default=""),
        sort_order: str = Query(default="desc"),
    ) -> dict[str, Any]:
        manager = _adlibs_manager()
        try:
            return manager.list_trips(
                limit=limit,
                event_type=event_type,
                query=query,
                object_id_prefix=object_id_prefix,
                source_host_prefix=source_host_prefix,
                source_user_prefix=source_user_prefix,
                created_after=created_after,
                created_before=created_before,
                sort_order=sort_order,
            )
        except ADLibsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/adlibs/trips/summary")
    def ecosystem_adlibs_trip_summary(
        limit: int = Query(default=500, ge=1, le=2000),
        event_type: str = Query(default=""),
        query: str = Query(default=""),
        object_id_prefix: str = Query(default=""),
        source_host_prefix: str = Query(default=""),
        source_user_prefix: str = Query(default=""),
        created_after: str = Query(default=""),
        created_before: str = Query(default=""),
        sort_order: str = Query(default="desc"),
    ) -> dict[str, Any]:
        manager = _adlibs_manager()
        try:
            return manager.trip_summary(
                limit=limit,
                event_type=event_type,
                query=query,
                object_id_prefix=object_id_prefix,
                source_host_prefix=source_host_prefix,
                source_user_prefix=source_user_prefix,
                created_after=created_after,
                created_before=created_before,
                sort_order=sort_order,
            )
        except ADLibsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/adlibs/events/catalog")
    def ecosystem_adlibs_event_catalog() -> dict[str, Any]:
        manager = _adlibs_manager()
        try:
            return manager.event_catalog()
        except ADLibsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/adlibs/events/ingest")
    def ecosystem_adlibs_ingest_event(payload: dict[str, Any]) -> dict[str, Any]:
        manager = _adlibs_manager()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="adlibs event payload must be an object")
        try:
            return manager.ingest_event(payload)
        except ADLibsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/adlibs/events/ingest/batch")
    def ecosystem_adlibs_ingest_events_batch(
        payload: dict[str, Any],
        continue_on_error: bool = Query(default=True),
    ) -> dict[str, Any]:
        manager = _adlibs_manager()
        rows = payload.get("events")
        if not isinstance(rows, list):
            raise HTTPException(status_code=400, detail="payload must include an 'events' list")
        try:
            return manager.ingest_events(rows, continue_on_error=continue_on_error)
        except ADLibsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/adlibs/trips")
    def ecosystem_adlibs_record_trip(payload: dict[str, Any]) -> dict[str, Any]:
        manager = _adlibs_manager()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="adlibs trip payload must be an object")
        try:
            return manager.record_trip(payload)
        except ADLibsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/dirtylaundry/sessions")
    def ecosystem_dirtylaundry_ingest(payload: dict[str, Any]) -> dict[str, Any]:
        manager = _dirtylaundry_manager()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="dirtylaundry session payload must be an object")
        try:
            return manager.ingest_session(payload)
        except DirtyLaundryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/dirtylaundry/sessions/preview")
    def ecosystem_dirtylaundry_preview(payload: dict[str, Any]) -> dict[str, Any]:
        manager = _dirtylaundry_manager()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="dirtylaundry session payload must be an object")
        try:
            return manager.preview_matches(payload)
        except DirtyLaundryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/dirtylaundry/sessions/evaluate")
    def ecosystem_dirtylaundry_evaluate(payload: dict[str, Any]) -> dict[str, Any]:
        manager = _dirtylaundry_manager()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="dirtylaundry session payload must be an object")
        try:
            return manager.evaluate_policy(payload)
        except DirtyLaundryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/dirtylaundry/sessions/reclassify")
    def ecosystem_dirtylaundry_reclassify(payload: dict[str, Any]) -> dict[str, Any]:
        manager = _dirtylaundry_manager()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="dirtylaundry session payload must be an object")
        try:
            return manager.reclassify_session(payload)
        except DirtyLaundryNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except DirtyLaundryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/dirtylaundry/profiles")
    def ecosystem_dirtylaundry_profiles(
        limit: int = Query(default=200, ge=1, le=2000),
        skill: str = Query(default=""),
        min_sessions: int = Query(default=0, ge=0, le=10000),
        query: str = Query(default=""),
        sort_by: str = Query(default="last_seen_at"),
        sort_order: str = Query(default="desc"),
    ) -> dict[str, Any]:
        manager = _dirtylaundry_manager()
        try:
            return manager.list_profiles(
                limit=limit,
                skill=skill,
                min_sessions=min_sessions,
                query=query,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        except DirtyLaundryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/dirtylaundry/profiles/{profile_id}")
    def ecosystem_dirtylaundry_profile_detail(profile_id: str) -> dict[str, Any]:
        manager = _dirtylaundry_manager()
        try:
            return manager.profile_detail(profile_id)
        except DirtyLaundryNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/ecosystem/dirtylaundry/profiles/{profile_id}/sessions")
    def ecosystem_dirtylaundry_profile_sessions(
        profile_id: str,
        limit: int = Query(default=200, ge=1, le=2000),
        session_prefix: str = Query(default=""),
        query: str = Query(default=""),
        sort_by: str = Query(default="observed_order"),
        sort_order: str = Query(default="asc"),
    ) -> dict[str, Any]:
        manager = _dirtylaundry_manager()
        try:
            return manager.profile_sessions(
                profile_id,
                limit=limit,
                session_prefix=session_prefix,
                query=query,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        except DirtyLaundryNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except DirtyLaundryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/dirtylaundry/profiles/{profile_id}/notes")
    def ecosystem_dirtylaundry_profile_note(profile_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        manager = _dirtylaundry_manager()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="dirtylaundry note payload must be an object")
        note = str(payload.get("note", "")).strip()
        try:
            return manager.add_note(profile_id=profile_id, note=note)
        except DirtyLaundryNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except DirtyLaundryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/dirtylaundry/stats")
    def ecosystem_dirtylaundry_stats() -> dict[str, Any]:
        manager = _dirtylaundry_manager()
        return manager.stats()

    @app.post("/ecosystem/dirtylaundry/share/export")
    def ecosystem_dirtylaundry_share_export(
        format: str = Query(default="native"),
    ) -> dict[str, Any]:
        manager = _dirtylaundry_manager()
        try:
            return manager.share_export(format_name=format)
        except DirtyLaundryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/dirtylaundry/share/import")
    def ecosystem_dirtylaundry_share_import(payload: dict[str, Any]) -> dict[str, Any]:
        manager = _dirtylaundry_manager()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="dirtylaundry share payload must be an object")
        try:
            return manager.share_import(payload)
        except DirtyLaundryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/dirtylaundry/share/push")
    def ecosystem_dirtylaundry_share_push(
        format: str = Query(default="native"),
        endpoint: str = Query(default=""),
    ) -> dict[str, Any]:
        manager = _dirtylaundry_manager()
        try:
            return manager.share_push(format_name=format, endpoint=endpoint)
        except DirtyLaundryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/dirtylaundry/share/pull")
    def ecosystem_dirtylaundry_share_pull(
        endpoint: str = Query(default=""),
    ) -> dict[str, Any]:
        manager = _dirtylaundry_manager()
        try:
            return manager.share_pull(endpoint=endpoint)
        except DirtyLaundryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/jit/deploy")
    def ecosystem_jit_deploy(payload: dict[str, Any]) -> dict[str, Any]:
        manager = _jit_manager()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="jit deployment payload must be an object")
        source = str(payload.get("source", "jit")).strip() or "jit"
        try:
            return manager.deploy(payload, source=source)
        except EcosystemJITError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/jit/pool")
    def ecosystem_jit_pool() -> dict[str, Any]:
        manager = _jit_manager()
        return manager.pool_status()

    @app.get("/ecosystem/jit/deployments")
    def ecosystem_jit_deployments(
        source: str = Query(default=""),
        deployment_id_prefix: str = Query(default=""),
        service_name: str = Query(default=""),
        min_session_count: int = Query(default=0, ge=0, le=100000),
        query: str = Query(default=""),
        sort_by: str = Query(default="activated_at"),
        sort_order: str = Query(default="desc"),
    ) -> dict[str, Any]:
        manager = _jit_manager()
        try:
            return manager.deployments_status_filtered(
                source=source,
                deployment_id_prefix=deployment_id_prefix,
                service_name=service_name,
                min_session_count=min_session_count,
                query=query,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        except EcosystemJITError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/activity/{deployment_id}/inject")
    def ecosystem_activity_inject(deployment_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        _require_ecosystem_enabled()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="activity payload must be an object")
        try:
            result = ecosystem_activity.inject(deployment_id=deployment_id, payload=payload)
            if ecosystem_jit_enabled and ecosystem_jit is not None:
                ecosystem_jit.touch_deployment(
                    deployment_id=deployment_id,
                    session_id=str(payload.get("session_id", "")).strip() or None,
                )
            return result
        except EcosystemActivityNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except EcosystemActivityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/activity/{deployment_id}")
    def ecosystem_activity_list(
        deployment_id: str,
        limit: int = Query(default=200, ge=1, le=2000),
        schedule_mode: str = Query(default=""),
        active: bool | None = Query(default=None),
        query: str = Query(default=""),
        sort_by: str = Query(default="created_at"),
        sort_order: str = Query(default="desc"),
    ) -> dict[str, Any]:
        _require_ecosystem_enabled()
        try:
            return ecosystem_activity.list_filtered(
                deployment_id=deployment_id,
                limit=limit,
                schedule_mode=schedule_mode,
                active=active,
                query=query,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        except EcosystemActivityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.delete("/ecosystem/activity/{deployment_id}/{activity_id}")
    def ecosystem_activity_delete(deployment_id: str, activity_id: str) -> dict[str, Any]:
        _require_ecosystem_enabled()
        try:
            return ecosystem_activity.cancel(deployment_id=deployment_id, activity_id=activity_id)
        except EcosystemActivityNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except EcosystemActivityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/witchbait/credentials")
    def ecosystem_witchbait_register(payload: dict[str, Any]) -> dict[str, Any]:
        manager = _witchbait_manager()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="credential payload must be an object")
        try:
            return manager.register_credential(payload, source="api")
        except EcosystemWitchbaitConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except EcosystemWitchbaitError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/witchbait/credentials/preview")
    def ecosystem_witchbait_preview(payload: dict[str, Any]) -> dict[str, Any]:
        manager = _witchbait_manager()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="credential preview payload must be an object")
        try:
            return manager.preview_credentials(payload)
        except EcosystemWitchbaitError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.delete("/ecosystem/witchbait/credentials/{credential_id}")
    def ecosystem_witchbait_delete(credential_id: str) -> dict[str, Any]:
        manager = _witchbait_manager()
        try:
            return manager.delete_credential(credential_id)
        except EcosystemWitchbaitNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except EcosystemWitchbaitError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/witchbait/credentials")
    def ecosystem_witchbait_list(
        limit: int = Query(default=200, ge=1, le=2000),
        credential_type: str = Query(default=""),
        source: str = Query(default=""),
        target_decoy_id: str = Query(default=""),
        query: str = Query(default=""),
        sort_by: str = Query(default="created_at"),
        sort_order: str = Query(default="desc"),
    ) -> dict[str, Any]:
        manager = _witchbait_manager()
        try:
            return manager.list_credentials_filtered(
                limit=limit,
                credential_type=credential_type,
                source=source,
                target_decoy_id=target_decoy_id,
                query=query,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        except EcosystemWitchbaitError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/witchbait/trips")
    def ecosystem_witchbait_trips(
        limit: int = Query(default=200, ge=1, le=2000),
        credential_id: str = Query(default=""),
        service: str = Query(default=""),
        action: str = Query(default=""),
        matched_field: str = Query(default=""),
        source_ip_prefix: str = Query(default=""),
        session_prefix: str = Query(default=""),
        query: str = Query(default=""),
        created_after: str = Query(default=""),
        created_before: str = Query(default=""),
        sort_by: str = Query(default="created_at"),
        sort_order: str = Query(default="desc"),
    ) -> dict[str, Any]:
        manager = _witchbait_manager()
        try:
            return manager.list_trips_filtered(
                limit=limit,
                credential_id=credential_id,
                service=service,
                action=action,
                matched_field=matched_field,
                source_ip_prefix=source_ip_prefix,
                session_prefix=session_prefix,
                query=query,
                created_after=created_after,
                created_before=created_before,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        except EcosystemWitchbaitError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/witchbait/trips/summary")
    def ecosystem_witchbait_trip_summary(
        limit: int = Query(default=500, ge=1, le=2000),
        credential_id: str = Query(default=""),
        service: str = Query(default=""),
        action: str = Query(default=""),
        matched_field: str = Query(default=""),
        source_ip_prefix: str = Query(default=""),
        session_prefix: str = Query(default=""),
        query: str = Query(default=""),
        created_after: str = Query(default=""),
        created_before: str = Query(default=""),
        sort_by: str = Query(default="created_at"),
        sort_order: str = Query(default="desc"),
    ) -> dict[str, Any]:
        manager = _witchbait_manager()
        try:
            return manager.trip_summary(
                limit=limit,
                credential_id=credential_id,
                service=service,
                action=action,
                matched_field=matched_field,
                source_ip_prefix=source_ip_prefix,
                session_prefix=session_prefix,
                query=query,
                created_after=created_after,
                created_before=created_before,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        except EcosystemWitchbaitError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/ecosystem/drift/snapshot")
    def ecosystem_drift_snapshot(
        limit: int = Query(default=2000, ge=1, le=2000),
        protocol: str = Query(default=""),
        source: str = Query(default=""),
        deployment_id_prefix: str = Query(default=""),
        service_prefix: str = Query(default=""),
        running: str = Query(default=""),
        query: str = Query(default=""),
        sort_by: str = Query(default="deployment_activated_at"),
        sort_order: str = Query(default="desc"),
    ) -> dict[str, Any]:
        _require_ecosystem_enabled()
        try:
            return ecosystem_drift.snapshot_filtered(
                limit=limit,
                protocol=protocol,
                source=source,
                deployment_id_prefix=deployment_id_prefix,
                service_prefix=service_prefix,
                running=running,
                query=query,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/ecosystem/drift/compare")
    def ecosystem_drift_compare(payload: dict[str, Any]) -> dict[str, Any]:
        _require_ecosystem_enabled()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="drift compare payload must be an object")
        try:
            result = ecosystem_drift.compare(payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if bool(result.get("below_threshold")):
            orchestrator.event_logger.emit(
                message="ecosystem drift threshold breached",
                service="ecosystem",
                action="drift_alert",
                event_type="alert",
                outcome="warning",
                payload={
                    "threshold": result.get("threshold"),
                    "believability_score": result.get("believability_score"),
                    "match_count": result.get("count"),
                },
                level="WARNING",
            )
        return result

    @app.get("/dashboard/summary")
    def dashboard_summary(
        report_limit: int = Query(default=200, ge=1, le=1000),
        report_events_per_session: int = Query(default=200, ge=0, le=2000),
        map_limit: int = Query(default=200, ge=1, le=1000),
        map_events_per_session: int = Query(default=10, ge=0, le=2000),
        canary_limit: int = Query(default=8, ge=1, le=1000),
        route_severity: str = Query(default="medium"),
        route_service: str = Query(default="ops"),
        route_action: str = Query(default="alert_test"),
        route_title: str = Query(default="manual_alert_test"),
        route_apply_throttle: bool = Query(default=False),
        include_templates: bool = Query(default=False),
        include_doctor: bool = Query(default=False),
        include_alert_routes: bool = Query(default=True),
        include_handoff: bool = Query(default=False),
        doctor_check_llm: bool = Query(default=False),
    ) -> dict[str, Any]:
        report = _resolve_live_report(
            limit=report_limit,
            events_per_session=report_events_per_session,
            ttl_seconds=5.0,
        )
        canaries = report.get("canaries", {})
        if not isinstance(canaries, dict):
            canaries = {}
        engagement_map = _summary_cache_get(
            f"dashboard:map:{map_limit}:{map_events_per_session}",
            ttl_seconds=5.0,
            build=lambda: build_engagement_map(
                orchestrator.session_manager.export_sessions(limit=map_limit, events_per_session=map_events_per_session)
            ),
        )
        normalized_severity = route_severity.strip().lower() or "medium"
        if normalized_severity not in {"low", "medium", "high", "critical"}:
            raise HTTPException(status_code=400, detail="invalid severity")
        payload: dict[str, Any] = {
            "status": orchestrator.status(),
            "intel": report,
            "map": engagement_map,
            "canaries": canaries,
            "canary_inventory": _summary_cache_get(
                f"dashboard:canary_inventory:{canary_limit}",
                ttl_seconds=5.0,
                build=lambda: orchestrator.canary_tokens(limit=canary_limit),
            ),
            "canary_hits": _summary_cache_get(
                f"dashboard:canary_hits:{canary_limit}",
                ttl_seconds=5.0,
                build=lambda: orchestrator.canary_hits(limit=canary_limit),
            ),
            "canary_types": canary_types_payload,
            "threat_preview": _summary_cache_get(
                "dashboard:threat_preview",
                ttl_seconds=10.0,
                build=lambda: {"threat_intel": orchestrator.threat_intel_preview()},
            ),
            "alerts": orchestrator.alert_router.snapshot(),
        }
        if include_alert_routes:
            payload["alert_routes"] = orchestrator.alert_routes(
                severity=normalized_severity,
                service=route_service.strip() or "ops",
                action=route_action.strip() or "alert_test",
                title=route_title.strip() or "manual_alert_test",
                apply_throttle=route_apply_throttle,
            )
        if include_templates:
            payload["template_inventory"] = _summary_cache_get(
                "dashboard:template_inventory",
                ttl_seconds=45.0,
                build=orchestrator.template_inventory,
            )
            payload["template_plan"] = _summary_cache_get(
                "dashboard:template_plan:default",
                ttl_seconds=45.0,
                build=lambda: orchestrator.service_plan(),
            )
            payload["template_plan_all"] = _summary_cache_get(
                "dashboard:template_plan:all",
                ttl_seconds=45.0,
                build=lambda: orchestrator.service_plan(all_tenants=True),
            )
            payload["template_validation"] = _summary_cache_get(
                "dashboard:template_validation:default",
                ttl_seconds=45.0,
                build=orchestrator.template_validation,
            )
            payload["template_validation_all"] = _summary_cache_get(
                "dashboard:template_validation:all",
                ttl_seconds=45.0,
                build=lambda: orchestrator.template_validation(all_tenants=True),
            )
            payload["template_diff"] = _summary_cache_get(
                "dashboard:template_diff",
                ttl_seconds=45.0,
                build=orchestrator.service_plan_diff,
            )
            payload["template_diff_matrix"] = _summary_cache_get(
                "dashboard:template_diff_matrix",
                ttl_seconds=45.0,
                build=orchestrator.service_plan_diff_matrix,
            )
        if include_doctor:
            payload["doctor"] = _summary_cache_get(
                f"dashboard:doctor:{1 if doctor_check_llm else 0}",
                ttl_seconds=30.0,
                build=lambda: run_diagnostics(orchestrator.config, check_llm=doctor_check_llm),
            )
        if include_handoff:
            payload["handoff"] = build_soc_handoff(
                report,
                max_techniques=5,
                max_sessions=5,
            )
        return payload

    @app.get("/templates/inventory")
    def templates_inventory() -> dict[str, Any]:
        return orchestrator.template_inventory()

    @app.get("/templates/plan")
    def templates_plan(
        tenant_id: str | None = Query(default=None),
        apply_threat_rotation: bool = Query(default=True),
        all_tenants: bool = Query(default=False),
    ) -> dict[str, Any]:
        return orchestrator.service_plan(
            tenant_id=tenant_id,
            apply_threat_rotation=apply_threat_rotation,
            all_tenants=all_tenants,
        )

    @app.get("/templates/validate")
    def templates_validate(
        tenant_id: str | None = Query(default=None),
        all_tenants: bool = Query(default=False),
    ) -> dict[str, Any]:
        return orchestrator.template_validation(tenant_id=tenant_id, all_tenants=all_tenants)

    @app.get("/templates/diff")
    def templates_diff(
        left_tenant_id: str | None = Query(default=None),
        right_tenant_id: str | None = Query(default=None),
        apply_threat_rotation: bool = Query(default=True),
    ) -> dict[str, Any]:
        return orchestrator.service_plan_diff(
            left_tenant_id=left_tenant_id,
            right_tenant_id=right_tenant_id,
            apply_threat_rotation=apply_threat_rotation,
        )

    @app.get("/templates/diff/matrix")
    def templates_diff_matrix(
        tenant_id: str | None = Query(default=None),
        apply_threat_rotation: bool = Query(default=True),
    ) -> dict[str, Any]:
        return orchestrator.service_plan_diff_matrix(
            tenant_id=tenant_id,
            apply_threat_rotation=apply_threat_rotation,
        )

    @app.get("/campaigns")
    def campaigns(
        limit: int = Query(default=100, ge=1, le=500),
        status: str | None = Query(default=None),
        campaign_id_prefix: str = Query(default=""),
        name_prefix: str = Query(default=""),
        min_nodes: int = Query(default=0, ge=0, le=10000),
        min_edges: int = Query(default=0, ge=0, le=10000),
        query: str = Query(default=""),
        sort_by: str = Query(default="updated_at"),
        sort_order: str = Query(default="desc"),
        compact: bool = Query(default=False),
    ) -> dict[str, Any]:
        normalized_status = str(status or "").strip().lower()
        if normalized_status and normalized_status not in VALID_CAMPAIGN_STATUSES:
            raise HTTPException(status_code=400, detail="invalid campaign status")
        cache_key = (
            "campaigns:"
            f"{limit}:{normalized_status or '*'}:{campaign_id_prefix.strip().lower()}:"
            f"{name_prefix.strip().lower()}:{int(min_nodes)}:{int(min_edges)}:{query.strip().lower()}:"
            f"{sort_by.strip().lower()}:{sort_order.strip().lower()}:{int(compact)}"
        )

        def _build_campaigns() -> dict[str, Any]:
            return orchestrator.campaign_graphs(
                limit=limit,
                status=normalized_status or None,
                campaign_id_prefix=campaign_id_prefix,
                name_prefix=name_prefix,
                min_nodes=min_nodes,
                min_edges=min_edges,
                query=query,
                sort_by=sort_by,
                sort_order=sort_order,
                compact=compact,
            )

        try:
            return _summary_cache_get(
                cache_key,
                ttl_seconds=1.0,
                build=_build_campaigns,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/campaigns/export")
    def campaigns_export(
        output_format: str = Query(default="json", alias="format"),
        limit: int = Query(default=100, ge=1, le=500),
        status: str | None = Query(default=None),
        campaign_id_prefix: str = Query(default=""),
        name_prefix: str = Query(default=""),
        min_nodes: int = Query(default=0, ge=0, le=10000),
        min_edges: int = Query(default=0, ge=0, le=10000),
        query: str = Query(default=""),
        sort_by: str = Query(default="updated_at"),
        sort_order: str = Query(default="desc"),
        compact: bool = Query(default=True),
    ) -> Any:
        normalized_status = str(status or "").strip().lower()
        if normalized_status and normalized_status not in VALID_CAMPAIGN_STATUSES:
            raise HTTPException(status_code=400, detail="invalid campaign status")
        cache_key = (
            "campaigns:"
            f"{limit}:{normalized_status or '*'}:{campaign_id_prefix.strip().lower()}:"
            f"{name_prefix.strip().lower()}:{int(min_nodes)}:{int(min_edges)}:{query.strip().lower()}:"
            f"{sort_by.strip().lower()}:{sort_order.strip().lower()}:{int(compact)}"
        )

        def _build_campaigns_for_export() -> dict[str, Any]:
            return orchestrator.campaign_graphs(
                limit=limit,
                status=normalized_status or None,
                campaign_id_prefix=campaign_id_prefix,
                name_prefix=name_prefix,
                min_nodes=min_nodes,
                min_edges=min_edges,
                query=query,
                sort_by=sort_by,
                sort_order=sort_order,
                compact=compact,
            )

        try:
            payload = _summary_cache_get(
                cache_key,
                ttl_seconds=1.0,
                build=_build_campaigns_for_export,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        campaigns_payload = payload.get("campaigns")
        if not isinstance(campaigns_payload, list):
            campaigns_payload = []
        rows = _campaign_inventory_export_rows(campaigns_payload)
        normalized_output_format = output_format.strip().lower() or "json"
        if normalized_output_format == "json":
            return {
                "count": len(rows),
                "campaigns": rows,
                "filters": dict(payload.get("filters", {})),
                "sort": dict(payload.get("sort", {})),
            }
        try:
            rendered = _summary_cache_get(
                f"{cache_key}:campaign_inventory_export:{normalized_output_format}",
                ttl_seconds=1.0,
                build=lambda: _render_campaign_inventory_export(
                    rows=rows,
                    output_format=normalized_output_format,
                ),
            )
            media_type = _campaign_versions_export_media_type(normalized_output_format)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return Response(content=rendered, media_type=media_type)

    @app.post("/campaigns/import")
    def campaign_import(payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="campaign import payload must be an object")
        schema = str(payload.get("schema", "")).strip()
        if schema and schema != CAMPAIGN_EXPORT_SCHEMA:
            raise HTTPException(status_code=400, detail="unsupported campaign import schema")
        raw_campaign = payload.get("campaign")
        if not isinstance(raw_campaign, dict):
            raise HTTPException(status_code=400, detail="campaign import requires a campaign object")
        campaign_id = _normalize_campaign_id(
            str(payload.get("campaign_id") or raw_campaign.get("campaign_id") or "").strip()
        )
        normalized_payload = _normalize_campaign_payload(raw_campaign)
        result = orchestrator.campaign_upsert(
            campaign_id=campaign_id,
            name=normalized_payload["name"],
            status=normalized_payload["status"],
            nodes=normalized_payload["nodes"],
            edges=normalized_payload["edges"],
            metadata={
                **normalized_payload["metadata"],
                "imported": True,
            },
        )
        if not bool(result.get("saved")):
            raise HTTPException(status_code=500, detail="failed to import campaign")
        return {
            "imported": True,
            "campaign_id": campaign_id,
            "campaign": result.get("campaign"),
            "store": result.get("store", {}),
        }

    @app.get("/campaigns/{campaign_id}")
    def campaign(campaign_id: str) -> dict[str, Any]:
        normalized_campaign_id = _normalize_campaign_id(campaign_id)
        payload = orchestrator.campaign_graph(campaign_id=normalized_campaign_id)
        if not bool(payload.get("found")):
            raise HTTPException(status_code=404, detail="campaign not found")
        return payload

    @app.get("/campaigns/{campaign_id}/versions")
    def campaign_versions(
        campaign_id: str,
        limit: int = Query(default=100, ge=1, le=500),
        event_type: str = Query(default=""),
        min_version: int = Query(default=0, ge=0, le=100000),
        max_version: int = Query(default=0, ge=0, le=100000),
        query: str = Query(default=""),
        sort_by: str = Query(default="version"),
        sort_order: str = Query(default="desc"),
        compact: bool = Query(default=False),
    ) -> dict[str, Any]:
        normalized_campaign_id = _normalize_campaign_id(campaign_id)
        versions_cache_key = (
            "campaign_versions:"
            f"{normalized_campaign_id}:{limit}:{event_type.strip().lower()}:"
            f"{int(min_version)}:{int(max_version)}:{query.strip().lower()}:"
            f"{sort_by.strip().lower()}:{sort_order.strip().lower()}:{int(compact)}"
        )

        def _build_campaign_versions() -> dict[str, Any]:
            return orchestrator.campaign_versions(
                campaign_id=normalized_campaign_id,
                limit=limit,
                event_type=event_type,
                min_version=min_version,
                max_version=max_version,
                query=query,
                sort_by=sort_by,
                sort_order=sort_order,
                compact=compact,
            )

        try:
            payload = _summary_cache_get(
                versions_cache_key,
                ttl_seconds=1.0,
                build=_build_campaign_versions,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not bool(payload.get("found")):
            raise HTTPException(status_code=404, detail="campaign not found")
        return payload

    @app.get("/campaigns/{campaign_id}/versions/export")
    def campaign_versions_export(
        campaign_id: str,
        output_format: str = Query(default="json", alias="format"),
        limit: int = Query(default=100, ge=1, le=500),
        event_type: str = Query(default=""),
        min_version: int = Query(default=0, ge=0, le=100000),
        max_version: int = Query(default=0, ge=0, le=100000),
        query: str = Query(default=""),
        sort_by: str = Query(default="version"),
        sort_order: str = Query(default="desc"),
        compact: bool = Query(default=True),
    ) -> Any:
        normalized_campaign_id = _normalize_campaign_id(campaign_id)
        versions_cache_key = (
            "campaign_versions:"
            f"{normalized_campaign_id}:{limit}:{event_type.strip().lower()}:"
            f"{int(min_version)}:{int(max_version)}:{query.strip().lower()}:"
            f"{sort_by.strip().lower()}:{sort_order.strip().lower()}:{int(compact)}"
        )

        def _build_campaign_versions_export_payload() -> dict[str, Any]:
            return orchestrator.campaign_versions(
                campaign_id=normalized_campaign_id,
                limit=limit,
                event_type=event_type,
                min_version=min_version,
                max_version=max_version,
                query=query,
                sort_by=sort_by,
                sort_order=sort_order,
                compact=compact,
            )

        try:
            payload = _summary_cache_get(
                versions_cache_key,
                ttl_seconds=1.0,
                build=_build_campaign_versions_export_payload,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not bool(payload.get("found")):
            raise HTTPException(status_code=404, detail="campaign not found")

        versions = payload.get("versions")
        if not isinstance(versions, list):
            versions = []
        rows = _campaign_versions_export_rows(versions)
        normalized_output_format = output_format.strip().lower() or "json"
        if normalized_output_format == "json":
            return {
                "campaign_id": normalized_campaign_id,
                "count": len(rows),
                "versions": rows,
                "filters": dict(payload.get("filters", {})),
                "sort": dict(payload.get("sort", {})),
            }
        try:
            rendered = _summary_cache_get(
                f"{versions_cache_key}:campaign_versions_export:{normalized_output_format}",
                ttl_seconds=1.0,
                build=lambda: _render_campaign_versions_export(
                    rows=rows,
                    output_format=normalized_output_format,
                ),
            )
            media_type = _campaign_versions_export_media_type(normalized_output_format)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return Response(content=rendered, media_type=media_type)

    @app.get("/campaigns/{campaign_id}/export")
    def campaign_export(
        campaign_id: str,
        include_versions: bool = Query(default=False),
        version_limit: int = Query(default=100, ge=1, le=500),
        version_event_type: str = Query(default=""),
        version_min: int = Query(default=0, ge=0, le=100000),
        version_max: int = Query(default=0, ge=0, le=100000),
        version_query: str = Query(default=""),
        version_sort_by: str = Query(default="version"),
        version_sort_order: str = Query(default="desc"),
        version_compact: bool = Query(default=False),
    ) -> dict[str, Any]:
        normalized_campaign_id = _normalize_campaign_id(campaign_id)
        payload = orchestrator.campaign_graph(campaign_id=normalized_campaign_id)
        if not bool(payload.get("found")):
            raise HTTPException(status_code=404, detail="campaign not found")
        package: dict[str, Any] = {
            "schema": CAMPAIGN_EXPORT_SCHEMA,
            "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "campaign": payload.get("campaign"),
        }
        if include_versions:
            versions_cache_key = (
                "campaign_versions:"
                f"{normalized_campaign_id}:{version_limit}:{version_event_type.strip().lower()}:"
                f"{int(version_min)}:{int(version_max)}:{version_query.strip().lower()}:"
                f"{version_sort_by.strip().lower()}:{version_sort_order.strip().lower()}:{int(version_compact)}"
            )

            def _build_campaign_versions_for_export() -> dict[str, Any]:
                return orchestrator.campaign_versions(
                    campaign_id=normalized_campaign_id,
                    limit=version_limit,
                    event_type=version_event_type,
                    min_version=version_min,
                    max_version=version_max,
                    query=version_query,
                    sort_by=version_sort_by,
                    sort_order=version_sort_order,
                    compact=version_compact,
                )

            try:
                versions_payload = _summary_cache_get(
                    versions_cache_key,
                    ttl_seconds=1.0,
                    build=_build_campaign_versions_for_export,
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            package["versions"] = versions_payload.get("versions", [])
            package["version_count"] = int(versions_payload.get("count", 0) or 0)
        return package

    @app.put("/campaigns/{campaign_id}")
    def campaign_upsert(campaign_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        normalized_campaign_id = _normalize_campaign_id(campaign_id)
        normalized_payload = _normalize_campaign_payload(payload)
        result = orchestrator.campaign_upsert(
            campaign_id=normalized_campaign_id,
            name=normalized_payload["name"],
            status=normalized_payload["status"],
            nodes=normalized_payload["nodes"],
            edges=normalized_payload["edges"],
            metadata=normalized_payload["metadata"],
        )
        if not bool(result.get("saved")):
            raise HTTPException(status_code=500, detail="failed to persist campaign")
        return result

    @app.post("/campaigns/{campaign_id}/status")
    def campaign_status(campaign_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="campaign status payload must be an object")
        normalized_campaign_id = _normalize_campaign_id(campaign_id)
        status = str(payload.get("status", "")).strip().lower()
        if status not in VALID_CAMPAIGN_STATUSES:
            raise HTTPException(status_code=400, detail="invalid campaign status")
        metadata = _normalize_campaign_metadata(payload.get("metadata", {}))
        result = orchestrator.campaign_set_status(
            campaign_id=normalized_campaign_id,
            status=status,
            metadata=metadata,
        )
        if not bool(result.get("updated")):
            raise HTTPException(status_code=404, detail="campaign not found")
        return result

    @app.delete("/campaigns/{campaign_id}")
    def campaign_delete(campaign_id: str) -> dict[str, Any]:
        normalized_campaign_id = _normalize_campaign_id(campaign_id)
        result = orchestrator.campaign_delete(campaign_id=normalized_campaign_id)
        if not bool(result.get("deleted")):
            raise HTTPException(status_code=404, detail="campaign not found")
        return result

    @app.get("/sessions")
    def sessions(
        limit: int = Query(default=100, ge=1, le=500),
        events_per_session: int = Query(default=100, ge=0, le=1000),
    ) -> dict[str, Any]:
        items = orchestrator.session_manager.export_sessions(limit=limit, events_per_session=events_per_session)
        return {"sessions": items, "count": len(items)}

    @app.get("/sessions/{session_id}/replay")
    def session_replay(
        session_id: str,
        events_limit: int = Query(default=500, ge=0, le=5000),
    ) -> dict[str, Any]:
        return orchestrator.session_replay(session_id=session_id, events_limit=events_limit)

    @app.get("/sessions/replay/compare")
    def session_replay_compare(
        left_session_id: str = Query(min_length=1),
        right_session_id: str = Query(min_length=1),
        events_limit: int = Query(default=500, ge=0, le=5000),
    ) -> dict[str, Any]:
        payload = orchestrator.session_replay_compare(
            left_session_id=left_session_id,
            right_session_id=right_session_id,
            events_limit=events_limit,
        )
        if not bool(payload.get("found")):
            raise HTTPException(status_code=404, detail="session replay not found")
        return payload

    @app.get("/theater/live")
    def theater_live(
        limit: int = Query(default=100, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
    ) -> dict[str, Any]:
        return _summary_cache_get(
            f"theater:live:{limit}:{events_per_session}",
            ttl_seconds=1.0,
            build=lambda: orchestrator.theater_live(limit=limit, events_per_session=events_per_session),
        )

    @app.get("/theater/sessions/{session_id}")
    def theater_session(
        session_id: str,
        events_limit: int = Query(default=500, ge=0, le=5000),
    ) -> dict[str, Any]:
        payload = orchestrator.theater_session(session_id=session_id, events_limit=events_limit)
        if payload is None:
            raise HTTPException(status_code=404, detail="theater session not found")
        return payload

    @app.get("/theater/sessions/{session_id}/bundle")
    def theater_session_bundle(
        session_id: str,
        events_limit: int = Query(default=500, ge=0, le=5000),
    ) -> dict[str, Any]:
        replay = orchestrator.session_replay(session_id=session_id, events_limit=events_limit)
        session_payload = orchestrator.theater_session(session_id=session_id, events_limit=events_limit)
        replay_found = bool(replay.get("found"))
        session_found = session_payload is not None
        if not replay_found and not session_found:
            raise HTTPException(status_code=404, detail="theater session not found")
        return {
            "found": replay_found or session_found,
            "session_id": session_id,
            "replay": replay,
            "theater_session": session_payload,
        }

    @app.get("/theater/recommendations")
    def theater_recommendations(
        limit: int = Query(default=20, ge=1, le=200),
        session_limit: int = Query(default=100, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
        min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
        min_prediction_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
        predicted_stage: str | None = Query(default=None),
        lure_arm: str | None = Query(default=None),
        context_key_prefix: str | None = Query(default=None),
        apply_allowed_only: bool = Query(default=False),
        include_explanation: bool = Query(default=True),
        compact: bool = Query(default=False),
        sort_by: Literal["confidence", "prediction_confidence", "session_id", "queue_position"] = Query(default="confidence"),
        sort_order: Literal["asc", "desc"] = Query(default="desc"),
    ) -> dict[str, Any]:
        payload = _summary_cache_get(
            f"theater:recommendations:{limit}:{session_limit}:{events_per_session}",
            ttl_seconds=1.0,
            build=lambda: orchestrator.theater_recommendations(
                limit=limit,
                session_limit=session_limit,
                events_per_session=events_per_session,
            ),
        )
        recommendations_raw = payload.get("recommendations", [])
        recommendations = recommendations_raw if isinstance(recommendations_raw, list) else []
        normalized_predicted_stage = str(predicted_stage or "").strip().lower()
        normalized_lure_arm = str(lure_arm or "").strip().lower()
        normalized_context_prefix = str(context_key_prefix or "").strip().lower()
        filtered: list[dict[str, Any]] = []
        for item in recommendations:
            if not isinstance(item, dict):
                continue
            confidence = max(0.0, min(1.0, float(item.get("confidence", 0.0) or 0.0)))
            if confidence < float(min_confidence):
                continue
            prediction_confidence = max(0.0, min(1.0, float(item.get("prediction_confidence", 0.0) or 0.0)))
            if prediction_confidence < float(min_prediction_confidence):
                continue
            stage = str(item.get("predicted_stage", "")).strip().lower()
            if normalized_predicted_stage and stage != normalized_predicted_stage:
                continue
            recommended_lure_arm = str(item.get("recommended_lure_arm", "")).strip().lower()
            if normalized_lure_arm and recommended_lure_arm != normalized_lure_arm:
                continue
            context_key = str(item.get("context_key", "")).strip().lower()
            if normalized_context_prefix and not context_key.startswith(normalized_context_prefix):
                continue
            apply_allowed = bool(item.get("apply_allowed"))
            if apply_allowed_only and not apply_allowed:
                continue
            filtered_item = dict(item)
            if not include_explanation:
                filtered_item.pop("explanation", None)
            filtered.append(filtered_item)
        reverse = sort_order == "desc"
        if sort_by in {"confidence", "prediction_confidence", "queue_position"}:
            filtered.sort(
                key=lambda item: float(item.get(sort_by, 0.0) or 0.0),
                reverse=reverse,
            )
        else:
            filtered.sort(
                key=lambda item: str(item.get("session_id", "")).strip().lower(),
                reverse=reverse,
            )
        for index, item in enumerate(filtered, start=1):
            item["result_rank"] = index
        if compact:
            compact_fields = {
                "recommendation_id",
                "session_id",
                "context_key",
                "recommended_lure_arm",
                "predicted_stage",
                "predicted_action",
                "confidence",
                "prediction_confidence",
                "apply_allowed",
                "queue_position",
                "result_rank",
                "explanation_digest",
            }
            filtered = [
                {key: value for key, value in item.items() if key in compact_fields}
                for item in filtered
            ]
        payload["recommendations"] = filtered
        payload["count"] = len(filtered)
        payload["filtering"] = {
            "min_confidence": float(min_confidence),
            "min_prediction_confidence": float(min_prediction_confidence),
            "predicted_stage": normalized_predicted_stage,
            "lure_arm": normalized_lure_arm,
            "context_key_prefix": normalized_context_prefix,
            "apply_allowed_only": apply_allowed_only,
            "include_explanation": include_explanation,
            "compact": compact,
            "sort_by": sort_by,
            "sort_order": sort_order,
        }
        return payload

    @app.get("/theater/actions")
    def theater_actions(
        limit: int = Query(default=200, ge=1, le=2000),
        session_id: str | None = Query(default=None),
        session_ids: str | None = Query(default=None),
        action_type: str | None = Query(default=None),
        action_types: str | None = Query(default=None),
        actor: str | None = Query(default=None),
        actor_prefix: str | None = Query(default=None),
        session_prefix: str | None = Query(default=None),
        query: str | None = Query(default=None),
        recommendation_id: str | None = Query(default=None),
        created_after: str | None = Query(default=None),
        created_before: str | None = Query(default=None),
        compact: bool = Query(default=False),
        sort_by: Literal["created_at", "session_id", "action_type", "actor"] = Query(default="created_at"),
        sort_order: Literal["asc", "desc"] = Query(default="desc"),
    ) -> dict[str, Any]:
        def _parse_filter_timestamp(raw: str | None, *, field_name: str) -> datetime | None:
            value = str(raw or "").strip()
            if not value:
                return None
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"{field_name} must be ISO-8601") from exc
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)

        def _parse_item_timestamp(item: dict[str, Any]) -> datetime | None:
            raw = str(item.get("created_at", "")).strip()
            if not raw:
                return None
            try:
                parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                return None
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)

        def _parse_action_type_filters(raw: str | None) -> list[str]:
            value = str(raw or "").strip()
            if not value:
                return []
            normalized = {token.strip().lower() for token in value.split(",") if token.strip()}
            return sorted(normalized)

        normalized_session = str(session_id or "").strip()
        normalized_session_lower = normalized_session.lower()
        raw_session_ids = [token.strip() for token in str(session_ids or "").split(",") if token.strip()]
        normalized_session_ids = sorted({token.lower() for token in raw_session_ids})
        if normalized_session_lower and normalized_session_lower not in normalized_session_ids:
            normalized_session_ids.append(normalized_session_lower)
            normalized_session_ids = sorted(set(normalized_session_ids))
            raw_session_ids.append(normalized_session)
        normalized_session_ids_set = set(normalized_session_ids)
        normalized_session_ids_key = ",".join(normalized_session_ids)
        base_session_id = normalized_session if len(normalized_session_ids) <= 1 else ""
        if not base_session_id and len(raw_session_ids) == 1:
            base_session_id = raw_session_ids[0]
        normalized_action_type = str(action_type or "").strip().lower()
        normalized_action_types = _parse_action_type_filters(action_types)
        if normalized_action_type and normalized_action_type not in normalized_action_types:
            normalized_action_types.append(normalized_action_type)
            normalized_action_types = sorted(set(normalized_action_types))
        normalized_action_types_set = set(normalized_action_types)
        base_action_type = normalized_action_types[0] if len(normalized_action_types) == 1 else None
        normalized_action_types_key = ",".join(normalized_action_types)
        created_after_dt = _parse_filter_timestamp(created_after, field_name="created_after")
        created_before_dt = _parse_filter_timestamp(created_before, field_name="created_before")
        if created_after_dt is not None and created_before_dt is not None and created_after_dt > created_before_dt:
            raise HTTPException(status_code=400, detail="created_after must be <= created_before")
        normalized_actor = str(actor or "").strip().lower()
        normalized_actor_prefix = str(actor_prefix or "").strip().lower()
        normalized_session_prefix = str(session_prefix or "").strip().lower()
        normalized_query = str(query or "").strip().lower()
        normalized_recommendation_id = str(recommendation_id or "").strip().lower()
        normalized_created_after = created_after_dt.isoformat() if created_after_dt is not None else ""
        normalized_created_before = created_before_dt.isoformat() if created_before_dt is not None else ""
        epoch_utc = datetime.fromtimestamp(0, tz=timezone.utc)

        def _build_filtered_payload() -> dict[str, Any]:
            payload = _summary_cache_get(
                f"theater:actions:{limit}:{base_session_id}:{normalized_session_ids_key}:{normalized_action_types_key}",
                ttl_seconds=1.0,
                build=lambda: orchestrator.theater_actions(
                    limit=limit,
                    session_id=base_session_id or None,
                    action_type=base_action_type,
                ),
            )
            actions_raw = payload.get("actions", [])
            actions = actions_raw if isinstance(actions_raw, list) else []
            filtered: list[dict[str, Any]] = []
            for item in actions:
                if not isinstance(item, dict):
                    continue
                action_session_id = str(item.get("session_id", "")).strip().lower()
                if normalized_session_ids_set and action_session_id not in normalized_session_ids_set:
                    continue
                if normalized_session_prefix and not action_session_id.startswith(normalized_session_prefix):
                    continue
                action_actor = str(item.get("actor", "")).strip().lower()
                if normalized_actor and action_actor != normalized_actor:
                    continue
                if normalized_actor_prefix and not action_actor.startswith(normalized_actor_prefix):
                    continue
                action_recommendation_id = str(item.get("recommendation_id", "")).strip().lower()
                if normalized_recommendation_id and action_recommendation_id != normalized_recommendation_id:
                    continue
                item_action_type = str(item.get("action_type", "")).strip().lower()
                if normalized_action_types_set:
                    if item_action_type not in normalized_action_types_set:
                        continue
                created_at = _parse_item_timestamp(item)
                if created_after_dt is not None:
                    if created_at is None or created_at < created_after_dt:
                        continue
                if created_before_dt is not None:
                    if created_at is None or created_at > created_before_dt:
                        continue
                if normalized_query:
                    action_created_at = str(item.get("created_at", "")).strip().lower()
                    core_searchable = " ".join(
                        [
                            action_session_id,
                            action_actor,
                            item_action_type,
                            action_recommendation_id,
                            action_created_at,
                        ]
                    )
                    if normalized_query not in core_searchable:
                        payload_value = item.get("payload", {})
                        if not isinstance(payload_value, dict):
                            payload_value = {}
                        metadata_value = item.get("metadata", {})
                        if not isinstance(metadata_value, dict):
                            metadata_value = {}
                        payload_searchable = json.dumps(
                            payload_value,
                            separators=(",", ":"),
                            sort_keys=True,
                            ensure_ascii=True,
                        ).lower()
                        metadata_searchable = json.dumps(
                            metadata_value,
                            separators=(",", ":"),
                            sort_keys=True,
                            ensure_ascii=True,
                        ).lower()
                        if normalized_query not in payload_searchable and normalized_query not in metadata_searchable:
                            continue
                filtered_item = dict(item)
                filtered_item["_created_at_dt"] = created_at
                filtered.append(filtered_item)
            reverse = sort_order == "desc"
            if sort_by == "created_at":
                filtered.sort(
                    key=lambda item: item.get("_created_at_dt") or epoch_utc,
                    reverse=reverse,
                )
            else:
                filtered.sort(
                    key=lambda item: str(item.get(sort_by, "")).strip().lower(),
                    reverse=reverse,
                )
            for index, item in enumerate(filtered, start=1):
                item["result_rank"] = index
            if compact:
                compact_fields = {
                    "row_id",
                    "created_at",
                    "action_type",
                    "session_id",
                    "recommendation_id",
                    "actor",
                    "result_rank",
                }
                filtered = [{key: value for key, value in item.items() if key in compact_fields} for item in filtered]
            else:
                for item in filtered:
                    item.pop("_created_at_dt", None)
            payload["actions"] = filtered
            payload["count"] = len(filtered)
            payload["filtering"] = {
                "session_id": normalized_session,
                "session_ids": normalized_session_ids,
                "session_prefix": normalized_session_prefix,
                "action_type": normalized_action_type,
                "action_types": normalized_action_types,
                "actor": normalized_actor,
                "actor_prefix": normalized_actor_prefix,
                "query": normalized_query,
                "recommendation_id": normalized_recommendation_id,
                "created_after": normalized_created_after,
                "created_before": normalized_created_before,
                "compact": compact,
                "sort_by": sort_by,
                "sort_order": sort_order,
            }
            return payload

        response_cache_key = (
            "theater:actions:response:"
            f"{limit}:{normalized_session}:{normalized_session_ids_key}:{normalized_session_prefix}:"
            f"{normalized_action_type}:{normalized_action_types_key}:"
            f"{normalized_actor}:{normalized_actor_prefix}:{normalized_recommendation_id}:"
            f"{normalized_query}:{normalized_created_after}:{normalized_created_before}:"
            f"{int(compact)}:{sort_by}:{sort_order}"
        )
        return _summary_cache_get(
            response_cache_key,
            ttl_seconds=1.0,
            build=_build_filtered_payload,
        )

    @app.get("/theater/actions/export")
    def theater_actions_export(
        limit: int = Query(default=200, ge=1, le=2000),
        session_id: str | None = Query(default=None),
        session_ids: str | None = Query(default=None),
        action_type: str | None = Query(default=None),
        action_types: str | None = Query(default=None),
        actor: str | None = Query(default=None),
        actor_prefix: str | None = Query(default=None),
        session_prefix: str | None = Query(default=None),
        query: str | None = Query(default=None),
        recommendation_id: str | None = Query(default=None),
        created_after: str | None = Query(default=None),
        created_before: str | None = Query(default=None),
        compact: bool = Query(default=False),
        sort_by: Literal["created_at", "session_id", "action_type", "actor"] = Query(default="created_at"),
        sort_order: Literal["asc", "desc"] = Query(default="desc"),
        output_format: Literal["json", "csv", "tsv", "ndjson", "jsonl", "logfmt", "cef", "leef", "syslog"] = Query(
            default="json",
            alias="format",
        ),
    ) -> Any:
        normalized_session = str(session_id or "").strip()
        raw_session_ids = str(session_ids or "").strip()
        normalized_session_ids = raw_session_ids.lower()
        normalized_action_type = str(action_type or "").strip().lower()
        normalized_action_types = str(action_types or "").strip().lower()
        normalized_actor = str(actor or "").strip().lower()
        normalized_actor_prefix = str(actor_prefix or "").strip().lower()
        normalized_session_prefix = str(session_prefix or "").strip().lower()
        normalized_query = str(query or "").strip().lower()
        normalized_recommendation_id = str(recommendation_id or "").strip().lower()
        normalized_created_after = str(created_after or "").strip()
        normalized_created_before = str(created_before or "").strip()
        export_cache_key = (
            "theater:actions:export:"
            f"{limit}:{normalized_session}:{normalized_session_ids}:{normalized_action_type}:{normalized_action_types}:"
            f"{normalized_actor}:{normalized_actor_prefix}:{normalized_session_prefix}:{normalized_recommendation_id}:"
            f"{normalized_query}:{normalized_created_after}:{normalized_created_before}:"
            f"{int(compact)}:{sort_by}:{sort_order}"
        )
        export_payload = _summary_cache_get(
            export_cache_key,
            ttl_seconds=1.0,
            build=lambda: build_theater_action_export(
                theater_actions(
                    limit=limit,
                    session_id=normalized_session or None,
                    session_ids=raw_session_ids or None,
                    action_type=normalized_action_type or None,
                    action_types=normalized_action_types or None,
                    actor=normalized_actor or None,
                    actor_prefix=normalized_actor_prefix or None,
                    session_prefix=normalized_session_prefix or None,
                    query=normalized_query or None,
                    recommendation_id=normalized_recommendation_id or None,
                    created_after=normalized_created_after or None,
                    created_before=normalized_created_before or None,
                    compact=compact,
                    sort_by=sort_by,
                    sort_order=sort_order,
                )
            ),
        )
        if output_format == "json":
            return export_payload
        rendered_payload = _summary_cache_get(
            f"{export_cache_key}:render:{output_format}",
            ttl_seconds=1.0,
            build=lambda: render_theater_action_export(export_payload, output_format=output_format),
        )
        if output_format == "csv":
            return Response(
                content=f"{rendered_payload}\n" if rendered_payload else "",
                media_type="text/csv; charset=utf-8",
            )
        if output_format == "tsv":
            return Response(
                content=f"{rendered_payload}\n" if rendered_payload else "",
                media_type="text/tab-separated-values; charset=utf-8",
            )
        if output_format == "ndjson":
            return Response(
                content=f"{rendered_payload}\n" if rendered_payload else "",
                media_type="application/x-ndjson; charset=utf-8",
            )
        if output_format == "jsonl":
            return Response(
                content=f"{rendered_payload}\n" if rendered_payload else "",
                media_type="application/x-ndjson; charset=utf-8",
            )
        if output_format == "logfmt":
            return Response(
                content=f"{rendered_payload}\n" if rendered_payload else "",
                media_type="text/plain; charset=utf-8",
            )
        if output_format == "cef":
            return Response(
                content=f"{rendered_payload}\n" if rendered_payload else "",
                media_type="text/plain; charset=utf-8",
            )
        if output_format == "leef":
            return Response(
                content=f"{rendered_payload}\n" if rendered_payload else "",
                media_type="text/plain; charset=utf-8",
            )
        if output_format == "syslog":
            return Response(
                content=f"{rendered_payload}\n" if rendered_payload else "",
                media_type="text/plain; charset=utf-8",
            )
        return export_payload

    @app.post("/theater/actions/apply-lure")
    def theater_apply_lure(payload: dict[str, Any]) -> dict[str, Any]:
        session_id = str(payload.get("session_id", "")).strip()
        if not session_id:
            raise HTTPException(status_code=400, detail="session_id must be non-empty")
        lure_arm = str(payload.get("lure_arm", "")).strip()
        if not lure_arm:
            raise HTTPException(status_code=400, detail="lure_arm must be non-empty")
        duration_seconds = float(payload.get("duration_seconds", 300.0) or 0.0)
        if duration_seconds <= 0:
            raise HTTPException(status_code=400, detail="duration_seconds must be > 0")
        metadata = payload.get("metadata", {})
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise HTTPException(status_code=400, detail="metadata must be an object")
        actor = str(payload.get("actor", "operator")).strip() or "operator"
        context_key = str(payload.get("context_key", "*")).strip() or "*"
        recommendation_id_raw = payload.get("recommendation_id")
        recommendation_id = str(recommendation_id_raw).strip() if recommendation_id_raw is not None else None
        return orchestrator.theater_apply_lure(
            session_id=session_id,
            lure_arm=lure_arm,
            actor=actor,
            context_key=context_key,
            duration_seconds=duration_seconds,
            recommendation_id=recommendation_id,
            metadata=metadata,
        )

    @app.post("/theater/actions/label")
    def theater_label(payload: dict[str, Any]) -> dict[str, Any]:
        session_id = str(payload.get("session_id", "")).strip()
        if not session_id:
            raise HTTPException(status_code=400, detail="session_id must be non-empty")
        label = str(payload.get("label", "")).strip()
        if not label:
            raise HTTPException(status_code=400, detail="label must be non-empty")
        confidence_raw = payload.get("confidence")
        confidence = None
        if confidence_raw is not None:
            confidence = float(confidence_raw)
            if confidence < 0.0 or confidence > 1.0:
                raise HTTPException(status_code=400, detail="confidence must be between 0 and 1")
        metadata = payload.get("metadata", {})
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise HTTPException(status_code=400, detail="metadata must be an object")
        actor = str(payload.get("actor", "operator")).strip() or "operator"
        recommendation_id_raw = payload.get("recommendation_id")
        recommendation_id = str(recommendation_id_raw).strip() if recommendation_id_raw is not None else None
        return orchestrator.theater_label(
            session_id=session_id,
            label=label,
            actor=actor,
            recommendation_id=recommendation_id,
            confidence=confidence,
            metadata=metadata,
        )

    @app.get("/intel/report")
    def intel_report(
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
    ) -> dict[str, Any]:
        return _resolve_live_report(limit=limit, events_per_session=events_per_session)

    @app.get("/intel/history")
    def intel_history(limit: int = Query(default=20, ge=1, le=500)) -> dict[str, Any]:
        return orchestrator.intelligence_history(limit=limit)

    @app.get("/intel/handoff")
    def intel_handoff(
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
        report_id: int | None = Query(default=None, ge=1),
        max_techniques: int = Query(default=5, ge=1, le=50),
        max_sessions: int = Query(default=5, ge=1, le=50),
        output_format: Literal["json", "markdown", "csv", "tsv", "ndjson", "jsonl", "cef", "leef", "syslog", "logfmt"] = Query(default="json", alias="format"),
    ) -> Any:
        handoff = _resolve_handoff_payload(
            limit=limit,
            events_per_session=events_per_session,
            report_id=report_id,
            max_techniques=max_techniques,
            max_sessions=max_sessions,
        )
        if output_format == "markdown":
            markdown = str(handoff.get("markdown", "")).strip()
            return Response(
                content=f"{markdown}\n" if markdown else "",
                media_type="text/markdown; charset=utf-8",
            )
        if output_format == "csv":
            csv_payload = str(handoff.get("csv", "")).strip()
            return Response(
                content=f"{csv_payload}\n" if csv_payload else "",
                media_type="text/csv; charset=utf-8",
            )
        if output_format == "tsv":
            tsv_payload = str(handoff.get("tsv", "")).strip()
            return Response(
                content=f"{tsv_payload}\n" if tsv_payload else "",
                media_type="text/tab-separated-values; charset=utf-8",
            )
        if output_format == "ndjson":
            ndjson_payload = str(handoff.get("ndjson", "")).strip()
            return Response(
                content=f"{ndjson_payload}\n" if ndjson_payload else "",
                media_type="application/x-ndjson; charset=utf-8",
            )
        if output_format == "jsonl":
            jsonl_payload = str(handoff.get("jsonl", "")).strip()
            return Response(
                content=f"{jsonl_payload}\n" if jsonl_payload else "",
                media_type="application/x-ndjson; charset=utf-8",
            )
        if output_format == "cef":
            cef_payload = str(handoff.get("cef", "")).strip()
            return Response(
                content=f"{cef_payload}\n" if cef_payload else "",
                media_type="text/plain; charset=utf-8",
            )
        if output_format == "leef":
            leef_payload = str(handoff.get("leef", "")).strip()
            return Response(
                content=f"{leef_payload}\n" if leef_payload else "",
                media_type="text/plain; charset=utf-8",
            )
        if output_format == "syslog":
            syslog_payload = str(handoff.get("syslog", "")).strip()
            return Response(
                content=f"{syslog_payload}\n" if syslog_payload else "",
                media_type="text/plain; charset=utf-8",
            )
        if output_format == "logfmt":
            logfmt_payload = str(handoff.get("logfmt", "")).strip()
            return Response(
                content=f"{logfmt_payload}\n" if logfmt_payload else "",
                media_type="text/plain; charset=utf-8",
            )
        return handoff

    @app.get("/intel/history/sessions")
    def intel_history_sessions(limit: int = Query(default=100, ge=1, le=2000)) -> dict[str, Any]:
        return orchestrator.intelligence_session_history(limit=limit)

    @app.get("/intel/history/{report_id}")
    def intel_history_report(report_id: int) -> dict[str, Any]:
        report = orchestrator.intelligence_history_report(report_id=report_id)
        if not bool(report.get("found")):
            raise HTTPException(status_code=404, detail="intelligence report not found")
        return report

    @app.get("/intel/history/{report_id}/sessions")
    def intel_history_report_sessions(
        report_id: int,
        limit: int = Query(default=1000, ge=1, le=5000),
    ) -> dict[str, Any]:
        report = orchestrator.intelligence_history_report(report_id=report_id)
        if not bool(report.get("found")):
            raise HTTPException(status_code=404, detail="intelligence report not found")
        return orchestrator.intelligence_history_report_sessions(report_id=report_id, limit=limit)

    @app.get("/intel/techniques")
    def intel_techniques(
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
    ) -> dict[str, Any]:
        report = _resolve_live_report(limit=limit, events_per_session=events_per_session)
        return {"techniques": report.get("techniques", []), "totals": report.get("totals", {})}

    @app.get("/intel/coverage")
    def intel_coverage(
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
    ) -> dict[str, Any]:
        report = _resolve_live_report(limit=limit, events_per_session=events_per_session)
        coverage = report.get("coverage", {})
        if not isinstance(coverage, dict):
            coverage = {}
        gaps = coverage.get("gaps")
        observed = coverage.get("observed")
        tactics = coverage.get("tactics")
        if not isinstance(gaps, list):
            coverage["gaps"] = []
        if not isinstance(observed, list):
            coverage["observed"] = []
        if not isinstance(tactics, list):
            coverage["tactics"] = []
        return coverage

    @app.get("/intel/profiles")
    def intel_profiles(
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
    ) -> dict[str, Any]:
        report = _resolve_live_report(limit=limit, events_per_session=events_per_session)
        return {"profiles": report.get("profiles", []), "sessions": report.get("sessions", [])}

    @app.get("/intel/canaries")
    def intel_canaries(
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
    ) -> dict[str, Any]:
        report = _resolve_live_report(limit=limit, events_per_session=events_per_session)
        canaries = report.get("canaries", {})
        if not isinstance(canaries, dict):
            canaries = {}
        return canaries

    @app.get("/intel/canary/tokens")
    def intel_canary_tokens(
        limit: int = Query(default=100, ge=1, le=1000),
        namespace: str | None = Query(default=None),
        token_type: str | None = Query(default=None),
    ) -> dict[str, Any]:
        return orchestrator.canary_tokens(limit=limit, namespace=namespace, token_type=token_type)

    @app.get("/intel/canary/tokens/{token_id}")
    def intel_canary_token(token_id: str) -> dict[str, Any]:
        payload = orchestrator.canary_token(token_id=token_id)
        if not bool(payload.get("found")):
            raise HTTPException(status_code=404, detail="canary token not found")
        return payload

    @app.get("/intel/canary/hits")
    def intel_canary_hits(
        limit: int = Query(default=200, ge=1, le=2000),
        token_id: str | None = Query(default=None),
    ) -> dict[str, Any]:
        return orchestrator.canary_hits(limit=limit, token_id=token_id)

    @app.get("/intel/canary/types")
    def intel_canary_types() -> dict[str, Any]:
        types = canary_type_catalog()
        return {"types": types, "count": len(types)}

    @app.get("/intel/fingerprints")
    def intel_fingerprints(
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
    ) -> dict[str, Any]:
        report = _resolve_live_report(limit=limit, events_per_session=events_per_session)
        fingerprints = report.get("fingerprints", [])
        if not isinstance(fingerprints, list):
            fingerprints = []
        return {"fingerprints": fingerprints, "count": len(fingerprints)}

    @app.get("/intel/kill-chain")
    def intel_kill_chain(
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
    ) -> dict[str, Any]:
        report = _resolve_live_report(limit=limit, events_per_session=events_per_session)
        kill_chain = report.get("kill_chain", {})
        if not isinstance(kill_chain, dict):
            kill_chain = {}
        return kill_chain

    @app.get("/intel/kill-chain/graph")
    def intel_kill_chain_graph(
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
    ) -> dict[str, Any]:
        report = _resolve_live_report(limit=limit, events_per_session=events_per_session)
        graph = report.get("kill_chain_graph", {})
        if not isinstance(graph, dict):
            graph = {}
        return graph

    @app.get("/intel/credential-reuse")
    def intel_credential_reuse(
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
    ) -> dict[str, Any]:
        report = _resolve_live_report(limit=limit, events_per_session=events_per_session)
        credential_reuse = report.get("credential_reuse", {})
        if not isinstance(credential_reuse, dict):
            credential_reuse = {}
        patterns = credential_reuse.get("patterns")
        if not isinstance(patterns, list):
            credential_reuse["patterns"] = []
        return credential_reuse

    @app.get("/intel/geography")
    def intel_geography(
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
    ) -> dict[str, Any]:
        report = _resolve_live_report(limit=limit, events_per_session=events_per_session)
        geography = report.get("geography", {})
        if not isinstance(geography, dict):
            geography = {}
        return geography

    @app.get("/intel/biometrics")
    def intel_biometrics(
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
    ) -> dict[str, Any]:
        report = _resolve_live_report(limit=limit, events_per_session=events_per_session)
        biometrics = report.get("biometrics", {})
        if not isinstance(biometrics, dict):
            biometrics = {}
        return biometrics

    @app.get("/intel/bandit/arms")
    def intel_bandit_arms() -> dict[str, Any]:
        return orchestrator.bandit_arms()

    @app.get("/intel/bandit/performance")
    def intel_bandit_performance(limit: int = Query(default=200, ge=1, le=2000)) -> dict[str, Any]:
        return orchestrator.bandit_performance(limit=limit)

    @app.get("/intel/bandit/observability")
    def intel_bandit_observability(limit: int = Query(default=30, ge=1, le=500)) -> dict[str, Any]:
        return orchestrator.bandit_observability(limit=limit)

    @app.post("/intel/bandit/override")
    def intel_bandit_override(payload: dict[str, Any]) -> dict[str, Any]:
        arm = str(payload.get("arm", "")).strip()
        if not arm:
            raise HTTPException(status_code=400, detail="arm must be non-empty")
        context_key = str(payload.get("context_key", "*")).strip() or "*"
        duration_seconds = float(payload.get("duration_seconds", 300.0) or 0.0)
        if duration_seconds <= 0:
            raise HTTPException(status_code=400, detail="duration_seconds must be > 0")
        return orchestrator.bandit_override(
            context_key=context_key,
            arm=arm,
            duration_seconds=duration_seconds,
        )

    @app.post("/intel/bandit/reset")
    def intel_bandit_reset(payload: dict[str, Any] | None = None) -> dict[str, Any]:
        reason = ""
        if isinstance(payload, dict):
            reason = str(payload.get("reason", "")).strip()
        return orchestrator.bandit_reset(reason=reason or "manual")

    @app.get("/intel/map")
    def intel_map(
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
    ) -> dict[str, Any]:
        sessions = orchestrator.session_manager.export_sessions(limit=limit, events_per_session=events_per_session)
        return build_engagement_map(sessions)

    @app.get("/intel/stix")
    def intel_stix(
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
    ) -> dict[str, Any]:
        report = _resolve_live_report(limit=limit, events_per_session=events_per_session)
        return build_stix_bundle(report)

    @app.get("/intel/stix/history/{report_id}")
    def intel_stix_history(report_id: int) -> dict[str, Any]:
        report = orchestrator.intelligence_history_report_payload(report_id=report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="intelligence report not found")
        return build_stix_bundle(report)

    @app.get("/intel/attack-navigator")
    def intel_attack_navigator(
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
        name: str | None = Query(default=None),
        domain: str = Query(default="enterprise-attack"),
    ) -> dict[str, Any]:
        report = _resolve_live_report(limit=limit, events_per_session=events_per_session)
        return build_attack_navigator_layer(
            report,
            layer_name=(name or "").strip() or "ClownPeanuts ATT&CK Observations",
            domain=domain,
        )

    @app.get("/intel/attack-navigator/history/{report_id}")
    def intel_attack_navigator_history(
        report_id: int,
        name: str | None = Query(default=None),
        domain: str = Query(default="enterprise-attack"),
    ) -> dict[str, Any]:
        report = orchestrator.intelligence_history_report_payload(report_id=report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="intelligence report not found")
        return build_attack_navigator_layer(
            report,
            layer_name=(name or "").strip() or "ClownPeanuts ATT&CK Observations",
            domain=domain,
        )

    @app.get("/intel/taxii/collections")
    def intel_taxii_collections() -> dict[str, Any]:
        return {
            "collections": [
                {
                    "id": "clownpeanuts-intel",
                    "title": "ClownPeanuts Intelligence Collection",
                    "description": "STIX 2.1 bundle export generated from honeypot telemetry.",
                    "can_read": True,
                    "can_write": False,
                }
            ]
        }

    @app.get("/taxii2/")
    def taxii2_discovery(request: Request) -> Response:
        api_root = str(request.url_for("taxii2_api_root"))
        return _taxii_response(
            {
            "title": "ClownPeanuts TAXII 2.1 Discovery",
            "description": "TAXII 2.1 discovery endpoint for ClownPeanuts intelligence exports.",
            "default": api_root,
            "api_roots": [api_root],
            }
        )

    @app.get("/taxii2/api/", name="taxii2_api_root")
    def taxii2_api_root() -> Response:
        return _taxii_response(
            {
            "title": "ClownPeanuts TAXII API Root",
            "description": "Primary TAXII API root for ClownPeanuts intelligence collection.",
            "versions": ["taxii-2.1"],
            "max_content_length": 10485760,
            }
        )

    @app.get("/taxii2/api/collections")
    def taxii2_collections() -> Response:
        return _taxii_response({"collections": [_taxii_collection_payload()]})

    @app.get("/taxii2/api/collections/{collection_id}")
    def taxii2_collection(collection_id: str) -> Response:
        _require_taxii_collection(collection_id)
        return _taxii_response(_taxii_collection_payload())

    @app.get("/taxii2/api/collections/{collection_id}/objects")
    def taxii2_collection_objects(
        collection_id: str,
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
        report_id: int | None = Query(default=None, ge=1),
        added_after: str | None = Query(default=None),
        next_cursor: str | None = Query(default=None, alias="next"),
    ) -> Response:
        _require_taxii_collection(collection_id)
        bundle = _taxii_export_bundle(limit=limit, events_per_session=events_per_session, report_id=report_id)

        objects = bundle.get("objects", [])
        if not isinstance(objects, list):
            objects = []

        manifest = build_taxii_manifest(bundle)
        filtered_objects, _ = _taxii_filter_objects(
            objects=[obj for obj in objects if isinstance(obj, dict)],
            manifest=manifest,
            added_after=_parse_taxii_timestamp(added_after),
        )
        return _taxii_response(_paginate_taxii(filtered_objects, limit=limit, next_cursor=next_cursor))

    @app.get("/taxii2/api/collections/{collection_id}/manifest")
    def taxii2_collection_manifest(
        collection_id: str,
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
        report_id: int | None = Query(default=None, ge=1),
        added_after: str | None = Query(default=None),
        next_cursor: str | None = Query(default=None, alias="next"),
    ) -> Response:
        _require_taxii_collection(collection_id)
        bundle = _taxii_export_bundle(limit=limit, events_per_session=events_per_session, report_id=report_id)
        manifest = build_taxii_manifest(bundle)

        _, filtered_manifest = _taxii_filter_objects(
            objects=[],
            manifest=[item for item in manifest if isinstance(item, dict)],
            added_after=_parse_taxii_timestamp(added_after),
        )
        return _taxii_response(_paginate_taxii(filtered_manifest, limit=limit, next_cursor=next_cursor))

    @app.get("/taxii2/api/collections/{collection_id}/objects/{object_id}")
    def taxii2_collection_object(
        collection_id: str,
        object_id: str,
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
        report_id: int | None = Query(default=None, ge=1),
    ) -> Response:
        _require_taxii_collection(collection_id)
        bundle = _taxii_export_bundle(limit=limit, events_per_session=events_per_session, report_id=report_id)
        obj = find_stix_object(bundle, object_id=object_id)
        if obj is None:
            raise HTTPException(status_code=404, detail="STIX object not found")
        return _taxii_response(obj)

    @app.get("/intel/taxii/collections/{collection_id}/objects")
    def intel_taxii_collection_objects(
        collection_id: str,
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
        report_id: int | None = Query(default=None, ge=1),
    ) -> dict[str, Any]:
        if collection_id != "clownpeanuts-intel":
            raise HTTPException(status_code=404, detail="unknown TAXII collection")
        report = _resolve_export_report(
            limit=limit,
            events_per_session=events_per_session,
            report_id=report_id,
        )
        bundle = build_stix_bundle(report)
        objects = bundle.get("objects", [])
        if not isinstance(objects, list):
            objects = []
        return {
            "collection_id": collection_id,
            "bundle_id": str(bundle.get("id", "")),
            "objects": objects,
        }

    @app.get("/intel/taxii/collections/{collection_id}/manifest")
    def intel_taxii_collection_manifest(
        collection_id: str,
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
        report_id: int | None = Query(default=None, ge=1),
    ) -> dict[str, Any]:
        if collection_id != "clownpeanuts-intel":
            raise HTTPException(status_code=404, detail="unknown TAXII collection")
        report = _resolve_export_report(
            limit=limit,
            events_per_session=events_per_session,
            report_id=report_id,
        )
        bundle = build_stix_bundle(report)
        return {
            "collection_id": collection_id,
            "bundle_id": str(bundle.get("id", "")),
            "manifest": build_taxii_manifest(bundle),
        }

    @app.get("/intel/taxii/collections/{collection_id}/objects/{object_id}")
    def intel_taxii_collection_object(
        collection_id: str,
        object_id: str,
        limit: int = Query(default=200, ge=1, le=1000),
        events_per_session: int = Query(default=200, ge=0, le=2000),
        report_id: int | None = Query(default=None, ge=1),
    ) -> dict[str, Any]:
        if collection_id != "clownpeanuts-intel":
            raise HTTPException(status_code=404, detail="unknown TAXII collection")
        report = _resolve_export_report(
            limit=limit,
            events_per_session=events_per_session,
            report_id=report_id,
        )
        bundle = build_stix_bundle(report)
        obj = find_stix_object(bundle, object_id=object_id)
        if obj is None:
            raise HTTPException(status_code=404, detail="STIX object not found")
        return {
            "collection_id": collection_id,
            "bundle_id": str(bundle.get("id", "")),
            "object": obj,
        }

    @app.post("/intel/rotate")
    def intel_rotate() -> dict[str, Any]:
        return {"threat_intel": orchestrator.rotate_threat_intel()}

    @app.get("/intel/rotate/preview")
    def intel_rotate_preview() -> dict[str, Any]:
        return {"threat_intel": orchestrator.threat_intel_preview()}

    @app.post("/intel/canary/hit")
    def intel_canary_hit(payload: dict[str, Any]) -> dict[str, Any]:
        token = str(payload.get("token", "")).strip()
        source_ip = str(payload.get("source_ip", "")).strip()
        service = str(payload.get("service", "canary")).strip() or "canary"
        session_id_raw = payload.get("session_id")
        tenant_id_raw = payload.get("tenant_id")
        metadata_raw = payload.get("metadata")

        session_id = str(session_id_raw).strip() if session_id_raw is not None else None
        if session_id == "":
            session_id = None
        tenant_id = str(tenant_id_raw).strip() if tenant_id_raw is not None else None
        if tenant_id == "":
            tenant_id = None
        metadata = metadata_raw if isinstance(metadata_raw, dict) else None

        try:
            result = orchestrator.ingest_canary_hit(
                token=token,
                source_ip=source_ip,
                service=service,
                session_id=session_id,
                tenant_id=tenant_id,
                metadata=metadata,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid canary hit payload") from exc

        return {"ingested": result}

    @app.post("/intel/canary/generate")
    def intel_canary_generate(payload: dict[str, Any]) -> dict[str, Any]:
        namespace = str(payload.get("namespace", "cp")).strip() or "cp"
        token_type = str(payload.get("token_type", "http")).strip() or "http"
        metadata_raw = payload.get("metadata")
        metadata = metadata_raw if isinstance(metadata_raw, dict) else None
        try:
            token = orchestrator.generate_canary_token(
                namespace=namespace,
                token_type=token_type,
                metadata=metadata,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid canary token parameters") from exc
        return {"token": token}

    @app.get("/alerts/recent")
    def alerts_recent() -> dict[str, Any]:
        return orchestrator.alert_router.snapshot()

    @app.get("/alerts/routes")
    def alerts_routes(
        severity: str = Query(default="medium"),
        service: str = Query(default="ops"),
        action: str = Query(default="alert_test"),
        title: str = Query(default="manual_alert_test"),
        apply_throttle: bool = Query(default=False),
    ) -> dict[str, Any]:
        normalized_severity = severity.strip().lower() or "medium"
        if normalized_severity not in {"low", "medium", "high", "critical"}:
            raise HTTPException(status_code=400, detail="invalid severity")
        return orchestrator.alert_routes(
            severity=normalized_severity,
            service=service.strip() or "ops",
            action=action.strip() or "alert_test",
            title=title.strip() or "manual_alert_test",
            apply_throttle=apply_throttle,
        )

    @app.post("/alerts/test")
    def alerts_test(payload: dict[str, Any]) -> dict[str, Any]:
        severity = str(payload.get("severity", "medium")).strip().lower() or "medium"
        if severity not in {"low", "medium", "high", "critical"}:
            raise HTTPException(status_code=400, detail="invalid severity")
        title = str(payload.get("title", "manual_alert_test")).strip() or "manual_alert_test"
        summary = str(payload.get("summary", "synthetic alert delivery test")).strip() or "synthetic alert delivery test"
        service = str(payload.get("service", "ops")).strip() or "ops"
        action = str(payload.get("action", "alert_test")).strip() or "alert_test"
        metadata_raw = payload.get("metadata")
        metadata = metadata_raw if isinstance(metadata_raw, dict) else None
        return {
            "result": orchestrator.alert_test(
                severity=severity,
                title=title,
                summary=summary,
                service=service,
                action=action,
                metadata=metadata,
            )
        }

    @app.get("/doctor")
    def doctor(check_llm: bool = Query(default=False)) -> dict[str, Any]:
        return run_diagnostics(orchestrator.config, check_llm=check_llm)

    @app.get("/engine/worlds")
    def engine_worlds() -> dict[str, Any]:
        return orchestrator.rabbit_hole.snapshot()

    @app.get("/engine/narrative/world")
    def engine_narrative_world(tenant_id: str | None = Query(default=None)) -> dict[str, Any]:
        return orchestrator.narrative_world(tenant_id=tenant_id)

    @app.get("/engine/narrative/session/{session_id}")
    def engine_narrative_session(
        session_id: str,
        events_limit: int = Query(default=500, ge=0, le=5000),
    ) -> dict[str, Any]:
        payload = orchestrator.narrative_session(session_id=session_id, events_limit=events_limit)
        if payload is None:
            raise HTTPException(status_code=404, detail="narrative session not found")
        return payload

    @app.get("/engine/local-llm")
    def engine_local_llm() -> dict[str, Any]:
        snapshot = orchestrator.rabbit_hole.snapshot()
        local_llm = snapshot.get("local_llm", {})
        if not isinstance(local_llm, dict):
            local_llm = {}
        return local_llm

    @app.websocket("/ws/theater/live")
    async def ws_theater_live(websocket: WebSocket) -> None:
        accept_subprotocol = _websocket_accept_subprotocol(websocket)
        if rate_limit_enabled and not _is_rate_limit_exempt(str(websocket.url.path)):
            allowed, _remaining, retry_after_seconds = _rate_limit_consume(_websocket_client_identity(websocket))
            if not allowed:
                await websocket.accept(subprotocol=accept_subprotocol)
                await websocket.close(code=4429, reason=f"rate limit exceeded; retry_after={retry_after_seconds}s")
                return
        if auth_enabled:
            role = _websocket_auth_role(websocket)
            if role is None:
                await websocket.accept(subprotocol=accept_subprotocol)
                await websocket.close(code=4401, reason="authentication required")
                return
        await websocket.accept(subprotocol=accept_subprotocol)

        def _query_int(name: str, *, default: int, minimum: int, maximum: int) -> int:
            raw = websocket.query_params.get(name)
            if raw is None:
                return default
            try:
                parsed = int(raw)
            except ValueError:
                return default
            return max(minimum, min(maximum, parsed))

        limit = _query_int("limit", default=100, minimum=1, maximum=1000)
        events_per_session = _query_int("events_per_session", default=200, minimum=0, maximum=2000)
        interval_ms = _query_int("interval_ms", default=800, minimum=100, maximum=10000)

        try:
            while True:
                payload = orchestrator.theater_live(limit=limit, events_per_session=events_per_session)
                await websocket.send_json(
                    {
                        "stream": "theater_live",
                        "sent_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        "payload": payload,
                    }
                )
                await asyncio.sleep(float(interval_ms) / 1000.0)
        except WebSocketDisconnect:
            return

    @app.websocket("/ws/events")
    async def ws_events(websocket: WebSocket) -> None:
        accept_subprotocol = _websocket_accept_subprotocol(websocket)
        if rate_limit_enabled and not _is_rate_limit_exempt(str(websocket.url.path)):
            allowed, _remaining, retry_after_seconds = _rate_limit_consume(_websocket_client_identity(websocket))
            if not allowed:
                await websocket.accept(subprotocol=accept_subprotocol)
                await websocket.close(code=4429, reason=f"rate limit exceeded; retry_after={retry_after_seconds}s")
                return
        if auth_enabled:
            role = _websocket_auth_role(websocket)
            if role is None:
                await websocket.accept(subprotocol=accept_subprotocol)
                await websocket.close(code=4401, reason="authentication required")
                return
        await websocket.accept(subprotocol=accept_subprotocol)

        def _query_int(name: str, *, default: int, minimum: int, maximum: int) -> int:
            raw = websocket.query_params.get(name)
            if raw is None:
                return default
            try:
                parsed = int(raw)
            except ValueError:
                return default
            return max(minimum, min(maximum, parsed))

        cursor = _query_int("cursor", default=0, minimum=0, maximum=2_147_483_647)
        batch_limit = _query_int("batch_limit", default=200, minimum=1, maximum=1000)
        interval_ms = _query_int("interval_ms", default=250, minimum=50, maximum=5000)
        mode_raw = str(websocket.query_params.get("format", "")).strip().lower()
        batch_mode = mode_raw in {"batch", "batched", "bulk"}
        include_payload = str(websocket.query_params.get("include_payload", "true")).strip().lower() not in {
            "0",
            "false",
            "no",
            "off",
        }

        def _query_filter_set(name: str) -> set[str]:
            raw = str(websocket.query_params.get(name, "")).strip().lower()
            if not raw:
                return set()
            values: set[str] = set()
            for part in raw.split(","):
                normalized = part.strip()
                if normalized:
                    values.add(normalized)
            return values

        topic_filter = _query_filter_set("topic")
        service_filter = _query_filter_set("service")
        action_filter = _query_filter_set("action")
        session_filter = _query_filter_set("session_id")

        try:
            while True:
                events, cursor = orchestrator.event_bus.recent_events_since(cursor=cursor, limit=batch_limit)
                if topic_filter or service_filter or action_filter or session_filter:
                    events = [
                        event
                        for event in events
                        if _event_matches_filters(
                            event,
                            topic_filter=topic_filter,
                            service_filter=service_filter,
                            action_filter=action_filter,
                            session_filter=session_filter,
                        )
                    ]
                if not include_payload:
                    events = [_trim_event_payload(event) for event in events]
                if batch_mode:
                    if events:
                        await websocket.send_json(
                            {
                                "stream": "events_batch",
                                "cursor": cursor,
                                "count": len(events),
                                "events": events,
                            }
                        )
                else:
                    for event in events:
                        await websocket.send_json(event)
                await asyncio.sleep(float(interval_ms) / 1000.0)
        except WebSocketDisconnect:
            return

    def _shutdown_ecosystem_managers() -> None:
        if pripyatsprings_manager is not None:
            pripyatsprings_manager.close()
        if adlibs_manager is not None:
            adlibs_manager.close()
        if dirtylaundry_manager is not None:
            dirtylaundry_manager.close()
        ecosystem_activity.close()
        if ecosystem_jit is not None:
            ecosystem_jit.close()
    app.add_event_handler("shutdown", _shutdown_ecosystem_managers)

    return app
