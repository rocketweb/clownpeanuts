"""Runtime deployment ingestion and lifecycle management for ecosystem mode."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import threading
from typing import Any
from uuid import uuid4

from clownpeanuts.config.schema import ServiceConfig, parse_config


class EcosystemDeploymentError(RuntimeError):
    """Base error for ecosystem deployment operations."""


class EcosystemDeploymentNotFoundError(EcosystemDeploymentError):
    """Requested deployment id does not exist."""


class EcosystemDeploymentConflictError(EcosystemDeploymentError):
    """Requested deployment conflicts with existing active or reserved bindings."""


@dataclass(slots=True)
class DeploymentRecord:
    deployment_id: str
    source: str
    created_at: str
    manifest: dict[str, Any]
    services: list[ServiceConfig]
    status: str = "pending"
    activated_at: str | None = None
    deleted_at: str | None = None
    last_error: str = ""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _service_bindings(services: list[ServiceConfig]) -> list[tuple[str, int]]:
    bindings: list[tuple[str, int]] = []
    for service in services:
        host = service.listen_host.strip() or "0.0.0.0"
        for port in service.ports:
            bindings.append((host, int(port)))
    return bindings


class EcosystemDeploymentManager:
    """In-memory deployment registry and activation lifecycle."""

    def __init__(self, *, orchestrator: Any) -> None:
        self._orchestrator = orchestrator
        self._lock = threading.RLock()
        self._deployments: dict[str, DeploymentRecord] = {}

    def register_manifest(self, payload: dict[str, Any], *, source: str = "api") -> dict[str, Any]:
        manifest = self._normalize_manifest(payload)
        services = self._parse_manifest_services(manifest)
        try:
            self._orchestrator.validate_runtime_services(services)
        except ValueError as exc:
            raise EcosystemDeploymentConflictError(str(exc)) from exc
        self._validate_reserved_binding_conflicts(services)

        deployment_id = uuid4().hex[:12]
        record = DeploymentRecord(
            deployment_id=deployment_id,
            source=source.strip() or "api",
            created_at=_utc_now(),
            manifest=deepcopy(manifest),
            services=services,
        )
        with self._lock:
            self._deployments[deployment_id] = record
        return self._record_summary(record)

    def activate(self, deployment_id: str) -> dict[str, Any]:
        record = self._record_or_raise(deployment_id)
        if record.status == "active":
            return self._record_detail(record)
        if record.status == "deleted":
            raise EcosystemDeploymentConflictError("cannot activate a deleted deployment")

        try:
            self._orchestrator.validate_runtime_services(record.services)
        except ValueError as exc:
            record.last_error = str(exc)
            raise EcosystemDeploymentConflictError(str(exc)) from exc
        self._validate_reserved_binding_conflicts(record.services, ignore_deployment_id=record.deployment_id)
        try:
            activation = self._orchestrator.activate_runtime_deployment(
                deployment_id=record.deployment_id,
                services=record.services,
                manifest_source=record.source,
            )
        except ValueError as exc:
            record.last_error = str(exc)
            raise EcosystemDeploymentConflictError(str(exc)) from exc
        except RuntimeError as exc:
            record.last_error = str(exc)
            raise EcosystemDeploymentError(str(exc)) from exc

        record.status = "active"
        record.activated_at = str(activation.get("activated_at") or _utc_now())
        record.last_error = ""
        return self._record_detail(record)

    def delete(self, deployment_id: str) -> dict[str, Any]:
        record = self._record_or_raise(deployment_id)
        if record.status == "active":
            try:
                self._orchestrator.deactivate_runtime_deployment(deployment_id=record.deployment_id)
            except KeyError as exc:
                raise EcosystemDeploymentNotFoundError(f"deployment '{record.deployment_id}' is not active") from exc
            except ValueError as exc:
                raise EcosystemDeploymentError(str(exc)) from exc
        record.status = "deleted"
        record.deleted_at = _utc_now()
        return self._record_detail(record)

    def list_deployments(
        self,
        *,
        status: str = "",
        source: str = "",
        deployment_id_prefix: str = "",
        service_name: str = "",
        min_session_count: int = 0,
        query: str = "",
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        with self._lock:
            records = list(self._deployments.values())
        session_ids_by_service = self._session_ids_by_service_name()
        summaries = [
            self._record_summary(record, session_ids_by_service=session_ids_by_service)
            for record in records
        ]
        normalized_status = status.strip().lower()
        if normalized_status:
            allowed_statuses = {"pending", "active", "deleted"}
            if normalized_status not in allowed_statuses:
                raise EcosystemDeploymentError("status filter must be one of: pending, active, deleted")
            summaries = [
                item
                for item in summaries
                if str(item.get("status", "")).strip().lower() == normalized_status
            ]

        normalized_source = source.strip().lower()
        if normalized_source:
            summaries = [
                item
                for item in summaries
                if str(item.get("source", "")).strip().lower() == normalized_source
            ]
        normalized_deployment_id_prefix = deployment_id_prefix.strip().lower()
        if normalized_deployment_id_prefix:
            summaries = [
                item
                for item in summaries
                if str(item.get("deployment_id", "")).strip().lower().startswith(normalized_deployment_id_prefix)
            ]

        normalized_service_name = service_name.strip().lower()
        if normalized_service_name:
            summaries = [
                item
                for item in summaries
                if any(
                    str(candidate).strip().lower() == normalized_service_name
                    for candidate in item.get("services", [])
                )
            ]

        minimum_session_count = max(0, int(min_session_count))
        if minimum_session_count > 0:
            summaries = [
                item
                for item in summaries
                if int(item.get("session_count", 0) or 0) >= minimum_session_count
            ]

        normalized_query = query.strip().lower()
        if normalized_query:
            filtered: list[dict[str, Any]] = []
            for item in summaries:
                searchable = " ".join(
                    [
                        str(item.get("deployment_id", "")).strip().lower(),
                        str(item.get("status", "")).strip().lower(),
                        str(item.get("source", "")).strip().lower(),
                        str(item.get("last_error", "")).strip().lower(),
                        " ".join(
                            str(candidate).strip().lower()
                            for candidate in item.get("services", [])
                            if str(candidate).strip()
                        ),
                    ]
                )
                if normalized_query in searchable:
                    filtered.append(item)
            summaries = filtered

        normalized_sort_by = sort_by.strip().lower() if sort_by else "created_at"
        allowed_sort_fields = {
            "created_at",
            "activated_at",
            "service_count",
            "session_count",
            "uptime_seconds",
            "status",
            "source",
            "deployment_id",
        }
        if normalized_sort_by not in allowed_sort_fields:
            raise EcosystemDeploymentError(
                "sort_by must be one of: created_at, activated_at, service_count, session_count, "
                "uptime_seconds, status, source, deployment_id"
            )
        normalized_sort_order = sort_order.strip().lower() if sort_order else "desc"
        if normalized_sort_order not in {"asc", "desc"}:
            raise EcosystemDeploymentError("sort_order must be one of: asc, desc")
        reverse = normalized_sort_order == "desc"
        summaries.sort(
            key=lambda item: self._deployment_sort_value(item=item, sort_by=normalized_sort_by),
            reverse=reverse,
        )
        return {
            "deployments": summaries,
            "count": len(summaries),
            "filters": {
                "status": normalized_status or None,
                "source": normalized_source or None,
                "deployment_id_prefix": normalized_deployment_id_prefix or None,
                "service_name": normalized_service_name or None,
                "min_session_count": minimum_session_count,
                "query": normalized_query or None,
            },
            "sort": {
                "by": normalized_sort_by,
                "order": normalized_sort_order,
            },
        }

    def deployment_detail(self, deployment_id: str) -> dict[str, Any]:
        record = self._record_or_raise(deployment_id)
        payload = self._record_detail(record)
        service_names = {service.name.strip().lower() for service in record.services if service.name.strip()}
        session_history = self._deployment_session_history(service_names=service_names)
        payload["runtime"] = self._orchestrator.runtime_deployment(deployment_id=record.deployment_id)
        payload["session_history"] = session_history
        payload["session_count"] = int(session_history.get("count", 0) or 0)
        payload["drift_metadata"] = self._deployment_live_service_metadata(service_names=service_names)
        return payload

    def state_snapshot(
        self,
        *,
        status: str = "",
        source: str = "",
        deployment_id_prefix: str = "",
        service_name: str = "",
        min_session_count: int = 0,
        query: str = "",
        sort_by: str = "created_at",
        sort_order: str = "desc",
        include_active_services: bool = True,
        include_runtime_deployments: bool = True,
    ) -> dict[str, Any]:
        deployments_payload = self.list_deployments(
            status=status,
            source=source,
            deployment_id_prefix=deployment_id_prefix,
            service_name=service_name,
            min_session_count=min_session_count,
            query=query,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        active_services = self._orchestrator.active_service_bindings() if include_active_services else []
        active_service_details = self._orchestrator.active_services_detail() if include_active_services else []
        runtime = self._orchestrator.runtime_deployments() if include_runtime_deployments else []
        return {
            "generated_at": _utc_now(),
            "deployments": deployments_payload["deployments"],
            "active_runtime_deployments": runtime,
            "active_service_bindings": active_services,
            "active_services": active_service_details,
            "count": len(active_services),
            "deployment_count": len(deployments_payload["deployments"]),
            "deployment_filters": dict(deployments_payload.get("filters", {})),
            "deployment_sort": dict(deployments_payload.get("sort", {})),
            "include_active_services": bool(include_active_services),
            "include_runtime_deployments": bool(include_runtime_deployments),
        }

    def _record_or_raise(self, deployment_id: str) -> DeploymentRecord:
        normalized_id = deployment_id.strip()
        if not normalized_id:
            raise EcosystemDeploymentNotFoundError("deployment id cannot be empty")
        with self._lock:
            record = self._deployments.get(normalized_id)
        if record is None:
            raise EcosystemDeploymentNotFoundError(f"deployment '{normalized_id}' not found")
        return record

    @staticmethod
    def _normalize_manifest(payload: dict[str, Any]) -> dict[str, Any]:
        manifest = payload.get("manifest")
        if isinstance(manifest, dict):
            return deepcopy(manifest)
        return deepcopy(payload)

    @staticmethod
    def _parse_manifest_services(manifest: dict[str, Any]) -> list[ServiceConfig]:
        raw_services = manifest.get("services")
        if not isinstance(raw_services, list):
            raise EcosystemDeploymentError("deployment manifest must include a 'services' list")
        try:
            parsed = parse_config({"services": raw_services})
        except ValueError as exc:
            raise EcosystemDeploymentError(f"invalid deployment manifest: {exc}") from exc
        services = parsed.services
        if not services:
            raise EcosystemDeploymentError("deployment manifest must contain at least one service entry")
        return services

    def _validate_reserved_binding_conflicts(
        self,
        services: list[ServiceConfig],
        *,
        ignore_deployment_id: str | None = None,
    ) -> None:
        requested = set(_service_bindings(services))
        with self._lock:
            existing = list(self._deployments.values())
        for record in existing:
            if record.deployment_id == ignore_deployment_id:
                continue
            if record.status not in {"pending", "active"}:
                continue
            for binding in _service_bindings(record.services):
                if binding in requested:
                    host, port = binding
                    raise EcosystemDeploymentConflictError(
                        f"runtime deployment binding conflict: {host}:{port} is already reserved by "
                        f"deployment '{record.deployment_id}'"
                    )

    def _record_summary(
        self,
        record: DeploymentRecord,
        *,
        session_ids_by_service: dict[str, set[str]] | None = None,
    ) -> dict[str, Any]:
        uptime_seconds = None
        if record.status == "active":
            activated = _parse_timestamp(record.activated_at)
            if activated is not None:
                delta = datetime.now(timezone.utc) - activated
                uptime_seconds = max(0, int(delta.total_seconds()))
        session_count = self._deployment_session_count(
            record,
            session_ids_by_service=session_ids_by_service,
        )
        return {
            "deployment_id": record.deployment_id,
            "status": record.status,
            "source": record.source,
            "created_at": record.created_at,
            "activated_at": record.activated_at,
            "deleted_at": record.deleted_at,
            "uptime_seconds": uptime_seconds,
            "session_count": session_count,
            "service_count": len(record.services),
            "services": [service.name for service in record.services],
            "last_error": record.last_error,
        }

    def _record_detail(self, record: DeploymentRecord) -> dict[str, Any]:
        payload = self._record_summary(record)
        payload["manifest"] = deepcopy(record.manifest)
        payload["service_configs"] = [
            {
                "name": service.name,
                "module": service.module,
                "enabled": service.enabled,
                "listen_host": service.listen_host,
                "ports": list(service.ports),
                "config": dict(service.config),
            }
            for service in record.services
        ]
        return payload

    @staticmethod
    def _deployment_sort_value(*, item: dict[str, Any], sort_by: str) -> tuple[int, Any]:
        if sort_by in {"service_count", "session_count", "uptime_seconds"}:
            value = item.get(sort_by)
            if value is None:
                return (1, 0)
            try:
                return (0, int(value))
            except (TypeError, ValueError):
                return (1, 0)
        value = str(item.get(sort_by, "") or "")
        return (0 if value else 1, value)

    def _session_ids_by_service_name(self) -> dict[str, set[str]]:
        sessions = self._orchestrator.session_manager.export_sessions(limit=2000, events_per_session=120)
        service_sessions: dict[str, set[str]] = {}
        for session in sessions:
            if not isinstance(session, dict):
                continue
            session_id = str(session.get("session_id", "")).strip()
            if not session_id:
                continue
            events = session.get("events")
            if not isinstance(events, list):
                continue
            seen_services: set[str] = set()
            for raw_event in events:
                if not isinstance(raw_event, dict):
                    continue
                service_name = str(raw_event.get("service", "")).strip().lower()
                if service_name:
                    seen_services.add(service_name)
            for service_name in seen_services:
                service_sessions.setdefault(service_name, set()).add(session_id)
        return service_sessions

    def _deployment_session_count(
        self,
        record: DeploymentRecord,
        *,
        session_ids_by_service: dict[str, set[str]] | None = None,
    ) -> int:
        service_names = {
            service.name.strip().lower()
            for service in record.services
            if service.name.strip()
        }
        if not service_names:
            return 0
        mapping = session_ids_by_service if session_ids_by_service is not None else self._session_ids_by_service_name()
        matched_session_ids: set[str] = set()
        for service_name in service_names:
            matched_session_ids.update(mapping.get(service_name, set()))
        return len(matched_session_ids)

    def _deployment_session_history(self, *, service_names: set[str]) -> dict[str, Any]:
        if not service_names:
            return {"count": 0, "sessions": []}
        sessions = self._orchestrator.session_manager.export_sessions(limit=400, events_per_session=120)
        matched: list[dict[str, Any]] = []
        for session in sessions:
            if not isinstance(session, dict):
                continue
            events = session.get("events")
            if not isinstance(events, list):
                continue
            matched_events: list[dict[str, Any]] = []
            for raw_event in events:
                if not isinstance(raw_event, dict):
                    continue
                service_name = str(raw_event.get("service", "")).strip().lower()
                if service_name in service_names:
                    matched_events.append(dict(raw_event))
            if not matched_events:
                continue
            matched.append(
                {
                    "session_id": str(session.get("session_id", "")),
                    "source_ip": str(session.get("source_ip", "")),
                    "created_at": session.get("created_at"),
                    "event_count_total": int(session.get("event_count_total", 0) or 0),
                    "matched_event_count": len(matched_events),
                    "matched_events": matched_events[-20:],
                }
            )
            if len(matched) >= 100:
                break
        return {"count": len(matched), "sessions": matched}

    def _deployment_live_service_metadata(self, *, service_names: set[str]) -> dict[str, Any]:
        if not service_names:
            return {"count": 0, "services": []}
        services = self._orchestrator.active_services_detail()
        matched = [
            service
            for service in services
            if isinstance(service, dict) and str(service.get("name", "")).strip().lower() in service_names
        ]
        return {
            "count": len(matched),
            "services": matched,
        }
