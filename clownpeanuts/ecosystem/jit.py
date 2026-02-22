"""JIT ephemeral deployment lifecycle and pool management."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import threading
import time
from typing import Any

from clownpeanuts.ecosystem.deployment import (
    EcosystemDeploymentConflictError,
    EcosystemDeploymentError,
    EcosystemDeploymentManager,
    EcosystemDeploymentNotFoundError,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class EcosystemJITError(RuntimeError):
    """Base error for ecosystem JIT operations."""


class EcosystemJITNotFoundError(EcosystemJITError):
    """Requested JIT deployment does not exist."""


@dataclass(slots=True)
class JITDeploymentRecord:
    deployment_id: str
    source: str
    slot_id: str
    activated_at: str
    activated_monotonic: float
    last_interaction_at: str
    last_interaction_monotonic: float
    idle_ttl_seconds: int
    max_ttl_seconds: int
    idle_expires_at: str
    max_expires_at: str
    idle_remaining_seconds: int
    max_remaining_seconds: int
    service_names: set[str] = field(default_factory=set)
    session_ids: set[str] = field(default_factory=set)


class EcosystemJITManager:
    """Maintains a pre-warmed pool and JIT deployment TTL lifecycle."""

    _WARMUP_SECONDS = 0.2
    _LATENCY_TARGET_MS = 500

    def __init__(
        self,
        *,
        deployment_manager: EcosystemDeploymentManager,
        pool_size: int = 10,
        ttl_idle_seconds: int = 14_400,
        ttl_max_seconds: int = 86_400,
    ) -> None:
        self._deployments = deployment_manager
        self._lock = threading.RLock()
        self._pool_target_size = max(1, int(pool_size))
        self._idle_ttl_seconds = max(60, int(ttl_idle_seconds))
        self._max_ttl_seconds = max(self._idle_ttl_seconds, int(ttl_max_seconds))
        self._available_slots = self._pool_target_size
        self._warming_slots = 0
        self._slot_counter = 1
        self._records: dict[str, JITDeploymentRecord] = {}
        self._service_to_deployments: dict[str, set[str]] = {}
        self._scheduler_stop = threading.Event()
        self._scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            name="ecosystem-jit-lifecycle",
            daemon=True,
        )
        self._scheduler_thread.start()

    def deploy(self, manifest_payload: dict[str, Any], *, source: str = "jit") -> dict[str, Any]:
        payload = dict(manifest_payload)
        started = time.monotonic()
        with self._lock:
            if self._available_slots <= 0:
                raise EcosystemJITError("jit pool exhausted; no pre-warmed slots are currently available")
            slot_id = f"jit-slot-{self._slot_counter}"
            self._slot_counter += 1
            self._available_slots -= 1

        try:
            registered = self._deployments.register_manifest(payload, source=source.strip() or "jit")
            deployment_id = str(registered.get("deployment_id", "")).strip()
            if not deployment_id:
                raise EcosystemJITError("jit deployment registration did not return a deployment id")
            activation = self._deployments.activate(deployment_id)
            detail = self._deployments.deployment_detail(deployment_id)
        except (
            EcosystemDeploymentConflictError,
            EcosystemDeploymentError,
            EcosystemDeploymentNotFoundError,
            EcosystemJITError,
        ) as exc:
            with self._lock:
                self._available_slots += 1
            raise EcosystemJITError(str(exc)) from exc

        service_names = {
            str(item.get("name", "")).strip().lower()
            for item in detail.get("service_configs", [])
            if isinstance(item, dict) and str(item.get("name", "")).strip()
        }
        now_monotonic = time.monotonic()
        record = JITDeploymentRecord(
            deployment_id=deployment_id,
            source=str(detail.get("source", source)).strip() or "jit",
            slot_id=slot_id,
            activated_at=str(activation.get("activated_at") or _utc_now()),
            activated_monotonic=now_monotonic,
            last_interaction_at=_utc_now(),
            last_interaction_monotonic=now_monotonic,
            idle_ttl_seconds=self._idle_ttl_seconds,
            max_ttl_seconds=self._max_ttl_seconds,
            idle_expires_at=_utc_now(),
            max_expires_at=_utc_now(),
            idle_remaining_seconds=self._idle_ttl_seconds,
            max_remaining_seconds=self._max_ttl_seconds,
            service_names=service_names,
            session_ids=set(),
        )
        self._refresh_record_ttl(record, now_monotonic=now_monotonic)
        with self._lock:
            self._records[deployment_id] = record
            for service in service_names:
                self._service_to_deployments.setdefault(service, set()).add(deployment_id)
        self._schedule_pool_replenish()
        latency_ms = int((time.monotonic() - started) * 1000.0)
        return {
            "deployment_id": deployment_id,
            "slot_id": slot_id,
            "source": record.source,
            "status": "active",
            "activation_latency_ms": latency_ms,
            "latency_target_ms": self._LATENCY_TARGET_MS,
            "meets_latency_target": latency_ms <= self._LATENCY_TARGET_MS,
            "activated_at": record.activated_at,
            "idle_ttl_seconds": self._idle_ttl_seconds,
            "max_ttl_seconds": self._max_ttl_seconds,
            "idle_expires_at": record.idle_expires_at,
            "max_expires_at": record.max_expires_at,
        }

    def touch_deployment(self, *, deployment_id: str, session_id: str | None = None) -> bool:
        normalized_id = deployment_id.strip()
        if not normalized_id:
            return False
        with self._lock:
            record = self._records.get(normalized_id)
            if record is None:
                return False
            now_monotonic = time.monotonic()
            record.last_interaction_monotonic = now_monotonic
            record.last_interaction_at = _utc_now()
            if session_id:
                normalized_session = session_id.strip()
                if normalized_session:
                    record.session_ids.add(normalized_session)
            self._refresh_record_ttl(record, now_monotonic=now_monotonic)
            return True

    def touch_from_event(self, event_payload: dict[str, Any]) -> None:
        if not isinstance(event_payload, dict):
            return
        service = str(event_payload.get("service", "")).strip().lower()
        if not service:
            return
        session_id = str(event_payload.get("session_id", "")).strip()
        with self._lock:
            deployment_ids = list(self._service_to_deployments.get(service, set()))
        for deployment_id in deployment_ids:
            self.touch_deployment(deployment_id=deployment_id, session_id=session_id or None)

    def pool_status(self) -> dict[str, Any]:
        with self._lock:
            active_count = len(self._records)
            return {
                "pool_target_size": self._pool_target_size,
                "available_containers": self._available_slots,
                "in_use_containers": active_count,
                "warming_containers": self._warming_slots,
                "total_capacity": self._available_slots + active_count + self._warming_slots,
            }

    def deployments_status(self) -> dict[str, Any]:
        return self.deployments_status_filtered()

    def deployments_status_filtered(
        self,
        *,
        source: str = "",
        deployment_id_prefix: str = "",
        service_name: str = "",
        min_session_count: int = 0,
        query: str = "",
        sort_by: str = "activated_at",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        normalized_source = source.strip().lower()
        normalized_deployment_prefix = deployment_id_prefix.strip().lower()
        normalized_service_name = service_name.strip().lower()
        normalized_query = query.strip().lower()
        minimum_sessions = max(0, int(min_session_count))
        normalized_sort_by = sort_by.strip().lower() if sort_by else "activated_at"
        allowed_sort_by = {
            "activated_at",
            "last_interaction_at",
            "idle_remaining_seconds",
            "max_remaining_seconds",
            "session_count",
            "source",
            "deployment_id",
            "slot_id",
        }
        if normalized_sort_by not in allowed_sort_by:
            raise EcosystemJITError(
                "sort_by must be one of: activated_at, last_interaction_at, idle_remaining_seconds, "
                "max_remaining_seconds, session_count, source, deployment_id, slot_id"
            )
        normalized_sort_order = sort_order.strip().lower() if sort_order else "desc"
        if normalized_sort_order not in {"asc", "desc"}:
            raise EcosystemJITError("sort_order must be one of: asc, desc")

        with self._lock:
            rows = [self._snapshot_record(item) for item in self._records.values()]
        filtered: list[dict[str, Any]] = []
        for row in rows:
            row_source = str(row.get("source", "")).strip().lower()
            row_deployment_id = str(row.get("deployment_id", "")).strip().lower()
            service_names = row.get("service_names")
            row_service_names = (
                [str(item).strip().lower() for item in service_names]
                if isinstance(service_names, list)
                else []
            )
            row_session_count = int(row.get("session_count", 0) or 0)
            if normalized_source and row_source != normalized_source:
                continue
            if normalized_deployment_prefix and not row_deployment_id.startswith(normalized_deployment_prefix):
                continue
            if normalized_service_name and normalized_service_name not in row_service_names:
                continue
            if row_session_count < minimum_sessions:
                continue
            if normalized_query:
                searchable = " ".join(
                    [
                        row_deployment_id,
                        str(row.get("slot_id", "")).strip().lower(),
                        row_source,
                        " ".join(row_service_names),
                    ]
                )
                if normalized_query not in searchable:
                    continue
            filtered.append(row)

        reverse = normalized_sort_order == "desc"
        filtered.sort(
            key=lambda item: self._deployment_sort_value(item=item, sort_by=normalized_sort_by),
            reverse=reverse,
        )
        return {
            "count": len(filtered),
            "total": len(rows),
            "deployments": filtered,
            "filters": {
                "source": normalized_source or None,
                "deployment_id_prefix": normalized_deployment_prefix or None,
                "service_name": normalized_service_name or None,
                "min_session_count": minimum_sessions,
                "query": normalized_query or None,
            },
            "sort": {
                "by": normalized_sort_by,
                "order": normalized_sort_order,
            },
        }

    def _schedule_pool_replenish(self) -> None:
        with self._lock:
            self._warming_slots += 1

        def _worker() -> None:
            time.sleep(self._WARMUP_SECONDS)
            with self._lock:
                self._warming_slots = max(0, self._warming_slots - 1)
                if self._available_slots < self._pool_target_size:
                    self._available_slots += 1

        threading.Thread(
            target=_worker,
            name="ecosystem-jit-pool-replenish",
            daemon=True,
        ).start()

    def _scheduler_loop(self) -> None:
        while not self._scheduler_stop.wait(1.0):
            expired_ids: list[str] = []
            with self._lock:
                now_monotonic = time.monotonic()
                for deployment_id, record in self._records.items():
                    self._refresh_record_ttl(record, now_monotonic=now_monotonic)
                    if record.idle_remaining_seconds <= 0 or record.max_remaining_seconds <= 0:
                        expired_ids.append(deployment_id)
            for deployment_id in expired_ids:
                self._teardown_expired(deployment_id)

    def _teardown_expired(self, deployment_id: str) -> None:
        try:
            self._deployments.delete(deployment_id)
        except Exception:
            pass
        with self._lock:
            record = self._records.pop(deployment_id, None)
            if record is None:
                return
            for service_name in record.service_names:
                deployment_ids = self._service_to_deployments.get(service_name)
                if deployment_ids is None:
                    continue
                deployment_ids.discard(deployment_id)
                if not deployment_ids:
                    self._service_to_deployments.pop(service_name, None)

    def close(self) -> None:
        self._scheduler_stop.set()
        if self._scheduler_thread.is_alive():
            self._scheduler_thread.join(timeout=1.0)

    @staticmethod
    def _refresh_record_ttl(record: JITDeploymentRecord, *, now_monotonic: float) -> None:
        idle_elapsed = max(0.0, now_monotonic - record.last_interaction_monotonic)
        max_elapsed = max(0.0, now_monotonic - record.activated_monotonic)
        record.idle_remaining_seconds = max(0, record.idle_ttl_seconds - int(idle_elapsed))
        record.max_remaining_seconds = max(0, record.max_ttl_seconds - int(max_elapsed))
        record.idle_expires_at = datetime.fromtimestamp(
            time.time() + record.idle_remaining_seconds,
            tz=timezone.utc,
        ).isoformat(timespec="seconds")
        record.max_expires_at = datetime.fromtimestamp(
            time.time() + record.max_remaining_seconds,
            tz=timezone.utc,
        ).isoformat(timespec="seconds")

    @staticmethod
    def _snapshot_record(record: JITDeploymentRecord) -> dict[str, Any]:
        return {
            "deployment_id": record.deployment_id,
            "slot_id": record.slot_id,
            "source": record.source,
            "activated_at": record.activated_at,
            "last_interaction_at": record.last_interaction_at,
            "idle_ttl_seconds": record.idle_ttl_seconds,
            "max_ttl_seconds": record.max_ttl_seconds,
            "idle_remaining_seconds": record.idle_remaining_seconds,
            "max_remaining_seconds": record.max_remaining_seconds,
            "idle_expires_at": record.idle_expires_at,
            "max_expires_at": record.max_expires_at,
            "service_names": sorted(record.service_names),
            "session_count": len(record.session_ids),
        }

    @staticmethod
    def _deployment_sort_value(*, item: dict[str, Any], sort_by: str) -> tuple[int, Any]:
        if sort_by in {"idle_remaining_seconds", "max_remaining_seconds", "session_count"}:
            value = item.get(sort_by)
            if value is None:
                return (1, 0)
            try:
                return (0, int(value))
            except (TypeError, ValueError):
                return (1, 0)
        value = str(item.get(sort_by, "") or "")
        return (0 if value else 1, value)
