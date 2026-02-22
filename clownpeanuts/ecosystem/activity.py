"""Runtime activity injection manager for ecosystem mode."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
import threading
import time
from typing import Any
from uuid import uuid4


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(slots=True)
class ActivityRecord:
    activity_id: str
    deployment_id: str
    payload: dict[str, Any]
    schedule_mode: str
    created_at: str
    active: bool
    interval_seconds: float | None = None
    cron: str | None = None
    next_run_monotonic: float | None = None
    next_run_at: str | None = None
    last_run_at: str | None = None
    run_count: int = 0
    last_error: str = ""
    last_result: dict[str, Any] | None = None
    cancelled_at: str | None = None


class EcosystemActivityError(RuntimeError):
    """Base error for ecosystem activity operations."""


class EcosystemActivityNotFoundError(EcosystemActivityError):
    """Requested activity id does not exist."""


class EcosystemActivityManager:
    """Executes immediate and interval activity injections for runtime deployments."""

    def __init__(self, *, orchestrator: Any) -> None:
        self._orchestrator = orchestrator
        self._lock = threading.RLock()
        self._records: dict[str, ActivityRecord] = {}
        self._scheduler_thread: threading.Thread | None = None
        self._scheduler_stop = threading.Event()

    @staticmethod
    def _parse_cron_field(field: str, *, minimum: int, maximum: int) -> set[int] | None:
        token = field.strip()
        if not token:
            return None
        if token == "*":
            return set(range(minimum, maximum + 1))
        values: set[int] = set()
        for part in token.split(","):
            part = part.strip()
            if not part:
                return None
            if part.startswith("*/"):
                step_raw = part[2:].strip()
                if not step_raw:
                    return None
                try:
                    step = int(step_raw)
                except ValueError:
                    return None
                if step <= 0:
                    return None
                values.update(range(minimum, maximum + 1, step))
                continue
            try:
                value = int(part)
            except ValueError:
                return None
            if value < minimum or value > maximum:
                return None
            values.add(value)
        return values if values else None

    @classmethod
    def _next_cron_occurrence(cls, cron_expr: str, *, now: datetime | None = None) -> datetime:
        raw = cron_expr.strip()
        parts = raw.split()
        if len(parts) != 5:
            raise EcosystemActivityError("cron expression must have 5 fields: minute hour day month weekday")
        minute_values = cls._parse_cron_field(parts[0], minimum=0, maximum=59)
        hour_values = cls._parse_cron_field(parts[1], minimum=0, maximum=23)
        day_values = cls._parse_cron_field(parts[2], minimum=1, maximum=31)
        month_values = cls._parse_cron_field(parts[3], minimum=1, maximum=12)
        weekday_values = cls._parse_cron_field(parts[4], minimum=0, maximum=7)
        if (
            minute_values is None
            or hour_values is None
            or day_values is None
            or month_values is None
            or weekday_values is None
        ):
            raise EcosystemActivityError("invalid cron expression field")
        normalized_weekdays = {0 if item == 7 else item for item in weekday_values}
        day_any = parts[2].strip() == "*"
        weekday_any = parts[4].strip() == "*"

        reference = now or datetime.now(UTC)
        candidate = (reference + timedelta(minutes=1)).replace(second=0, microsecond=0)
        # Search up to one year ahead.
        for _ in range(0, 366 * 24 * 60):
            if candidate.minute not in minute_values:
                candidate += timedelta(minutes=1)
                continue
            if candidate.hour not in hour_values:
                candidate += timedelta(minutes=1)
                continue
            if candidate.month not in month_values:
                candidate += timedelta(minutes=1)
                continue
            day_match = candidate.day in day_values
            weekday = (candidate.weekday() + 1) % 7  # Sunday=0
            weekday_match = weekday in normalized_weekdays
            if day_any and weekday_any:
                passes_day_gate = True
            elif day_any:
                passes_day_gate = weekday_match
            elif weekday_any:
                passes_day_gate = day_match
            else:
                passes_day_gate = day_match or weekday_match
            if passes_day_gate:
                return candidate
            candidate += timedelta(minutes=1)
        raise EcosystemActivityError("cron expression does not produce a runnable schedule within one year")

    def _schedule_next_run(self, record: ActivityRecord) -> None:
        if record.schedule_mode in {"interval", "recurring"}:
            interval_seconds = float(record.interval_seconds or 0.0)
            if interval_seconds <= 0:
                record.active = False
                record.next_run_monotonic = None
                record.next_run_at = None
                return
            record.next_run_monotonic = time.monotonic() + interval_seconds
            next_epoch = time.time() + interval_seconds
            record.next_run_at = datetime.fromtimestamp(next_epoch, tz=timezone.utc).isoformat(timespec="seconds")
            return
        if record.schedule_mode == "cron":
            cron_expr = str(record.cron or "").strip()
            if not cron_expr:
                record.active = False
                record.next_run_monotonic = None
                record.next_run_at = None
                return
            next_run = self._next_cron_occurrence(cron_expr)
            delta = max(0.0, next_run.timestamp() - time.time())
            record.next_run_monotonic = time.monotonic() + delta
            record.next_run_at = next_run.isoformat(timespec="seconds")
            return
        record.next_run_monotonic = None
        record.next_run_at = None

    def inject(self, *, deployment_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        normalized_deployment_id = deployment_id.strip()
        if not normalized_deployment_id:
            raise EcosystemActivityError("deployment_id cannot be empty")
        if not isinstance(payload, dict):
            raise EcosystemActivityError("activity payload must be an object")

        schedule = payload.get("schedule")
        mode = "once"
        interval_seconds: float | None = None
        cron: str | None = None
        if isinstance(schedule, dict):
            raw_mode = str(schedule.get("mode") or schedule.get("type") or "once").strip().lower()
            if raw_mode:
                mode = raw_mode
            interval_raw = schedule.get("interval_seconds", schedule.get("interval"))
            if interval_raw is not None:
                try:
                    interval_seconds = float(interval_raw)
                except (TypeError, ValueError) as exc:
                    raise EcosystemActivityError("schedule interval_seconds must be numeric") from exc
            cron_value = schedule.get("cron")
            if cron_value is not None:
                cron = str(cron_value).strip() or None

        if mode not in {"once", "interval", "recurring", "cron"}:
            raise EcosystemActivityError("schedule mode must be 'once', 'interval', 'recurring', or 'cron'")

        activity_id = uuid4().hex[:12]
        record = ActivityRecord(
            activity_id=activity_id,
            deployment_id=normalized_deployment_id,
            payload=dict(payload),
            schedule_mode=mode,
            created_at=_utc_now(),
            active=mode in {"interval", "recurring", "cron"},
            interval_seconds=interval_seconds if mode in {"interval", "recurring"} else None,
            cron=cron if mode == "cron" else None,
        )

        if mode == "once":
            try:
                result = self._orchestrator.inject_runtime_activity(
                    deployment_id=normalized_deployment_id,
                    payload=record.payload,
                )
            except KeyError as exc:
                raise EcosystemActivityError(f"deployment '{normalized_deployment_id}' is not active") from exc
            except ValueError as exc:
                raise EcosystemActivityError(str(exc)) from exc
            record.run_count = 1
            record.last_run_at = _utc_now()
            record.last_result = result
            with self._lock:
                self._records[activity_id] = record
            payload_result = self._record_payload(record)
            payload_result["result"] = result
            return payload_result

        if mode in {"interval", "recurring"}:
            if interval_seconds is None or interval_seconds <= 0:
                raise EcosystemActivityError("interval schedule requires interval_seconds > 0")
        if mode == "cron":
            if not cron:
                raise EcosystemActivityError("cron schedule requires a cron expression")
            # Validate cron expression and compute initial run.
            self._next_cron_occurrence(cron)
        self._schedule_next_run(record)
        with self._lock:
            self._records[activity_id] = record
        self._ensure_scheduler()
        return self._record_payload(record)

    def list(self, *, deployment_id: str) -> dict[str, Any]:
        normalized_deployment_id = deployment_id.strip()
        if not normalized_deployment_id:
            raise EcosystemActivityError("deployment_id cannot be empty")
        return self.list_filtered(deployment_id=normalized_deployment_id)

    def list_filtered(
        self,
        *,
        deployment_id: str,
        schedule_mode: str = "",
        active: bool | None = None,
        query: str = "",
        sort_by: str = "created_at",
        sort_order: str = "desc",
        limit: int = 200,
    ) -> dict[str, Any]:
        normalized_deployment_id = deployment_id.strip()
        if not normalized_deployment_id:
            raise EcosystemActivityError("deployment_id cannot be empty")
        safe_limit = max(1, min(2000, int(limit)))
        normalized_mode = schedule_mode.strip().lower()
        if normalized_mode and normalized_mode not in {"once", "interval", "recurring", "cron"}:
            raise EcosystemActivityError("schedule_mode must be one of: once, interval, recurring, cron")
        normalized_query = query.strip().lower()
        normalized_sort_by = sort_by.strip().lower() if sort_by else "created_at"
        allowed_sort_by = {"created_at", "next_run_at", "last_run_at", "run_count", "schedule_mode", "activity_id"}
        if normalized_sort_by not in allowed_sort_by:
            raise EcosystemActivityError(
                "sort_by must be one of: created_at, next_run_at, last_run_at, run_count, schedule_mode, activity_id"
            )
        normalized_sort_order = sort_order.strip().lower() if sort_order else "desc"
        if normalized_sort_order not in {"asc", "desc"}:
            raise EcosystemActivityError("sort_order must be one of: asc, desc")

        with self._lock:
            records = [
                record
                for record in self._records.values()
                if record.deployment_id == normalized_deployment_id
            ]
        filtered: list[ActivityRecord] = []
        for record in records:
            if normalized_mode and record.schedule_mode != normalized_mode:
                continue
            if active is not None and bool(record.active) is not bool(active):
                continue
            if normalized_query:
                payload = record.payload if isinstance(record.payload, dict) else {}
                searchable = " ".join(
                    [
                        record.activity_id,
                        record.schedule_mode,
                        str(payload.get("type", "")),
                        str(payload.get("service", "")),
                        str(payload.get("session_id", "")),
                        str(payload.get("payload", "")),
                    ]
                ).lower()
                if normalized_query not in searchable:
                    continue
            filtered.append(record)

        reverse = normalized_sort_order == "desc"
        filtered.sort(
            key=lambda item: self._record_sort_value(record=item, sort_by=normalized_sort_by),
            reverse=reverse,
        )
        limited = filtered[:safe_limit]
        return {
            "deployment_id": normalized_deployment_id,
            "activities": [self._record_payload(record) for record in limited],
            "count": len(limited),
            "total_filtered": len(filtered),
            "filters": {
                "schedule_mode": normalized_mode or None,
                "active": active,
                "query": normalized_query or None,
            },
            "sort": {
                "by": normalized_sort_by,
                "order": normalized_sort_order,
            },
        }

    def cancel(self, *, deployment_id: str, activity_id: str) -> dict[str, Any]:
        normalized_deployment_id = deployment_id.strip()
        normalized_activity_id = activity_id.strip()
        if not normalized_deployment_id or not normalized_activity_id:
            raise EcosystemActivityError("deployment_id and activity_id are required")
        with self._lock:
            record = self._records.get(normalized_activity_id)
            if record is None or record.deployment_id != normalized_deployment_id:
                raise EcosystemActivityNotFoundError(
                    f"activity '{normalized_activity_id}' not found for deployment '{normalized_deployment_id}'"
                )
            record.active = False
            record.cancelled_at = _utc_now()
            record.next_run_monotonic = None
            record.next_run_at = None
            return self._record_payload(record)

    def _ensure_scheduler(self) -> None:
        with self._lock:
            if self._scheduler_thread and self._scheduler_thread.is_alive():
                return
            self._scheduler_stop.clear()
            self._scheduler_thread = threading.Thread(
                target=self._scheduler_loop,
                name="ecosystem-activity-scheduler",
                daemon=True,
            )
            self._scheduler_thread.start()

    def _scheduler_loop(self) -> None:
        while not self._scheduler_stop.wait(1.0):
            now = time.monotonic()
            due_ids: list[str] = []
            with self._lock:
                for record in self._records.values():
                    if not record.active:
                        continue
                    if record.next_run_monotonic is None:
                        continue
                    if record.next_run_monotonic <= now:
                        due_ids.append(record.activity_id)
            for activity_id in due_ids:
                self._execute_activity(activity_id)

    def _execute_activity(self, activity_id: str) -> None:
        with self._lock:
            record = self._records.get(activity_id)
            if record is None or not record.active:
                return
            deployment_id = record.deployment_id
            payload = dict(record.payload)

        try:
            result = self._orchestrator.inject_runtime_activity(
                deployment_id=deployment_id,
                payload=payload,
            )
            error_message = ""
        except Exception as exc:  # pragma: no cover - defensive scheduler safety
            result = None
            error_message = f"{type(exc).__name__}: {exc}"

        with self._lock:
            record = self._records.get(activity_id)
            if record is None:
                return
            record.run_count += 1
            record.last_run_at = _utc_now()
            record.last_result = result
            record.last_error = error_message
            if record.active and record.schedule_mode in {"interval", "recurring", "cron"}:
                self._schedule_next_run(record)
            else:
                record.active = False
                record.next_run_monotonic = None
                record.next_run_at = None

    def close(self) -> None:
        self._scheduler_stop.set()
        with self._lock:
            thread = self._scheduler_thread
        if thread and thread.is_alive():
            thread.join(timeout=1.0)
        with self._lock:
            self._scheduler_thread = None

    @staticmethod
    def _record_payload(record: ActivityRecord) -> dict[str, Any]:
        return {
            "activity_id": record.activity_id,
            "deployment_id": record.deployment_id,
            "schedule_mode": record.schedule_mode,
            "active": record.active,
            "created_at": record.created_at,
            "interval_seconds": record.interval_seconds,
            "cron": record.cron,
            "next_run_at": record.next_run_at,
            "last_run_at": record.last_run_at,
            "run_count": record.run_count,
            "last_error": record.last_error,
            "cancelled_at": record.cancelled_at,
        }

    @staticmethod
    def _record_sort_value(*, record: ActivityRecord, sort_by: str) -> tuple[int, Any]:
        if sort_by == "run_count":
            return (0, int(record.run_count))
        if sort_by in {"created_at", "next_run_at", "last_run_at", "schedule_mode", "activity_id"}:
            value = getattr(record, sort_by, None)
            if value is None:
                return (1, "")
            return (0, str(value))
        return (0, str(record.created_at))
