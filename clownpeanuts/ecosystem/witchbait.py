"""Credential registry and trip detection for ecosystem mode."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
import threading
from typing import Any
from uuid import uuid4


_WITCHBAIT_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,80}$")
_AUTH_ACTIONS = {"auth_attempt", "credential_capture"}
_CANDIDATE_FIELDS = {
    "password",
    "passwd",
    "passphrase",
    "username",
    "user",
    "token",
    "api_key",
    "secret",
    "credential",
    "auth_response_hex",
    "scram_payload",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hash_credential_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class WitchbaitCredentialRecord:
    credential_id: str
    credential_type: str
    credential_hash: str
    placement_vector: str
    target_decoy_id: str
    metadata: dict[str, Any]
    created_at: str
    source: str


@dataclass(slots=True)
class WitchbaitTripRecord:
    trip_id: str
    credential_id: str
    credential_type: str
    credential_hash: str
    matched_field: str
    session_id: str
    source_ip: str
    service: str
    action: str
    placement_vector: str
    target_decoy_id: str
    created_at: str


class EcosystemWitchbaitError(RuntimeError):
    """Base error for ecosystem witchbait operations."""


class EcosystemWitchbaitNotFoundError(EcosystemWitchbaitError):
    """Requested witchbait entity does not exist."""


class EcosystemWitchbaitConflictError(EcosystemWitchbaitError):
    """Requested witchbait operation conflicts with existing state."""


class EcosystemWitchbaitManager:
    """In-memory credential registry and event-driven trip detection."""

    _MAX_TRIPS = 10_000

    def __init__(
        self,
        *,
        orchestrator: Any,
        seed_credentials: list[dict[str, Any]] | None = None,
    ) -> None:
        self._orchestrator = orchestrator
        self._lock = threading.RLock()
        self._credentials_by_id: dict[str, WitchbaitCredentialRecord] = {}
        self._credential_id_by_hash: dict[str, str] = {}
        self._session_tags: dict[str, set[str]] = {}
        self._trips: list[WitchbaitTripRecord] = []
        self._event_dedup: dict[str, None] = {}
        self._orchestrator.event_bus.subscribe("events", self._handle_event)

        for raw_seed in seed_credentials or []:
            if not isinstance(raw_seed, dict):
                continue
            try:
                self.register_credential(
                    raw_seed,
                    source="config",
                    allow_existing=True,
                )
            except EcosystemWitchbaitError:
                continue

    def register_credential(
        self,
        payload: dict[str, Any],
        *,
        source: str = "api",
        allow_existing: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise EcosystemWitchbaitError("credential payload must be an object")
        credential_value = str(
            payload.get("credential_value")
            or payload.get("credential")
            or payload.get("value")
            or ""
        ).strip()
        if not credential_value:
            raise EcosystemWitchbaitError("credential_value must be non-empty")

        credential_id = str(payload.get("credential_id") or uuid4().hex[:12]).strip()
        if _WITCHBAIT_ID_RE.fullmatch(credential_id) is None:
            raise EcosystemWitchbaitError(
                "credential_id must match ^[A-Za-z0-9._:-]{1,80}$"
            )

        credential_type = str(payload.get("credential_type") or payload.get("type") or "password").strip().lower()
        if not credential_type:
            credential_type = "password"
        if len(credential_type) > 64:
            raise EcosystemWitchbaitError("credential_type must be 1-64 chars")

        placement_vector = str(payload.get("placement_vector") or payload.get("placement") or "").strip()
        target_decoy_id = str(
            payload.get("target_decoy_id")
            or payload.get("target_deployment_id")
            or payload.get("target_id")
            or ""
        ).strip()
        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            raise EcosystemWitchbaitError("metadata must be an object")

        credential_hash = _hash_credential_value(credential_value)
        with self._lock:
            existing_by_hash = self._credential_id_by_hash.get(credential_hash)
            if existing_by_hash is not None:
                existing_record = self._credentials_by_id.get(existing_by_hash)
                if existing_record is not None:
                    if allow_existing:
                        return self._credential_payload(existing_record)
                    raise EcosystemWitchbaitConflictError(
                        f"credential hash already registered as '{existing_by_hash}'"
                    )
            if credential_id in self._credentials_by_id:
                raise EcosystemWitchbaitConflictError(
                    f"credential id '{credential_id}' already exists"
                )

            record = WitchbaitCredentialRecord(
                credential_id=credential_id,
                credential_type=credential_type,
                credential_hash=credential_hash,
                placement_vector=placement_vector,
                target_decoy_id=target_decoy_id,
                metadata=dict(metadata),
                created_at=_utc_now(),
                source=source.strip() or "api",
            )
            self._credentials_by_id[record.credential_id] = record
            self._credential_id_by_hash[record.credential_hash] = record.credential_id
        return self._credential_payload(record)

    def preview_credentials(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise EcosystemWitchbaitError("credential preview payload must be an object")
        raw_rows = payload.get("credentials", [])
        if not isinstance(raw_rows, list):
            raise EcosystemWitchbaitError("credentials must be a list")

        to_register: list[dict[str, Any]] = []
        already_present: list[dict[str, Any]] = []
        collisions: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        planned_ids: set[str] = set()
        planned_hashes: set[str] = set()

        with self._lock:
            existing_ids = set(self._credentials_by_id.keys())
            existing_hashes = dict(self._credential_id_by_hash)

        for index, row in enumerate(raw_rows, start=1):
            if not isinstance(row, dict):
                skipped.append(
                    {
                        "index": index,
                        "reason": "payload row must be an object",
                    }
                )
                continue
            credential_value = str(
                row.get("credential_value")
                or row.get("credential")
                or row.get("value")
                or ""
            ).strip()
            if not credential_value:
                skipped.append({"index": index, "reason": "credential_value must be non-empty"})
                continue

            credential_id = str(row.get("credential_id", "")).strip()
            if credential_id and _WITCHBAIT_ID_RE.fullmatch(credential_id) is None:
                skipped.append(
                    {
                        "index": index,
                        "credential_id": credential_id,
                        "reason": "credential_id must match ^[A-Za-z0-9._:-]{1,80}$",
                    }
                )
                continue

            metadata = row.get("metadata", {})
            if metadata is None:
                metadata = {}
            if not isinstance(metadata, dict):
                skipped.append(
                    {
                        "index": index,
                        "credential_id": credential_id or None,
                        "reason": "metadata must be an object",
                    }
                )
                continue

            candidate = {
                "index": index,
                "credential_id": credential_id or None,
                "credential_type": str(row.get("credential_type") or row.get("type") or "password").strip().lower()
                or "password",
                "placement_vector": str(row.get("placement_vector") or row.get("placement") or "").strip(),
                "target_decoy_id": str(
                    row.get("target_decoy_id")
                    or row.get("target_deployment_id")
                    or row.get("target_id")
                    or ""
                ).strip(),
                "metadata": dict(metadata),
            }
            credential_hash = _hash_credential_value(credential_value)
            existing_credential_id = existing_hashes.get(credential_hash)
            if existing_credential_id:
                already_present.append(
                    {
                        **candidate,
                        "credential_hash": credential_hash,
                        "existing_credential_id": existing_credential_id,
                        "reason": "credential_hash_already_registered",
                    }
                )
                continue

            if credential_id and credential_id in existing_ids:
                collisions.append(
                    {
                        **candidate,
                        "credential_hash": credential_hash,
                        "reason": "credential_id_already_registered",
                    }
                )
                continue

            if credential_hash in planned_hashes:
                collisions.append(
                    {
                        **candidate,
                        "credential_hash": credential_hash,
                        "reason": "duplicate_credential_value_in_payload",
                    }
                )
                continue
            if credential_id and credential_id in planned_ids:
                collisions.append(
                    {
                        **candidate,
                        "credential_hash": credential_hash,
                        "reason": "duplicate_credential_id_in_payload",
                    }
                )
                continue

            planned_hashes.add(credential_hash)
            if credential_id:
                planned_ids.add(credential_id)
            to_register.append({**candidate, "credential_hash": credential_hash})

        return {
            "status": "preview",
            "requested": len(raw_rows),
            "to_register_count": len(to_register),
            "already_present_count": len(already_present),
            "collision_count": len(collisions),
            "skipped_count": len(skipped),
            "to_register": to_register,
            "already_present": already_present,
            "collisions": collisions,
            "skipped": skipped,
        }

    def delete_credential(self, credential_id: str) -> dict[str, Any]:
        normalized_id = credential_id.strip()
        if not normalized_id:
            raise EcosystemWitchbaitNotFoundError("credential_id cannot be empty")
        with self._lock:
            record = self._credentials_by_id.pop(normalized_id, None)
            if record is None:
                raise EcosystemWitchbaitNotFoundError(
                    f"credential '{normalized_id}' not found"
                )
            current = self._credential_id_by_hash.get(record.credential_hash)
            if current == normalized_id:
                self._credential_id_by_hash.pop(record.credential_hash, None)
        return {
            "credential_id": normalized_id,
            "status": "deleted",
            "deleted_at": _utc_now(),
        }

    def list_credentials(self) -> dict[str, Any]:
        return self.list_credentials_filtered()

    def list_credentials_filtered(
        self,
        *,
        credential_type: str = "",
        source: str = "",
        target_decoy_id: str = "",
        query: str = "",
        sort_by: str = "created_at",
        sort_order: str = "desc",
        limit: int = 200,
    ) -> dict[str, Any]:
        safe_limit = max(1, min(2000, int(limit)))
        normalized_type = credential_type.strip().lower()
        normalized_source = source.strip().lower()
        normalized_target_decoy_id = target_decoy_id.strip().lower()
        normalized_query = query.strip().lower()
        normalized_sort_by = sort_by.strip().lower() if sort_by else "created_at"
        allowed_sort_by = {"created_at", "credential_id", "credential_type", "source", "target_decoy_id"}
        if normalized_sort_by not in allowed_sort_by:
            raise EcosystemWitchbaitError(
                "sort_by must be one of: created_at, credential_id, credential_type, source, target_decoy_id"
            )
        normalized_sort_order = sort_order.strip().lower() if sort_order else "desc"
        if normalized_sort_order not in {"asc", "desc"}:
            raise EcosystemWitchbaitError("sort_order must be one of: asc, desc")

        with self._lock:
            rows = list(self._credentials_by_id.values())
        filtered: list[WitchbaitCredentialRecord] = []
        for row in rows:
            row_type = row.credential_type.strip().lower()
            row_source = row.source.strip().lower()
            row_target_decoy_id = row.target_decoy_id.strip().lower()
            if normalized_type and row_type != normalized_type:
                continue
            if normalized_source and row_source != normalized_source:
                continue
            if normalized_target_decoy_id and row_target_decoy_id != normalized_target_decoy_id:
                continue
            if normalized_query:
                searchable = " ".join(
                    [
                        row.credential_id,
                        row_type,
                        row_source,
                        row_target_decoy_id,
                        row.placement_vector.strip().lower(),
                        str(row.metadata).lower(),
                    ]
                )
                if normalized_query not in searchable:
                    continue
            filtered.append(row)

        reverse = normalized_sort_order == "desc"
        filtered.sort(
            key=lambda item: self._credential_sort_value(record=item, sort_by=normalized_sort_by),
            reverse=reverse,
        )
        limited = filtered[:safe_limit]
        return {
            "count": len(limited),
            "total": len(rows),
            "total_filtered": len(filtered),
            "credentials": [self._credential_payload(record) for record in limited],
            "filters": {
                "credential_type": normalized_type or None,
                "source": normalized_source or None,
                "target_decoy_id": normalized_target_decoy_id or None,
                "query": normalized_query or None,
            },
            "sort": {
                "by": normalized_sort_by,
                "order": normalized_sort_order,
            },
        }

    def list_trips(self, *, limit: int = 200) -> dict[str, Any]:
        return self.list_trips_filtered(limit=limit)

    @staticmethod
    def _normalize_timestamp(value: str) -> str:
        raw = value.strip()
        if not raw:
            return ""
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise EcosystemWitchbaitError("timestamp filters must be valid ISO-8601 values") from exc
        return parsed.isoformat(timespec="seconds")

    def list_trips_filtered(
        self,
        *,
        limit: int = 200,
        credential_id: str = "",
        service: str = "",
        action: str = "",
        matched_field: str = "",
        source_ip_prefix: str = "",
        session_prefix: str = "",
        query: str = "",
        created_after: str = "",
        created_before: str = "",
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        safe_limit = max(1, min(2000, int(limit)))
        normalized_credential_id = credential_id.strip().lower()
        normalized_service = service.strip().lower()
        normalized_action = action.strip().lower()
        normalized_matched_field = matched_field.strip().lower()
        normalized_source_ip_prefix = source_ip_prefix.strip().lower()
        normalized_session_prefix = session_prefix.strip().lower()
        normalized_query = query.strip().lower()
        after = self._normalize_timestamp(created_after) if created_after.strip() else ""
        before = self._normalize_timestamp(created_before) if created_before.strip() else ""
        if after and before and after > before:
            raise EcosystemWitchbaitError("created_after must be less than or equal to created_before")

        normalized_sort_by = sort_by.strip().lower() if sort_by else "created_at"
        allowed_sort_by = {
            "created_at",
            "credential_id",
            "service",
            "action",
            "matched_field",
            "session_id",
            "source_ip",
            "trip_id",
        }
        if normalized_sort_by not in allowed_sort_by:
            raise EcosystemWitchbaitError(
                "sort_by must be one of: created_at, credential_id, service, action, matched_field, session_id, "
                "source_ip, trip_id"
            )
        normalized_sort_order = sort_order.strip().lower() if sort_order else "desc"
        if normalized_sort_order not in {"asc", "desc"}:
            raise EcosystemWitchbaitError("sort_order must be one of: asc, desc")

        with self._lock:
            rows = list(self._trips)
        filtered: list[WitchbaitTripRecord] = []
        for row in rows:
            row_credential_id = row.credential_id.strip().lower()
            row_service = row.service.strip().lower()
            row_action = row.action.strip().lower()
            row_matched_field = row.matched_field.strip().lower()
            row_source_ip = row.source_ip.strip().lower()
            row_session_id = row.session_id.strip().lower()
            row_created_at = row.created_at.strip()

            if normalized_credential_id and row_credential_id != normalized_credential_id:
                continue
            if normalized_service and row_service != normalized_service:
                continue
            if normalized_action and row_action != normalized_action:
                continue
            if normalized_matched_field and row_matched_field != normalized_matched_field:
                continue
            if normalized_source_ip_prefix and not row_source_ip.startswith(normalized_source_ip_prefix):
                continue
            if normalized_session_prefix and not row_session_id.startswith(normalized_session_prefix):
                continue
            if after and row_created_at < after:
                continue
            if before and row_created_at > before:
                continue
            if normalized_query:
                searchable = " ".join(
                    [
                        row.trip_id,
                        row_credential_id,
                        row.credential_type.strip().lower(),
                        row_matched_field,
                        row_session_id,
                        row_source_ip,
                        row_service,
                        row_action,
                        row.placement_vector.strip().lower(),
                        row.target_decoy_id.strip().lower(),
                    ]
                )
                if normalized_query not in searchable:
                    continue
            filtered.append(row)

        reverse = normalized_sort_order == "desc"
        filtered.sort(
            key=lambda item: self._trip_sort_value(record=item, sort_by=normalized_sort_by),
            reverse=reverse,
        )
        limited = filtered[:safe_limit]
        return {
            "count": len(limited),
            "total": len(rows),
            "total_filtered": len(filtered),
            "trips": [self._trip_payload(item) for item in limited],
            "filters": {
                "credential_id": normalized_credential_id or None,
                "service": normalized_service or None,
                "action": normalized_action or None,
                "matched_field": normalized_matched_field or None,
                "source_ip_prefix": normalized_source_ip_prefix or None,
                "session_prefix": normalized_session_prefix or None,
                "query": normalized_query or None,
                "created_after": after or None,
                "created_before": before or None,
            },
            "sort": {
                "by": normalized_sort_by,
                "order": normalized_sort_order,
            },
        }

    def trip_summary(
        self,
        *,
        limit: int = 500,
        credential_id: str = "",
        service: str = "",
        action: str = "",
        matched_field: str = "",
        source_ip_prefix: str = "",
        session_prefix: str = "",
        query: str = "",
        created_after: str = "",
        created_before: str = "",
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        safe_limit = max(1, min(2000, int(limit)))
        listing = self.list_trips_filtered(
            limit=safe_limit,
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
        trips = listing.get("trips", [])
        if not isinstance(trips, list):
            trips = []
        created_values = [
            str(row.get("created_at", "")).strip()
            for row in trips
            if isinstance(row, dict) and str(row.get("created_at", "")).strip()
        ]
        total_filtered = int(listing.get("total_filtered", len(trips)))
        return {
            "count": len(trips),
            "total_filtered": total_filtered,
            "limit": safe_limit,
            "truncated": total_filtered > len(trips),
            "window": {
                "earliest_created_at": min(created_values) if created_values else None,
                "latest_created_at": max(created_values) if created_values else None,
            },
            "by_credential_id": self._ranked_counts(trips, key="credential_id", label="credential_id"),
            "by_service": self._ranked_counts(trips, key="service", label="service"),
            "by_action": self._ranked_counts(trips, key="action", label="action"),
            "by_matched_field": self._ranked_counts(trips, key="matched_field", label="matched_field"),
            "by_source_ip": self._ranked_counts(trips, key="source_ip", label="source_ip"),
            "filters": dict(listing.get("filters", {})),
            "sort": dict(listing.get("sort", {})),
        }

    def session_tags(self, session_id: str) -> list[str]:
        normalized_session_id = session_id.strip()
        if not normalized_session_id:
            return []
        with self._lock:
            values = self._session_tags.get(normalized_session_id, set())
            return sorted(values)

    def _handle_event(self, envelope: dict[str, Any]) -> None:
        event = envelope.get("payload")
        if not isinstance(event, dict):
            return
        action = str(event.get("action", "")).strip().lower()
        if action not in _AUTH_ACTIONS:
            return
        payload = event.get("payload")
        if not isinstance(payload, dict):
            payload = {}

        candidates = self._extract_candidates(event, payload)
        if not candidates:
            return

        source_ip = str(event.get("source_ip") or payload.get("source_ip") or "").strip()
        session_id = str(event.get("session_id", "")).strip()
        service = str(event.get("service", "")).strip()
        timestamp = str(event.get("timestamp", "")).strip() or _utc_now()

        for field_name, candidate_value in candidates:
            credential_hash = _hash_credential_value(candidate_value)
            with self._lock:
                credential_id = self._credential_id_by_hash.get(credential_hash)
                if not credential_id:
                    continue
                record = self._credentials_by_id.get(credential_id)
                if record is None:
                    continue
                dedupe_key = "|".join(
                    [
                        timestamp,
                        session_id,
                        source_ip,
                        service,
                        action,
                        credential_id,
                        field_name,
                    ]
                )
                if dedupe_key in self._event_dedup:
                    continue
                self._event_dedup[dedupe_key] = None
                if len(self._event_dedup) > (self._MAX_TRIPS * 2):
                    trim_keys = list(self._event_dedup.keys())[: self._MAX_TRIPS]
                    for key in trim_keys:
                        self._event_dedup.pop(key, None)
                if session_id:
                    tagged = self._session_tags.setdefault(session_id, set())
                    tagged.add(record.credential_id)
                    self._orchestrator.session_manager.add_session_tags(
                        session_id=session_id,
                        source_ip=source_ip or "unknown",
                        tags=[
                            "witchbait",
                            record.credential_id,
                            f"witchbait:{record.credential_id}",
                        ],
                    )

                trip = WitchbaitTripRecord(
                    trip_id=uuid4().hex[:12],
                    credential_id=record.credential_id,
                    credential_type=record.credential_type,
                    credential_hash=record.credential_hash,
                    matched_field=field_name,
                    session_id=session_id,
                    source_ip=source_ip,
                    service=service,
                    action=action,
                    placement_vector=record.placement_vector,
                    target_decoy_id=record.target_decoy_id,
                    created_at=_utc_now(),
                )
                self._trips.insert(0, trip)
                if len(self._trips) > self._MAX_TRIPS:
                    self._trips = self._trips[: self._MAX_TRIPS]

            self._orchestrator.event_logger.emit(
                message="witchbait credential trip detected",
                service="ecosystem",
                action="witchbait_trip",
                session_id=session_id or None,
                source_ip=source_ip or None,
                event_type="alert",
                outcome="success",
                payload={
                    "witchbait_credential_id": trip.credential_id,
                    "credential_type": trip.credential_type,
                    "matched_field": trip.matched_field,
                    "placement_vector": trip.placement_vector,
                    "target_decoy_id": trip.target_decoy_id,
                    "service": service,
                    "trigger_action": action,
                    "session_tags": self._orchestrator.session_manager.session_tags(session_id),
                },
                level="WARNING",
            )

    @staticmethod
    def _extract_candidates(event: dict[str, Any], payload: dict[str, Any]) -> list[tuple[str, str]]:
        candidates: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for source_name, source_payload in (("event", event), ("payload", payload)):
            for key, value in source_payload.items():
                normalized_key = str(key).strip().lower()
                if normalized_key not in _CANDIDATE_FIELDS:
                    continue
                if not isinstance(value, str):
                    continue
                candidate = value.strip()
                if not candidate:
                    continue
                if len(candidate) > 4096:
                    continue
                item = (f"{source_name}.{normalized_key}", candidate)
                if item in seen:
                    continue
                seen.add(item)
                candidates.append(item)
        return candidates

    @staticmethod
    def _credential_payload(record: WitchbaitCredentialRecord) -> dict[str, Any]:
        return {
            "credential_id": record.credential_id,
            "credential_type": record.credential_type,
            "credential_hash": record.credential_hash,
            "placement_vector": record.placement_vector,
            "target_decoy_id": record.target_decoy_id,
            "metadata": dict(record.metadata),
            "source": record.source,
            "created_at": record.created_at,
        }

    @staticmethod
    def _trip_payload(record: WitchbaitTripRecord) -> dict[str, Any]:
        return {
            "trip_id": record.trip_id,
            "credential_id": record.credential_id,
            "credential_type": record.credential_type,
            "credential_hash": record.credential_hash,
            "matched_field": record.matched_field,
            "session_id": record.session_id,
            "source_ip": record.source_ip,
            "service": record.service,
            "action": record.action,
            "placement_vector": record.placement_vector,
            "target_decoy_id": record.target_decoy_id,
            "created_at": record.created_at,
        }

    @staticmethod
    def _trip_sort_value(*, record: WitchbaitTripRecord, sort_by: str) -> tuple[int, str]:
        value = getattr(record, sort_by, None)
        if value is None:
            return (1, "")
        text = str(value)
        return (0 if text else 1, text)

    @staticmethod
    def _credential_sort_value(*, record: WitchbaitCredentialRecord, sort_by: str) -> tuple[int, str]:
        value = getattr(record, sort_by, None)
        if value is None:
            return (1, "")
        text = str(value)
        return (0 if text else 1, text)

    @staticmethod
    def _ranked_counts(rows: list[dict[str, Any]], *, key: str, label: str) -> list[dict[str, Any]]:
        counts: dict[str, int] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            value = str(row.get(key, "")).strip()
            if not value:
                continue
            counts[value] = counts.get(value, 0) + 1
        ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        return [{label: value, "count": count} for value, count in ranked]
