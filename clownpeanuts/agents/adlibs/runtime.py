"""Runtime manager for optional ADLibs workflows."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

from clownpeanuts.agents.backend import load_backend
from clownpeanuts.config.schema import ADLibsConfig

from .bloodhound import fabricate_relationships
from .connector import ADConnector, ADConnectorConfig
from .monitor import ADEventMonitor
from .seeder import ADObjectSeeder


class ADLibsError(RuntimeError):
    """Base error for ADLibs runtime operations."""


class ADLibsNotFoundError(ADLibsError):
    """Requested ADLibs object does not exist."""


class ADLibsManager:
    """Manager for optional AD seeding and trip telemetry flows."""

    _BACKEND_METHODS = frozenset(
        {
            "close",
            "validate",
            "seed",
            "list_objects",
            "list_objects_filtered",
            "delete_object",
            "list_trips",
            "record_trip",
        }
    )

    def __init__(
        self,
        config: ADLibsConfig,
        *,
        register_credential: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        emit_hook: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._config = config
        self._register_credential = register_credential
        self._emit_hook = emit_hook
        self._connector = ADConnector(
            ADConnectorConfig(
                ldap_uri=config.ldap_uri,
                bind_dn=config.ldap_bind_dn,
                bind_password_env=config.ldap_bind_password_env,
                base_dn=config.base_dn,
                target_ou=config.target_ou,
            )
        )
        self._seeder = ADObjectSeeder(target_ou=config.target_ou, store_path=config.store_path)
        self._monitor = ADEventMonitor(store_path=config.store_path)
        self._backend_path = str(config.backend).strip()
        self._backend = load_backend(
            backend_path=self._backend_path,
            module_name="adlibs",
            required_methods=self._BACKEND_METHODS,
            init_kwargs={
                "config": config,
                "register_credential": register_credential,
                "emit_hook": emit_hook,
            },
        )

    def __getattribute__(self, name: str) -> Any:
        if name in object.__getattribute__(self, "_BACKEND_METHODS"):
            backend = object.__getattribute__(self, "_backend")
            if backend is not None:
                return getattr(backend, name)
        return object.__getattribute__(self, name)

    def close(self) -> None:
        self._seeder.close()
        self._monitor.close()

    def validate(self) -> dict[str, Any]:
        connector_issues = self._connector.validate()
        plan = self._seeder.validate_plan(
            fake_users=self._config.fake_users,
            fake_service_accounts=self._config.fake_service_accounts,
            fake_groups=self._config.fake_groups,
        )
        issues = list(connector_issues)
        issues.extend(str(item) for item in plan.get("issues", []) if str(item))
        return {
            "ready": not issues,
            "issues": issues,
            "backend_configured": bool(self._backend_path),
            "backend_mode": "builtin",
            "connector": self._connector.status(),
            "plan": plan,
        }

    def seed(self) -> dict[str, Any]:
        validation = self.validate()
        if not bool(validation.get("ready")):
            raise ADLibsError("adlibs configuration is incomplete")
        result = self._seeder.seed(
            fake_users=self._config.fake_users,
            fake_service_accounts=self._config.fake_service_accounts,
            fake_groups=self._config.fake_groups,
        )
        objects = result.get("objects", [])
        if isinstance(objects, list):
            result["relationships"] = fabricate_relationships(objects)
            result["witchbait"] = self._register_seed_credentials(objects)
        else:
            result["relationships"] = []
            result["witchbait"] = {"enabled": False, "registered": 0, "credentials": []}
        return result

    def list_objects(self, *, limit: int = 200) -> dict[str, Any]:
        return self.list_objects_filtered(limit=limit)

    def list_objects_filtered(
        self,
        *,
        limit: int = 200,
        object_type: str = "",
        object_id_prefix: str = "",
        name_prefix: str = "",
        query: str = "",
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        safe_limit = max(1, min(2000, int(limit)))
        normalized_object_type = object_type.strip().lower()
        normalized_object_id_prefix = object_id_prefix.strip().lower()
        normalized_name_prefix = name_prefix.strip().lower()
        normalized_query = query.strip().lower()
        normalized_sort_by = sort_by.strip().lower() if sort_by else "created_at"
        allowed_sort_by = {"created_at", "object_id", "object_type", "name"}
        if normalized_sort_by not in allowed_sort_by:
            raise ADLibsError("sort_by must be one of: created_at, object_id, object_type, name")
        normalized_sort_order = sort_order.strip().lower() if sort_order else "desc"
        if normalized_sort_order not in {"asc", "desc"}:
            raise ADLibsError("sort_order must be one of: asc, desc")

        objects = self._seeder.list_objects(limit=2000)
        filtered: list[dict[str, Any]] = []
        for row in objects:
            if not isinstance(row, dict):
                continue
            row_object_type = str(row.get("object_type", "")).strip().lower()
            row_object_id = str(row.get("object_id", "")).strip().lower()
            row_name = str(row.get("name", "")).strip().lower()
            if normalized_object_type and row_object_type != normalized_object_type:
                continue
            if normalized_object_id_prefix and not row_object_id.startswith(normalized_object_id_prefix):
                continue
            if normalized_name_prefix and not row_name.startswith(normalized_name_prefix):
                continue
            if normalized_query:
                row_dn = str(row.get("distinguished_name", "")).strip().lower()
                row_attributes = row.get("attributes")
                attributes_text = str(row_attributes).lower() if isinstance(row_attributes, dict) else ""
                searchable = " ".join(
                    [
                        row_object_type,
                        row_object_id,
                        row_name,
                        row_dn,
                        attributes_text,
                    ]
                )
                if normalized_query not in searchable:
                    continue
            filtered.append(dict(row))

        reverse = normalized_sort_order == "desc"
        filtered.sort(
            key=lambda item: self._object_sort_value(item=item, sort_by=normalized_sort_by),
            reverse=reverse,
        )
        limited = filtered[:safe_limit]
        return {
            "count": len(limited),
            "total_filtered": len(filtered),
            "objects": limited,
            "relationships": fabricate_relationships(limited),
            "filters": {
                "object_type": normalized_object_type or None,
                "object_id_prefix": normalized_object_id_prefix or None,
                "name_prefix": normalized_name_prefix or None,
                "query": normalized_query or None,
            },
            "sort": {
                "by": normalized_sort_by,
                "order": normalized_sort_order,
            },
        }

    def delete_object(self, object_id: str) -> dict[str, Any]:
        normalized_object_id = object_id.strip()
        if not normalized_object_id:
            raise ADLibsError("object_id cannot be empty")
        deleted = self._seeder.delete_object(normalized_object_id)
        if not deleted:
            raise ADLibsNotFoundError(f"adlibs object '{normalized_object_id}' was not found")
        return {
            "object_id": normalized_object_id,
            "status": "deleted",
        }

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
            raise ADLibsError("timestamp filters must be valid ISO-8601 values") from exc
        return parsed.isoformat(timespec="seconds")

    def list_trips(
        self,
        *,
        limit: int = 200,
        event_type: str = "",
        query: str = "",
        object_id_prefix: str = "",
        source_host_prefix: str = "",
        source_user_prefix: str = "",
        created_after: str = "",
        created_before: str = "",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        safe_limit = max(1, min(2000, int(limit)))
        normalized_event_type = event_type.strip().lower()
        normalized_query = query.strip().lower()
        normalized_object_prefix = object_id_prefix.strip().lower()
        normalized_host_prefix = source_host_prefix.strip().lower()
        normalized_user_prefix = source_user_prefix.strip().lower()
        after = self._normalize_timestamp(created_after) if created_after.strip() else ""
        before = self._normalize_timestamp(created_before) if created_before.strip() else ""
        if after and before and after > before:
            raise ADLibsError("created_after must be less than or equal to created_before")
        normalized_sort_order = sort_order.strip().lower() if sort_order else "desc"
        if normalized_sort_order not in {"asc", "desc"}:
            raise ADLibsError("sort_order must be one of: asc, desc")

        trips = self._monitor.list_trips(limit=2000)
        filtered: list[dict[str, Any]] = []
        for row in trips:
            if not isinstance(row, dict):
                continue
            row_event_type = str(row.get("event_type", "")).strip().lower()
            row_object_id = str(row.get("object_id", "")).strip().lower()
            row_source_host = str(row.get("source_host", "")).strip().lower()
            row_source_user = str(row.get("source_user", "")).strip().lower()
            row_created_at = str(row.get("created_at", "")).strip()
            if normalized_event_type and row_event_type != normalized_event_type:
                continue
            if normalized_object_prefix and not row_object_id.startswith(normalized_object_prefix):
                continue
            if normalized_host_prefix and not row_source_host.startswith(normalized_host_prefix):
                continue
            if normalized_user_prefix and not row_source_user.startswith(normalized_user_prefix):
                continue
            if after and row_created_at < after:
                continue
            if before and row_created_at > before:
                continue
            if normalized_query:
                metadata = row.get("metadata")
                metadata_text = str(metadata).lower() if isinstance(metadata, dict) else ""
                searchable = " ".join(
                    [
                        row_event_type,
                        row_object_id,
                        row_source_host,
                        row_source_user,
                        metadata_text,
                    ]
                )
                if normalized_query not in searchable:
                    continue
            filtered.append(dict(row))

        reverse = normalized_sort_order == "desc"
        filtered.sort(
            key=lambda item: (
                str(item.get("created_at", "")),
                str(item.get("trip_id", "")),
            ),
            reverse=reverse,
        )
        limited = filtered[:safe_limit]
        return {
            "count": len(limited),
            "total_filtered": len(filtered),
            "trips": limited,
            "filters": {
                "event_type": normalized_event_type or None,
                "query": normalized_query or None,
                "object_id_prefix": normalized_object_prefix or None,
                "source_host_prefix": normalized_host_prefix or None,
                "source_user_prefix": normalized_user_prefix or None,
                "created_after": after or None,
                "created_before": before or None,
            },
            "sort": {"order": normalized_sort_order},
        }

    def trip_summary(
        self,
        *,
        limit: int = 500,
        event_type: str = "",
        query: str = "",
        object_id_prefix: str = "",
        source_host_prefix: str = "",
        source_user_prefix: str = "",
        created_after: str = "",
        created_before: str = "",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        if self._backend is not None and hasattr(self._backend, "trip_summary"):
            return self._backend.trip_summary(
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
        safe_limit = max(1, min(2000, int(limit)))
        listing = self.list_trips(
            limit=safe_limit,
            event_type=event_type,
            query=query,
            object_id_prefix=object_id_prefix,
            source_host_prefix=source_host_prefix,
            source_user_prefix=source_user_prefix,
            created_after=created_after,
            created_before=created_before,
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
            "by_event_type": self._ranked_counts(trips, key="event_type", label="event_type"),
            "by_object_id": self._ranked_counts(trips, key="object_id", label="object_id"),
            "by_source_host": self._ranked_counts(trips, key="source_host", label="source_host"),
            "by_source_user": self._ranked_counts(trips, key="source_user", label="source_user"),
            "filters": dict(listing.get("filters", {})),
            "sort": dict(listing.get("sort", {})),
        }

    def event_catalog(self) -> dict[str, Any]:
        if self._backend is not None and hasattr(self._backend, "event_catalog"):
            return self._backend.event_catalog()
        events = self._monitor.event_catalog()
        return {
            "count": len(events),
            "events": events,
            "backend_configured": bool(self._backend_path),
            "backend_mode": "builtin",
        }

    def ingest_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._backend is not None and hasattr(self._backend, "ingest_event"):
            return self._backend.ingest_event(payload)
        if not isinstance(payload, dict):
            raise ADLibsError("ingest_event requires a payload object")
        event_id = self._extract_event_id(payload)
        event_type = self._monitor.classify_event_type(event_id)
        source_host = self._pick_text(
            payload,
            "source_host",
            "source_machine",
            "source_computer",
            "computer",
            "workstation",
            "host",
        )
        source_user = self._pick_text(
            payload,
            "source_user",
            "source_username",
            "source_account",
            "subject_user_name",
            "account_name",
            "username",
            "user",
        )
        object_row = self._match_seeded_object(payload)
        if object_row is None:
            return {
                "status": "ignored",
                "reason": "no_seeded_object_match",
                "event_id": event_id or None,
                "event_type": event_type,
                "source_host": source_host,
                "source_user": source_user,
            }
        object_id = str(object_row.get("object_id", "")).strip()
        metadata = self._build_event_metadata(payload=payload, event_id=event_id, event_type=event_type)
        trip = self.record_trip(
            {
                "object_id": object_id,
                "event_type": event_type,
                "source_host": source_host,
                "source_user": source_user,
                "metadata": metadata,
            }
        )
        return {
            "status": "recorded",
            "event_id": event_id or None,
            "event_type": event_type,
            "source_host": source_host,
            "source_user": source_user,
            "matched_object": {
                "object_id": object_id,
                "name": str(object_row.get("name", "")),
                "object_type": str(object_row.get("object_type", "")),
                "distinguished_name": str(object_row.get("distinguished_name", "")),
            },
            "trip": trip,
        }

    def ingest_events(self, payloads: list[dict[str, Any]], *, continue_on_error: bool = True) -> dict[str, Any]:
        if self._backend is not None and hasattr(self._backend, "ingest_events"):
            return self._backend.ingest_events(payloads, continue_on_error=continue_on_error)
        results: list[dict[str, Any]] = []
        errors: list[str] = []
        recorded = 0
        ignored = 0
        for index, payload in enumerate(payloads):
            if not isinstance(payload, dict):
                errors.append(f"index {index}: payload must be an object")
                if not continue_on_error:
                    break
                continue
            try:
                result = self.ingest_event(payload)
            except ADLibsError as exc:
                errors.append(f"index {index}: {exc}")
                if not continue_on_error:
                    break
                continue
            results.append(result)
            if str(result.get("status", "")).strip().lower() == "recorded":
                recorded += 1
            else:
                ignored += 1
        return {
            "requested": len(payloads),
            "processed": len(results),
            "recorded": recorded,
            "ignored": ignored,
            "errors": errors,
            "results": results,
            "continue_on_error": bool(continue_on_error),
        }

    def record_trip(self, payload: dict[str, Any]) -> dict[str, Any]:
        object_id = str(payload.get("object_id", "")).strip()
        event_type = str(payload.get("event_type", "")).strip()
        if not object_id or not event_type:
            raise ADLibsError("record_trip requires object_id and event_type")
        trip = self._monitor.record_trip(
            object_id=object_id,
            event_type=event_type,
            source_host=str(payload.get("source_host", "")).strip(),
            source_user=str(payload.get("source_user", "")).strip(),
            metadata=dict(payload.get("metadata", {}) or {}),
        )
        if self._emit_hook is not None:
            try:
                self._emit_hook(
                    {
                        "trip_id": trip.trip_id,
                        "object_id": trip.object_id,
                        "event_type": trip.event_type,
                        "source_host": trip.source_host,
                        "source_user": trip.source_user,
                        "metadata": dict(trip.metadata),
                        "created_at": trip.created_at,
                    }
                )
            except Exception:
                pass
        return {
            "trip_id": trip.trip_id,
            "object_id": trip.object_id,
            "event_type": trip.event_type,
            "created_at": trip.created_at,
        }

    def _match_seeded_object(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        objects = self._seeder.list_objects(limit=2000)
        if not objects:
            return None
        by_object_id: dict[str, dict[str, Any]] = {}
        for row in objects:
            if not isinstance(row, dict):
                continue
            object_id = str(row.get("object_id", "")).strip().lower()
            if object_id:
                by_object_id[object_id] = row

        direct_object_id = self._pick_text(payload, "object_id", "target_object_id", "seeded_object_id").lower()
        if direct_object_id:
            matched = by_object_id.get(direct_object_id)
            if matched is not None:
                return matched

        candidates: set[str] = set()
        for key in (
            "target_account",
            "target_user",
            "target_username",
            "target_object",
            "object_name",
            "service_name",
            "distinguished_name",
            "object_dn",
            "target_dn",
            "target_principal",
        ):
            value = self._pick_text(payload, key)
            candidates.update(self._identifier_variants(value))
        message = self._pick_text(payload, "message", "raw_message", "event_text").lower()

        for row in objects:
            if not isinstance(row, dict):
                continue
            object_id = str(row.get("object_id", "")).strip().lower()
            name = str(row.get("name", "")).strip().lower()
            distinguished_name = str(row.get("distinguished_name", "")).strip().lower()
            identifiers = {object_id, name, distinguished_name}
            identifiers.discard("")
            if identifiers and identifiers.intersection(candidates):
                return row
            if message and any(identifier and identifier in message for identifier in identifiers):
                return row
        return None

    def _build_event_metadata(self, *, payload: dict[str, Any], event_id: str, event_type: str) -> dict[str, Any]:
        metadata: dict[str, Any] = {}
        raw_metadata = payload.get("metadata", {})
        if isinstance(raw_metadata, dict):
            metadata.update({str(key): value for key, value in raw_metadata.items() if str(key).strip()})
        if event_id:
            metadata.setdefault("event_id", event_id)
        metadata.setdefault("event_type", event_type)
        for key in (
            "source_ip",
            "source_host",
            "source_machine",
            "source_user",
            "subject_user_name",
            "account_name",
            "target_account",
            "target_user",
            "service_name",
            "object_name",
            "distinguished_name",
            "object_dn",
            "event_source",
            "channel",
        ):
            value = self._pick_text(payload, key)
            if value:
                metadata.setdefault(key, value)
        return metadata

    def _extract_event_id(self, payload: dict[str, Any]) -> str:
        for key in ("event_id", "eventId", "id", "event_code"):
            if key not in payload:
                continue
            normalized = self._monitor.normalize_event_id(payload.get(key))
            if normalized:
                return normalized
        return ""

    @staticmethod
    def _pick_text(payload: dict[str, Any], *keys: str) -> str:
        for key in keys:
            if key not in payload:
                continue
            value = str(payload.get(key, "")).strip()
            if value:
                return value
        return ""

    @staticmethod
    def _identifier_variants(value: str) -> set[str]:
        normalized = value.strip().lower()
        if not normalized:
            return set()
        variants = {normalized}
        if "@" in normalized:
            variants.add(normalized.split("@", 1)[0])
        if "\\" in normalized:
            variants.add(normalized.rsplit("\\", 1)[-1])
        if "/" in normalized:
            variants.add(normalized.split("/", 1)[0])
            variants.add(normalized.rsplit("/", 1)[-1])
        return {item for item in variants if item}

    def _register_seed_credentials(self, objects: list[dict[str, Any]]) -> dict[str, Any]:
        if not self._config.witchbait_integration or self._register_credential is None:
            return {"enabled": False, "registered": 0, "credentials": []}

        registered: list[str] = []
        for row in objects:
            if not isinstance(row, dict):
                continue
            object_type = str(row.get("object_type", "")).strip().lower()
            if object_type not in {"user", "service_account"}:
                continue
            object_name = str(row.get("name", "")).strip().lower()
            if not object_name:
                continue
            credential_id = f"adlibs-{object_name}"
            credential_value = f"{object_name}-temp-credential"
            payload = {
                "credential_id": credential_id,
                "credential_value": credential_value,
                "credential_type": "password",
                "placement_vector": "directory_seed",
                "target_decoy_id": str(row.get("object_id", "")).strip(),
                "metadata": {
                    "module": "adlibs",
                    "object_type": object_type,
                    "name": object_name,
                },
            }
            try:
                self._register_credential(payload)
                registered.append(credential_id)
            except Exception:
                continue
        return {
            "enabled": True,
            "registered": len(registered),
            "credentials": registered,
        }

    @staticmethod
    def _object_sort_value(*, item: dict[str, Any], sort_by: str) -> tuple[int, str]:
        value = str(item.get(sort_by, "") or "")
        return (0 if value else 1, value)

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
