"""Runtime manager for optional PripyatSprings workflows."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

from clownpeanuts.agents.backend import load_backend
from clownpeanuts.config.schema import PripyatSpringsConfig

from .fingerprints import FingerprintRegistry
from .middleware import MiddlewareConfig, ToxicDataMiddleware
from .tracking import TrackingRegistry


class PripyatSpringsError(RuntimeError):
    """Base error for PripyatSprings runtime operations."""


class PripyatSpringsManager:
    """Manager for optional toxic-data tracking/fingerprint flows."""

    _BACKEND_METHODS = frozenset(
        {
            "close",
            "status",
            "resolve_toxicity_level",
            "register_fingerprint",
            "list_fingerprints",
            "list_fingerprints_filtered",
            "record_hit",
            "list_hits",
            "list_hits_filtered",
            "transform",
        }
    )

    def __init__(
        self,
        config: PripyatSpringsConfig,
        *,
        emit_hook: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._config = config
        self._emit_hook = emit_hook
        self._fingerprints = FingerprintRegistry(store_path=config.store_path)
        self._tracking = TrackingRegistry(store_path=config.store_path)
        self._middleware = ToxicDataMiddleware(
            MiddlewareConfig(
                enabled=config.enabled,
                default_toxicity=config.default_toxicity,
            )
        )
        self._backend_path = str(config.backend).strip()
        self._backend = load_backend(
            backend_path=self._backend_path,
            module_name="pripyatsprings",
            required_methods=self._BACKEND_METHODS,
            init_kwargs={
                "config": config,
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
        self._fingerprints.close()
        self._tracking.close()

    def status(self) -> dict[str, Any]:
        level3_acknowledged = bool(self._config.level3_acknowledgment.strip())
        return {
            "enabled": self._config.enabled,
            "backend_configured": bool(self._backend_path),
            "backend_mode": "builtin",
            "default_toxicity": self._config.default_toxicity,
            "tracking_domain": self._config.tracking_domain,
            "canary_dns_domain": self._config.canary_dns_domain,
            "tracking_server_port": self._config.tracking_server_port,
            "level3_acknowledgment": level3_acknowledged,
            "level3_enabled": level3_acknowledged,
            "fingerprints": len(self._fingerprints.list(limit=2000)),
            "hits": self._tracking.summary(),
        }

    def resolve_toxicity_level(self, *, emulator: str = "", toxicity_level: int | None = None) -> int:
        if toxicity_level is not None:
            level = int(toxicity_level)
        else:
            normalized_emulator = emulator.strip()
            override = self._config.per_emulator_overrides.get(normalized_emulator)
            if override is None:
                level = int(self._config.default_toxicity)
            else:
                level = int(override)
        safe_level = max(1, min(3, level))
        if safe_level >= 3 and not self._config.level3_acknowledgment.strip():
            raise PripyatSpringsError("toxicity level 3 requires level3_acknowledgment")
        return safe_level

    def register_fingerprint(self, payload: dict[str, Any]) -> dict[str, Any]:
        export_payload = str(payload.get("payload", "")).strip()
        session_id = str(payload.get("session_id", "")).strip()
        deployment_id = str(payload.get("deployment_id", "")).strip()
        if not export_payload:
            raise PripyatSpringsError("payload is required")
        if not session_id:
            raise PripyatSpringsError("session_id is required")
        if not deployment_id:
            raise PripyatSpringsError("deployment_id is required")
        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            raise PripyatSpringsError("metadata must be an object")
        record = self._fingerprints.register(
            payload=export_payload,
            session_id=session_id,
            deployment_id=deployment_id,
            metadata=metadata,
        )
        return {
            "fingerprint_id": record.fingerprint_id,
            "session_id": record.session_id,
            "deployment_id": record.deployment_id,
            "created_at": record.created_at,
            "metadata": dict(record.metadata),
        }

    def list_fingerprints(self, *, limit: int = 200) -> dict[str, Any]:
        return self.list_fingerprints_filtered(limit=limit)

    def list_fingerprints_filtered(
        self,
        *,
        limit: int = 200,
        session_id: str = "",
        deployment_id: str = "",
        query: str = "",
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        safe_limit = max(1, min(2000, int(limit)))
        normalized_session_id = session_id.strip().lower()
        normalized_deployment_id = deployment_id.strip().lower()
        normalized_query = query.strip().lower()
        normalized_sort_by = sort_by.strip().lower() if sort_by else "created_at"
        allowed_sort_by = {"created_at", "fingerprint_id", "session_id", "deployment_id"}
        if normalized_sort_by not in allowed_sort_by:
            raise PripyatSpringsError("sort_by must be one of: created_at, fingerprint_id, session_id, deployment_id")
        normalized_sort_order = sort_order.strip().lower() if sort_order else "desc"
        if normalized_sort_order not in {"asc", "desc"}:
            raise PripyatSpringsError("sort_order must be one of: asc, desc")

        rows = self._fingerprints.list(limit=2000)
        payload: list[dict[str, Any]] = []
        for row in rows:
            item = {
                "fingerprint_id": row.fingerprint_id,
                "session_id": row.session_id,
                "deployment_id": row.deployment_id,
                "created_at": row.created_at,
                "metadata": dict(row.metadata),
            }
            row_session_id = str(item.get("session_id", "")).strip().lower()
            row_deployment_id = str(item.get("deployment_id", "")).strip().lower()
            if normalized_session_id and row_session_id != normalized_session_id:
                continue
            if normalized_deployment_id and row_deployment_id != normalized_deployment_id:
                continue
            if normalized_query:
                searchable = " ".join(
                    [
                        str(item.get("fingerprint_id", "")).strip().lower(),
                        row_session_id,
                        row_deployment_id,
                        str(item.get("metadata", "")).lower(),
                    ]
                )
                if normalized_query not in searchable:
                    continue
            payload.append(item)

        reverse = normalized_sort_order == "desc"
        payload.sort(
            key=lambda item: self._fingerprint_sort_value(item=item, sort_by=normalized_sort_by),
            reverse=reverse,
        )
        limited = payload[:safe_limit]
        return {
            "count": len(limited),
            "total_filtered": len(payload),
            "fingerprints": limited,
            "filters": {
                "session_id": normalized_session_id or None,
                "deployment_id": normalized_deployment_id or None,
                "query": normalized_query or None,
            },
            "sort": {
                "by": normalized_sort_by,
                "order": normalized_sort_order,
            },
        }

    def record_hit(self, payload: dict[str, Any]) -> dict[str, Any]:
        fingerprint_id = str(payload.get("fingerprint_id", "")).strip()
        source_ip = str(payload.get("source_ip", "")).strip()
        if not fingerprint_id:
            raise PripyatSpringsError("fingerprint_id is required")
        fingerprint = self._fingerprints.get(fingerprint_id)
        if fingerprint is None:
            raise PripyatSpringsError("fingerprint_id is not registered")
        if not source_ip:
            raise PripyatSpringsError("source_ip is required")
        metadata = payload.get("metadata", {})
        headers = payload.get("headers", {})
        if not isinstance(metadata, dict):
            raise PripyatSpringsError("metadata must be an object")
        if not isinstance(headers, dict):
            raise PripyatSpringsError("headers must be an object")
        hit = self._tracking.register_hit(
            fingerprint_id=fingerprint_id,
            source_ip=source_ip,
            user_agent=str(payload.get("user_agent", "")).strip(),
            headers=headers,
            metadata=metadata,
        )
        if self._emit_hook is not None:
            try:
                self._emit_hook(
                    {
                        "hit_id": hit.hit_id,
                        "fingerprint_id": hit.fingerprint_id,
                        "session_id": fingerprint.session_id,
                        "deployment_id": fingerprint.deployment_id,
                        "source_ip": hit.source_ip,
                        "user_agent": hit.user_agent,
                        "metadata": dict(hit.metadata),
                        "headers": dict(hit.headers),
                        "created_at": hit.created_at,
                    }
                )
            except Exception:
                pass
        return {
            "hit_id": hit.hit_id,
            "fingerprint_id": hit.fingerprint_id,
            "session_id": fingerprint.session_id,
            "deployment_id": fingerprint.deployment_id,
            "source_ip": hit.source_ip,
            "created_at": hit.created_at,
        }

    def list_hits(self, *, limit: int = 200) -> dict[str, Any]:
        return self.list_hits_filtered(limit=limit)

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
            raise PripyatSpringsError("timestamp filters must be valid ISO-8601 values") from exc
        return parsed.isoformat(timespec="seconds")

    def list_hits_filtered(
        self,
        *,
        limit: int = 200,
        fingerprint_id: str = "",
        source_ip_prefix: str = "",
        session_id: str = "",
        deployment_id: str = "",
        query: str = "",
        created_after: str = "",
        created_before: str = "",
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        safe_limit = max(1, min(2000, int(limit)))
        normalized_fingerprint_id = fingerprint_id.strip().lower()
        normalized_source_ip_prefix = source_ip_prefix.strip().lower()
        normalized_session_id = session_id.strip().lower()
        normalized_deployment_id = deployment_id.strip().lower()
        normalized_query = query.strip().lower()
        after = self._normalize_timestamp(created_after) if created_after.strip() else ""
        before = self._normalize_timestamp(created_before) if created_before.strip() else ""
        if after and before and after > before:
            raise PripyatSpringsError("created_after must be less than or equal to created_before")
        normalized_sort_by = sort_by.strip().lower() if sort_by else "created_at"
        allowed_sort_by = {
            "created_at",
            "source_ip",
            "fingerprint_id",
            "session_id",
            "deployment_id",
            "hit_id",
        }
        if normalized_sort_by not in allowed_sort_by:
            raise PripyatSpringsError(
                "sort_by must be one of: created_at, source_ip, fingerprint_id, session_id, deployment_id, hit_id"
            )
        normalized_sort_order = sort_order.strip().lower() if sort_order else "desc"
        if normalized_sort_order not in {"asc", "desc"}:
            raise PripyatSpringsError("sort_order must be one of: asc, desc")

        hits = self._tracking.list_hits(limit=2000)
        rows = [self._hit_payload(hit) for hit in hits]
        filtered: list[dict[str, Any]] = []
        for row in rows:
            row_fingerprint_id = str(row.get("fingerprint_id", "")).strip().lower()
            row_source_ip = str(row.get("source_ip", "")).strip().lower()
            row_session_id = str(row.get("session_id", "")).strip().lower()
            row_deployment_id = str(row.get("deployment_id", "")).strip().lower()
            row_created_at = str(row.get("created_at", "")).strip()
            if normalized_fingerprint_id and row_fingerprint_id != normalized_fingerprint_id:
                continue
            if normalized_source_ip_prefix and not row_source_ip.startswith(normalized_source_ip_prefix):
                continue
            if normalized_session_id and row_session_id != normalized_session_id:
                continue
            if normalized_deployment_id and row_deployment_id != normalized_deployment_id:
                continue
            if after and row_created_at < after:
                continue
            if before and row_created_at > before:
                continue
            if normalized_query:
                searchable = " ".join(
                    [
                        str(row.get("hit_id", "")).strip().lower(),
                        row_fingerprint_id,
                        row_source_ip,
                        row_session_id,
                        row_deployment_id,
                        str(row.get("user_agent", "")).strip().lower(),
                        str(row.get("metadata", "")).lower(),
                        str(row.get("fingerprint_metadata", "")).lower(),
                    ]
                )
                if normalized_query not in searchable:
                    continue
            filtered.append(row)

        reverse = normalized_sort_order == "desc"
        filtered.sort(
            key=lambda item: self._hit_sort_value(item=item, sort_by=normalized_sort_by),
            reverse=reverse,
        )
        limited = filtered[:safe_limit]
        return {
            "count": len(limited),
            "total_filtered": len(filtered),
            "hits": limited,
            "summary": self._tracking.summary(),
            "filters": {
                "fingerprint_id": normalized_fingerprint_id or None,
                "source_ip_prefix": normalized_source_ip_prefix or None,
                "session_id": normalized_session_id or None,
                "deployment_id": normalized_deployment_id or None,
                "query": normalized_query or None,
                "created_after": after or None,
                "created_before": before or None,
            },
            "sort": {
                "by": normalized_sort_by,
                "order": normalized_sort_order,
            },
        }

    def hit_summary(
        self,
        *,
        limit: int = 500,
        fingerprint_id: str = "",
        source_ip_prefix: str = "",
        session_id: str = "",
        deployment_id: str = "",
        query: str = "",
        created_after: str = "",
        created_before: str = "",
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        if self._backend is not None and hasattr(self._backend, "hit_summary"):
            return self._backend.hit_summary(
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
        safe_limit = max(1, min(2000, int(limit)))
        listing = self.list_hits_filtered(
            limit=safe_limit,
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
        hits = listing.get("hits", [])
        if not isinstance(hits, list):
            hits = []
        created_values = [
            str(row.get("created_at", "")).strip()
            for row in hits
            if isinstance(row, dict) and str(row.get("created_at", "")).strip()
        ]
        total_filtered = int(listing.get("total_filtered", len(hits)))
        return {
            "count": len(hits),
            "total_filtered": total_filtered,
            "limit": safe_limit,
            "truncated": total_filtered > len(hits),
            "window": {
                "earliest_created_at": min(created_values) if created_values else None,
                "latest_created_at": max(created_values) if created_values else None,
            },
            "by_source_ip": self._ranked_counts(hits, key="source_ip", label="source_ip"),
            "by_fingerprint_id": self._ranked_counts(hits, key="fingerprint_id", label="fingerprint_id"),
            "by_session_id": self._ranked_counts(hits, key="session_id", label="session_id"),
            "by_deployment_id": self._ranked_counts(hits, key="deployment_id", label="deployment_id"),
            "filters": dict(listing.get("filters", {})),
            "sort": dict(listing.get("sort", {})),
            "tracking_summary": dict(listing.get("summary", {})),
        }

    def _hit_payload(self, hit: Any) -> dict[str, Any]:
        fingerprint = self._fingerprints.get(hit.fingerprint_id)
        session_id = ""
        deployment_id = ""
        fingerprint_metadata: dict[str, Any] = {}
        if fingerprint is not None:
            session_id = fingerprint.session_id
            deployment_id = fingerprint.deployment_id
            fingerprint_metadata = dict(fingerprint.metadata)
        return {
            "hit_id": hit.hit_id,
            "fingerprint_id": hit.fingerprint_id,
            "session_id": session_id,
            "deployment_id": deployment_id,
            "source_ip": hit.source_ip,
            "user_agent": hit.user_agent,
            "headers": dict(hit.headers),
            "metadata": dict(hit.metadata),
            "fingerprint_metadata": fingerprint_metadata,
            "created_at": hit.created_at,
        }

    @staticmethod
    def _hit_sort_value(*, item: dict[str, Any], sort_by: str) -> tuple[int, str]:
        value = str(item.get(sort_by, "") or "")
        return (0 if value else 1, value)

    @staticmethod
    def _fingerprint_sort_value(*, item: dict[str, Any], sort_by: str) -> tuple[int, str]:
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

    def transform(self, payload: dict[str, Any], *, toxicity_level: int | None = None) -> dict[str, Any]:
        emulator = str(payload.get("emulator", "")).strip()
        resolved_level = self.resolve_toxicity_level(emulator=emulator, toxicity_level=toxicity_level)
        return self._middleware.transform(payload, toxicity_level=resolved_level)
