"""Runtime manager for optional DirtyLaundry workflows."""

from __future__ import annotations

from typing import Any, Callable

from clownpeanuts.agents.backend import load_backend
from clownpeanuts.config.schema import DirtyLaundryConfig

from .adaptive import policy_for_skill
from .classifier import classify_skill_level
from .matching import MatchingEngine
from .profiles import ProfileStore
from .sharing import (
    export_profiles,
    export_profiles_stix,
    import_profiles,
    pull_share_payload,
    push_share_payload,
)


class DirtyLaundryError(RuntimeError):
    """Base error for DirtyLaundry runtime operations."""


class DirtyLaundryNotFoundError(DirtyLaundryError):
    """Requested DirtyLaundry entity does not exist."""


class DirtyLaundryManager:
    """In-memory profile manager for optional cross-session attribution flows."""

    _BACKEND_METHODS = frozenset(
        {
            "close",
            "ingest_session",
            "list_profiles",
            "profile_detail",
            "profile_sessions",
            "add_note",
            "stats",
            "share_export",
            "share_import",
            "share_push",
            "share_pull",
        }
    )

    _METRIC_KEYS = {
        "typing_cadence",
        "command_vocabulary",
        "tool_signatures",
        "temporal_pattern",
        "credential_reuse",
    }

    def __init__(
        self,
        config: DirtyLaundryConfig,
        *,
        emit_hook: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._config = config
        self._emit_hook = emit_hook
        self._store = ProfileStore(
            db_path=config.profile_store_path or None,
            max_profiles=config.max_profiles,
            max_sessions_per_profile=config.max_sessions_per_profile,
            max_notes_per_profile=config.max_notes_per_profile,
        )
        self._matcher = MatchingEngine(threshold=config.match_threshold)
        self._backend_path = str(config.backend).strip()
        self._backend = load_backend(
            backend_path=self._backend_path,
            module_name="dirtylaundry",
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
        self._store.close()

    def ingest_session(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._backend is not None and hasattr(self._backend, "ingest_session"):
            return self._backend.ingest_session(payload)
        session_id = str(payload.get("session_id", "")).strip()
        if not session_id:
            raise DirtyLaundryError("session_id is required")
        metrics = self._metrics_from_payload(payload)
        existing = {profile.profile_id: profile.metrics for profile in self._store.list_profiles(limit=5000)}
        match = self._matcher.match(current=metrics, profiles=existing)
        if match is not None:
            profile = self._store.add_session(profile_id=match.profile_id, session_id=session_id)
            if profile is None:  # pragma: no cover - defensive
                raise DirtyLaundryNotFoundError(f"profile '{match.profile_id}' was not found")
            auto_theater_recommended = self._maybe_emit_auto_theater(profile)
            return {
                "status": "matched",
                "match_score": match.score,
                "match_breakdown": dict(match.breakdown),
                "profile": self._store.as_payload(profile),
                "policy": policy_for_skill(profile.skill),
                "auto_theater_recommended": auto_theater_recommended,
            }

        skill = classify_skill_level(metrics)
        profile = self._store.create_profile(skill=skill, session_id=session_id, metrics=metrics)
        auto_theater_recommended = self._maybe_emit_auto_theater(profile)
        return {
            "status": "created",
            "match_score": None,
            "match_breakdown": {},
            "profile": self._store.as_payload(profile),
            "policy": policy_for_skill(profile.skill),
            "auto_theater_recommended": auto_theater_recommended,
        }

    def preview_matches(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._backend is not None and hasattr(self._backend, "preview_matches"):
            return self._backend.preview_matches(payload)
        if not isinstance(payload, dict):
            raise DirtyLaundryError("session payload must be an object")

        metrics = self._metrics_from_payload(payload)
        try:
            limit = int(payload.get("limit", 5))
        except (TypeError, ValueError) as exc:
            raise DirtyLaundryError("limit must be an integer") from exc
        safe_limit = max(1, min(100, limit))
        include_breakdown = self._parse_bool(payload.get("include_breakdown"), default=True)
        try:
            min_score = float(payload.get("min_score", 0.0))
        except (TypeError, ValueError) as exc:
            raise DirtyLaundryError("min_score must be a number") from exc
        safe_min_score = max(0.0, min(1.0, min_score))

        profiles = self._store.list_profiles(limit=5000)
        profile_metrics = {profile.profile_id: profile.metrics for profile in profiles}
        ranked = self._matcher.ranked_matches(
            current=metrics,
            profiles=profile_metrics,
            limit=max(1, len(profile_metrics)),
            include_breakdown=include_breakdown,
        )
        best = ranked[0] if ranked else None

        profiles_by_id = {profile.profile_id: profile for profile in profiles}
        matches: list[dict[str, Any]] = []
        for row in ranked:
            if row.score < safe_min_score:
                continue
            profile = profiles_by_id.get(row.profile_id)
            if profile is None:
                continue
            item: dict[str, Any] = {
                "profile_id": row.profile_id,
                "score": round(float(row.score), 6),
                "skill": str(profile.skill),
                "session_count": len(profile.sessions),
                "last_seen_at": str(profile.last_seen_at),
            }
            if include_breakdown:
                item["breakdown"] = dict(row.breakdown)
            matches.append(item)
            if len(matches) >= safe_limit:
                break

        threshold = float(self._config.match_threshold)
        return {
            "count": len(matches),
            "matches": matches,
            "candidate_profile_id": best.profile_id if best is not None else None,
            "candidate_score": round(float(best.score), 6) if best is not None else None,
            "would_match": bool(best is not None and best.score >= threshold),
            "threshold": threshold,
            "total_profiles_considered": len(profile_metrics),
            "effective_limit": safe_limit,
            "include_breakdown": include_breakdown,
            "min_score": safe_min_score,
            "metrics": metrics,
            "backend_configured": bool(self._backend_path),
            "backend_mode": "builtin",
        }

    def evaluate_policy(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._backend is not None and hasattr(self._backend, "evaluate_policy"):
            return self._backend.evaluate_policy(payload)
        metrics = self._metrics_from_payload(payload)
        skill = classify_skill_level(metrics)
        return {
            "skill": skill,
            "metrics": metrics,
            "policy": policy_for_skill(skill),
            "backend_configured": bool(self._backend_path),
            "backend_mode": "builtin",
        }

    def reclassify_session(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._backend is not None and hasattr(self._backend, "reclassify_session"):
            return self._backend.reclassify_session(payload)
        session_id = str(payload.get("session_id", "")).strip()
        if not session_id:
            raise DirtyLaundryError("session_id is required")
        metrics = self._metrics_from_payload(payload)
        requested_profile_id = str(payload.get("profile_id", "")).strip()
        profile = self._resolve_profile_for_session(
            session_id=session_id,
            requested_profile_id=requested_profile_id,
        )
        if profile is None:
            if requested_profile_id:
                raise DirtyLaundryNotFoundError(f"profile '{requested_profile_id}' was not found")
            raise DirtyLaundryNotFoundError(
                f"session '{session_id}' is not associated with any known profile"
            )
        previous_skill = str(profile.skill)
        next_skill = classify_skill_level(metrics)
        updated = self._store.upsert_profile(
            profile_id=profile.profile_id,
            skill=next_skill,
            metrics=metrics,
            created_at=profile.created_at,
            last_seen_at=profile.last_seen_at,
        )
        updated = self._store.add_session(profile_id=updated.profile_id, session_id=session_id) or updated
        skill_changed = previous_skill != next_skill
        if skill_changed:
            self._store.add_note(
                profile_id=updated.profile_id,
                note=f"reclassified:{previous_skill}->{next_skill}",
            )
            refreshed = self._store.get_profile(updated.profile_id)
            if refreshed is not None:
                updated = refreshed
        auto_theater_recommended = self._maybe_emit_auto_theater(updated)
        return {
            "status": "reclassified",
            "session_id": session_id,
            "profile_id": updated.profile_id,
            "previous_skill": previous_skill,
            "current_skill": updated.skill,
            "skill_changed": skill_changed,
            "metrics": metrics,
            "policy": policy_for_skill(updated.skill),
            "profile": self._store.as_payload(updated),
            "auto_theater_recommended": auto_theater_recommended,
            "backend_configured": bool(self._backend_path),
            "backend_mode": "builtin",
        }

    def list_profiles(
        self,
        *,
        limit: int = 200,
        skill: str = "",
        min_sessions: int = 0,
        query: str = "",
        sort_by: str = "last_seen_at",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        safe_limit = max(1, min(2000, int(limit)))
        profiles = self._store.list_profiles(limit=10000)
        skill_filter = skill.strip().lower()
        query_filter = query.strip().lower()
        minimum_sessions = max(0, int(min_sessions))

        filtered = []
        for profile in profiles:
            if skill_filter and profile.skill.strip().lower() != skill_filter:
                continue
            session_count = len(profile.sessions)
            if session_count < minimum_sessions:
                continue
            if query_filter:
                searchable = " ".join(
                    [
                        profile.profile_id.strip().lower(),
                        profile.skill.strip().lower(),
                        " ".join(item.strip().lower() for item in profile.sessions),
                    ]
                )
                if query_filter not in searchable:
                    continue
            filtered.append(profile)

        allowed_sort_fields = {"last_seen_at", "created_at", "session_count", "skill", "profile_id"}
        normalized_sort_by = sort_by.strip().lower() if sort_by else "last_seen_at"
        if normalized_sort_by not in allowed_sort_fields:
            raise DirtyLaundryError(
                "sort_by must be one of: last_seen_at, created_at, session_count, skill, profile_id"
            )
        normalized_sort_order = sort_order.strip().lower() if sort_order else "desc"
        if normalized_sort_order not in {"asc", "desc"}:
            raise DirtyLaundryError("sort_order must be one of: asc, desc")
        reverse = normalized_sort_order == "desc"

        if normalized_sort_by == "session_count":
            filtered.sort(key=lambda item: (len(item.sessions), item.last_seen_at, item.profile_id), reverse=reverse)
        elif normalized_sort_by == "created_at":
            filtered.sort(key=lambda item: (item.created_at, item.profile_id), reverse=reverse)
        elif normalized_sort_by == "skill":
            filtered.sort(
                key=lambda item: (item.skill.lower(), item.last_seen_at, item.profile_id),
                reverse=reverse,
            )
        elif normalized_sort_by == "profile_id":
            filtered.sort(key=lambda item: item.profile_id, reverse=reverse)
        else:
            filtered.sort(key=lambda item: (item.last_seen_at, item.profile_id), reverse=reverse)

        limited = filtered[:safe_limit]
        return {
            "count": len(limited),
            "total_filtered": len(filtered),
            "profiles": [self._store.as_payload(profile) for profile in limited],
            "filters": {
                "skill": skill_filter or None,
                "min_sessions": minimum_sessions,
                "query": query_filter or None,
            },
            "sort": {
                "by": normalized_sort_by,
                "order": normalized_sort_order,
            },
        }

    def profile_detail(self, profile_id: str) -> dict[str, Any]:
        profile = self._store.get_profile(profile_id)
        if profile is None:
            raise DirtyLaundryNotFoundError(f"profile '{profile_id.strip()}' was not found")
        return self._store.as_payload(profile)

    def profile_sessions(
        self,
        profile_id: str,
        *,
        limit: int = 200,
        session_prefix: str = "",
        query: str = "",
        sort_by: str = "observed_order",
        sort_order: str = "asc",
    ) -> dict[str, Any]:
        profile = self._store.get_profile(profile_id)
        if profile is None:
            raise DirtyLaundryNotFoundError(f"profile '{profile_id.strip()}' was not found")
        safe_limit = max(1, min(2000, int(limit)))
        normalized_prefix = session_prefix.strip().lower()
        normalized_query = query.strip().lower()
        normalized_sort_by = sort_by.strip().lower() if sort_by else "observed_order"
        if normalized_sort_by not in {"observed_order", "session_id"}:
            raise DirtyLaundryError("sort_by must be one of: observed_order, session_id")
        normalized_sort_order = sort_order.strip().lower() if sort_order else "asc"
        if normalized_sort_order not in {"asc", "desc"}:
            raise DirtyLaundryError("sort_order must be one of: asc, desc")
        rows: list[dict[str, Any]] = []
        for index, session_id in enumerate(profile.sessions, start=1):
            normalized_session = session_id.strip().lower()
            if normalized_prefix and not normalized_session.startswith(normalized_prefix):
                continue
            if normalized_query and normalized_query not in normalized_session:
                continue
            rows.append({"session_id": session_id, "observed_order": index})

        reverse = normalized_sort_order == "desc"
        if normalized_sort_by == "session_id":
            rows.sort(key=lambda item: str(item.get("session_id", "")).lower(), reverse=reverse)
        else:
            rows.sort(key=lambda item: int(item.get("observed_order", 0)), reverse=reverse)
        limited_rows = rows[:safe_limit]
        return {
            "profile_id": profile.profile_id,
            "count": len(limited_rows),
            "total_filtered": len(rows),
            "sessions": [str(item.get("session_id", "")) for item in limited_rows],
            "filters": {
                "session_prefix": normalized_prefix or None,
                "query": normalized_query or None,
            },
            "sort": {
                "by": normalized_sort_by,
                "order": normalized_sort_order,
            },
        }

    def add_note(self, *, profile_id: str, note: str) -> dict[str, Any]:
        if not note.strip():
            raise DirtyLaundryError("note cannot be empty")
        profile = self._store.add_note(profile_id=profile_id, note=note)
        if profile is None:
            raise DirtyLaundryNotFoundError(f"profile '{profile_id.strip()}' was not found")
        return self._store.as_payload(profile)

    def stats(self) -> dict[str, Any]:
        profiles = self._store.list_profiles(limit=10000)
        distribution: dict[str, int] = {}
        total_sessions = 0
        return_profiles = 0
        for profile in profiles:
            distribution[profile.skill] = distribution.get(profile.skill, 0) + 1
            session_count = len(profile.sessions)
            total_sessions += session_count
            if session_count > 1:
                return_profiles += 1
        profile_count = len(profiles)
        average_sessions_per_profile = (float(total_sessions) / float(profile_count)) if profile_count > 0 else 0.0
        return_rate = (float(return_profiles) / float(profile_count)) if profile_count > 0 else 0.0
        return {
            "profile_count": profile_count,
            "total_sessions": total_sessions,
            "average_sessions_per_profile": round(average_sessions_per_profile, 6),
            "return_rate": round(return_rate, 6),
            "backend_configured": bool(self._backend_path),
            "backend_mode": "builtin",
            "skill_distribution": distribution,
            "matching_threshold": self._config.match_threshold,
            "matching_window_seconds": self._config.matching_window_seconds,
            "sharing_enabled": self._config.sharing.enabled,
            "sharing_endpoint": self._config.sharing.endpoint,
            "sharing_request_timeout_seconds": float(self._config.sharing.request_timeout_seconds),
            "sharing_headers_count": len(self._config.sharing.headers),
            "profile_store_path": self._store.db_path,
            "max_profiles": self._store.max_profiles,
            "max_sessions_per_profile": self._store.max_sessions_per_profile,
            "max_notes_per_profile": self._store.max_notes_per_profile,
        }

    def share_export(self, *, format_name: str = "native") -> dict[str, Any]:
        normalized = format_name.strip().lower() or "native"
        profiles = self._store.list_profiles(limit=10000)
        if normalized in {"native", "default"}:
            return export_profiles(profiles)
        if normalized in {"stix", "stix2", "stix2.1"}:
            return export_profiles_stix(profiles)
        raise DirtyLaundryError("share export format must be one of: native, stix")

    def share_import(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise DirtyLaundryError("share import payload must be an object")
        return import_profiles(payload, store=self._store)

    def share_push(self, *, format_name: str = "native", endpoint: str = "") -> dict[str, Any]:
        if not self._config.sharing.enabled:
            raise DirtyLaundryError("sharing is disabled")
        target_endpoint = endpoint.strip() or self._config.sharing.endpoint.strip()
        if not target_endpoint:
            raise DirtyLaundryError("sharing endpoint is required")
        payload = self.share_export(format_name=format_name)
        timeout_seconds = max(0.5, float(self._config.sharing.request_timeout_seconds))
        headers = {
            str(key).strip(): str(value).strip()
            for key, value in self._config.sharing.headers.items()
            if str(key).strip()
        }
        try:
            remote = push_share_payload(
                endpoint=target_endpoint,
                payload=payload,
                headers=headers,
                timeout_seconds=timeout_seconds,
            )
        except RuntimeError as exc:
            raise DirtyLaundryError(str(exc)) from exc
        return {
            "status": "pushed",
            "endpoint": target_endpoint,
            "exported_count": int(payload.get("count", 0)),
            "remote": remote,
        }

    def share_pull(self, *, endpoint: str = "") -> dict[str, Any]:
        if not self._config.sharing.enabled:
            raise DirtyLaundryError("sharing is disabled")
        target_endpoint = endpoint.strip() or self._config.sharing.endpoint.strip()
        if not target_endpoint:
            raise DirtyLaundryError("sharing endpoint is required")
        timeout_seconds = max(0.5, float(self._config.sharing.request_timeout_seconds))
        headers = {
            str(key).strip(): str(value).strip()
            for key, value in self._config.sharing.headers.items()
            if str(key).strip()
        }
        try:
            payload = pull_share_payload(
                endpoint=target_endpoint,
                headers=headers,
                timeout_seconds=timeout_seconds,
            )
        except RuntimeError as exc:
            raise DirtyLaundryError(str(exc)) from exc
        result = self.share_import(payload)
        return {
            "status": "pulled",
            "endpoint": target_endpoint,
            "import": result,
        }

    def _maybe_emit_auto_theater(self, profile: Any) -> bool:
        if profile is None:
            return False
        if not self._config.auto_theater_on_apt:
            return False
        if str(getattr(profile, "skill", "")).strip().lower() != "apt":
            return False
        if self._emit_hook is not None:
            try:
                self._emit_hook(
                    {
                        "profile_id": str(getattr(profile, "profile_id", "")),
                        "skill": "apt",
                        "session_count": len(getattr(profile, "sessions", []) or []),
                    }
                )
            except Exception:
                pass
        return True

    def _metrics_from_payload(self, payload: dict[str, Any]) -> dict[str, float]:
        metrics_raw = payload.get("metrics", {})
        if not isinstance(metrics_raw, dict):
            raise DirtyLaundryError("metrics must be an object")
        metrics: dict[str, float] = {}
        for key in self._METRIC_KEYS:
            raw_value = metrics_raw.get(key, 0.0)
            try:
                parsed = float(raw_value)
            except (TypeError, ValueError):
                parsed = 0.0
            metrics[key] = max(0.0, min(1.0, parsed))
        return metrics

    @staticmethod
    def _parse_bool(value: Any, *, default: bool) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        normalized = str(value).strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off"}:
            return False
        return default

    def _resolve_profile_for_session(
        self,
        *,
        session_id: str,
        requested_profile_id: str = "",
    ) -> Any:
        normalized_profile_id = requested_profile_id.strip()
        if normalized_profile_id:
            return self._store.get_profile(normalized_profile_id)
        normalized_session_id = session_id.strip()
        if not normalized_session_id:
            return None
        profiles = self._store.list_profiles(limit=5000)
        for profile in profiles:
            if normalized_session_id in profile.sessions:
                return profile
        return None
