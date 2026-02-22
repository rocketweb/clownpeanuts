"""Session tracking with memory and Redis backends."""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import json
import threading
from typing import Any, Iterable
from urllib.parse import urlparse, urlunparse

from clownpeanuts.config.schema import SessionConfig
from clownpeanuts.core.logging import get_logger


@dataclass(slots=True)
class SessionEvent:
    timestamp: datetime
    service: str
    action: str
    payload: dict[str, Any]


@dataclass(slots=True)
class Session:
    session_id: str
    source_ip: str
    fingerprint: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    events: deque[SessionEvent] = field(default_factory=deque)
    event_count_total: int = 0
    tags: set[str] = field(default_factory=set)
    narrative: dict[str, Any] = field(default_factory=dict)


class SessionManager:
    _AUTH_ACTIONS = {"auth_attempt", "credential_capture"}
    _COMMAND_ACTIONS = {"command", "command_attempt"}
    _MAX_MEMORY_SESSIONS = 10_000
    _MAX_SESSION_TAGS = 128
    _MAX_TOUCHED_SERVICES = 64

    def __init__(self, config: SessionConfig | None = None) -> None:
        self.config = config or SessionConfig()
        self.logger = get_logger("clownpeanuts.session")
        self._lock = threading.RLock()
        self._sessions: OrderedDict[str, Session] = OrderedDict()
        self._created_sessions: OrderedDict[str, None] = OrderedDict()
        self._memory_total_events = 0
        self._memory_credential_events = 0
        self._memory_command_events = 0
        self._backend = "memory"
        self._redis_client: Any | None = None

        if self.config.backend == "redis":
            self._initialize_redis()

    @property
    def backend(self) -> str:
        return self._backend

    def get_or_create(self, session_id: str, source_ip: str, fingerprint: str | None = None) -> Session:
        if self._backend == "redis":
            return self._redis_or_fallback(
                redis_fn=lambda: self._get_or_create_redis(session_id, source_ip, fingerprint),
                fallback_fn=lambda: self._get_or_create_memory(session_id, source_ip, fingerprint),
            )
        return self._get_or_create_memory(session_id, source_ip, fingerprint)

    def record_event(self, session_id: str, service: str, action: str, payload: dict[str, Any]) -> SessionEvent:
        if self._backend == "redis":
            return self._redis_or_fallback(
                redis_fn=lambda: self._record_event_redis(session_id, service, action, payload),
                fallback_fn=lambda: self._record_event_memory(session_id, service, action, payload),
            )
        return self._record_event_memory(session_id, service, action, payload)

    def snapshot(self) -> dict[str, int | str]:
        if self._backend == "redis":
            return self._redis_or_fallback(
                redis_fn=self._snapshot_redis,
                fallback_fn=self._snapshot_memory,
            )
        return self._snapshot_memory()

    def session_event_count(self, session_id: str) -> int:
        if self._backend == "redis":
            return int(
                self._redis_or_fallback(
                    redis_fn=lambda: self._session_event_count_redis(session_id),
                    fallback_fn=lambda: self._session_event_count_memory(session_id),
                )
            )
        return self._session_event_count_memory(session_id)

    def add_session_tags(self, *, session_id: str, tags: Iterable[str], source_ip: str = "unknown") -> list[str]:
        normalized_session_id = session_id.strip()
        if not normalized_session_id:
            return []
        if self._backend == "redis":
            return list(
                self._redis_or_fallback(
                    redis_fn=lambda: self._add_session_tags_redis(
                        session_id=normalized_session_id,
                        tags=tags,
                        source_ip=source_ip,
                    ),
                    fallback_fn=lambda: self._add_session_tags_memory(
                        session_id=normalized_session_id,
                        tags=tags,
                        source_ip=source_ip,
                    ),
                )
            )
        return self._add_session_tags_memory(session_id=normalized_session_id, tags=tags, source_ip=source_ip)

    def session_tags(self, session_id: str) -> list[str]:
        normalized_session_id = session_id.strip()
        if not normalized_session_id:
            return []
        if self._backend == "redis":
            return list(
                self._redis_or_fallback(
                    redis_fn=lambda: self._session_tags_redis(normalized_session_id),
                    fallback_fn=lambda: self._session_tags_memory(normalized_session_id),
                )
            )
        return self._session_tags_memory(normalized_session_id)

    def export_sessions(self, *, limit: int = 100, events_per_session: int = 100) -> list[dict[str, Any]]:
        limit = max(1, int(limit))
        events_per_session = max(0, int(events_per_session))
        if self._backend == "redis":
            return list(
                self._redis_or_fallback(
                    redis_fn=lambda: self._export_sessions_redis(limit=limit, events_per_session=events_per_session),
                    fallback_fn=lambda: self._export_sessions_memory(limit=limit, events_per_session=events_per_session),
                )
            )
        return self._export_sessions_memory(limit=limit, events_per_session=events_per_session)

    def export_session(self, session_id: str, *, events_limit: int = 500) -> dict[str, Any] | None:
        events_limit = max(0, int(events_limit))
        if self._backend == "redis":
            return self._redis_or_fallback(
                redis_fn=lambda: self._export_session_redis(session_id=session_id, events_limit=events_limit),
                fallback_fn=lambda: self._export_session_memory(session_id=session_id, events_limit=events_limit),
            )
        return self._export_session_memory(session_id=session_id, events_limit=events_limit)

    def resolve_narrative_context(
        self,
        *,
        session_id: str,
        source_ip: str,
        tenant_id: str = "default",
        service: str = "",
        action: str = "",
        hints: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized_tenant = tenant_id.strip() or "default"
        normalized_service = service.strip().lower()
        normalized_action = action.strip().lower()
        if self._backend == "redis":
            return dict(
                self._redis_or_fallback(
                    redis_fn=lambda: self._resolve_narrative_context_redis(
                        session_id=session_id,
                        source_ip=source_ip,
                        tenant_id=normalized_tenant,
                        service=normalized_service,
                        action=normalized_action,
                        hints=hints,
                    ),
                    fallback_fn=lambda: self._resolve_narrative_context_memory(
                        session_id=session_id,
                        source_ip=source_ip,
                        tenant_id=normalized_tenant,
                        service=normalized_service,
                        action=normalized_action,
                        hints=hints,
                    ),
                )
            )
        return self._resolve_narrative_context_memory(
            session_id=session_id,
            source_ip=source_ip,
            tenant_id=normalized_tenant,
            service=normalized_service,
            action=normalized_action,
            hints=hints,
        )

    def _initialize_redis(self) -> None:
        try:
            import redis  # type: ignore[import-not-found]

            safe_redis_url = self._redact_redis_url(self.config.redis_url)
            client = redis.Redis.from_url(
                self.config.redis_url,
                socket_connect_timeout=self.config.connect_timeout_seconds,
                socket_timeout=self.config.connect_timeout_seconds,
                decode_responses=True,
            )
            client.ping()
            self._redis_client = client
            self._backend = "redis"
            if not self._redis_url_has_credentials(self.config.redis_url):
                self.logger.warning(
                    "redis session backend configured without AUTH credentials",
                    extra={
                        "service": "session",
                        "payload": {
                            "backend": "redis",
                            "redis_url": safe_redis_url,
                        },
                    },
                )
            self.logger.info(
                "session backend initialized",
                extra={
                    "service": "session",
                    "payload": {
                        "backend": self._backend,
                        "redis_url": safe_redis_url,
                    },
                },
            )
        except Exception as exc:
            if self.config.required:
                raise RuntimeError(f"failed to initialize required redis session backend: {exc}") from exc
            self._backend = "memory"
            self._redis_client = None
            self.logger.warning(
                "redis session backend unavailable, falling back to memory",
                extra={
                    "service": "session",
                    "payload": {
                        "backend": "memory",
                        "error": str(exc),
                    },
                },
            )

    def _redis_or_fallback(self, *, redis_fn: Any, fallback_fn: Any) -> Any:
        try:
            return redis_fn()
        except Exception as exc:
            self._degrade_to_memory(exc)
            return fallback_fn()

    def _degrade_to_memory(self, exc: Exception) -> None:
        if self._backend == "memory":
            return
        self._backend = "memory"
        self._redis_client = None
        self.logger.error(
            "redis session backend failed, switched to memory",
            extra={
                "service": "session",
                "payload": {
                    "error": str(exc),
                    "fallback": "memory",
                },
            },
        )

    @staticmethod
    def _normalize_tag_values(tags: Iterable[str]) -> list[str]:
        values: list[str] = []
        seen: set[str] = set()
        for raw in tags:
            normalized = str(raw).strip().lower()
            if not normalized or len(normalized) > 128:
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            values.append(normalized)
        values.sort()
        return values

    @staticmethod
    def _redis_url_has_credentials(redis_url: str) -> bool:
        parsed = urlparse(str(redis_url).strip())
        password = parsed.password or ""
        return bool(password.strip())

    @staticmethod
    def _redact_redis_url(redis_url: str) -> str:
        raw = str(redis_url).strip()
        parsed = urlparse(raw)
        if not parsed.password:
            return raw
        hostname = parsed.hostname or ""
        if not hostname:
            return raw
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        username = parsed.username or ""
        userinfo = f"{username}:***@" if username else ":***@"
        netloc = f"{userinfo}{hostname}"
        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"
        return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))

    def _get_or_create_memory(self, session_id: str, source_ip: str, fingerprint: str | None = None) -> Session:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                if len(self._sessions) >= self._MAX_MEMORY_SESSIONS:
                    evicted_session_id, _ = self._sessions.popitem(last=False)
                    self._created_sessions.pop(evicted_session_id, None)
                session = Session(
                    session_id=session_id,
                    source_ip=source_ip,
                    fingerprint=fingerprint,
                    events=deque(maxlen=self.config.max_events_per_session),
                )
                self._sessions[session_id] = session
                self._created_sessions[session_id] = None
            else:
                self._sessions.move_to_end(session_id)
                if fingerprint and not session.fingerprint:
                    session.fingerprint = fingerprint
            return session

    def _record_event_memory(
        self,
        session_id: str,
        service: str,
        action: str,
        payload: dict[str, Any],
    ) -> SessionEvent:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                source_ip = str(payload.get("source_ip", "unknown"))
                session = self._get_or_create_memory(session_id=session_id, source_ip=source_ip)
            else:
                self._sessions.move_to_end(session_id)
            normalized_payload = dict(payload)
            if "session_tags" not in normalized_payload and session.tags:
                normalized_payload["session_tags"] = sorted(session.tags)
            event = SessionEvent(
                timestamp=datetime.now(UTC),
                service=service,
                action=action,
                payload=normalized_payload,
            )
            session.events.append(event)
            session.event_count_total += 1
            self._memory_total_events += 1
            if action in self._AUTH_ACTIONS:
                self._memory_credential_events += 1
            if action in self._COMMAND_ACTIONS:
                self._memory_command_events += 1
            return event

    def _resolve_narrative_context_memory(
        self,
        *,
        session_id: str,
        source_ip: str,
        tenant_id: str,
        service: str,
        action: str,
        hints: dict[str, Any] | None,
    ) -> dict[str, Any]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                session = self._get_or_create_memory(session_id=session_id, source_ip=source_ip)
            narrative = self._default_narrative(
                session_id=session_id,
                source_ip=session.source_ip,
                tenant_id=tenant_id,
                existing=session.narrative,
            )
            if service:
                touched = narrative.get("touched_services", [])
                if not isinstance(touched, list):
                    touched = []
                if service not in touched:
                    touched.append(service)
                    if len(touched) > self._MAX_TOUCHED_SERVICES:
                        touched = touched[-self._MAX_TOUCHED_SERVICES :]
                narrative["touched_services"] = touched
                narrative["last_service"] = service
            if action:
                depth = int(narrative.get("discovery_depth", 0) or 0)
                narrative["discovery_depth"] = min(10_000, depth + 1)
                narrative["last_action"] = action
            hint_payload = self._sanitize_narrative_hints(hints)
            if hint_payload:
                narrative["last_hints"] = hint_payload
            narrative["updated_at"] = datetime.now(UTC).isoformat(timespec="microseconds")
            session.narrative = narrative
            return dict(narrative)

    def _snapshot_memory(self) -> dict[str, int | str]:
        with self._lock:
            return {
                "backend": self._backend,
                "sessions": len(self._sessions),
                "events": self._memory_total_events,
                "credential_events": self._memory_credential_events,
                "command_events": self._memory_command_events,
            }

    def _session_event_count_memory(self, session_id: str) -> int:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return 0
            return session.event_count_total

    def _add_session_tags_memory(self, *, session_id: str, tags: Iterable[str], source_ip: str) -> list[str]:
        normalized_tags = self._normalize_tag_values(tags)
        if not normalized_tags:
            return self._session_tags_memory(session_id)
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                session = self._get_or_create_memory(
                    session_id=session_id,
                    source_ip=source_ip.strip() or "unknown",
                )
            for value in normalized_tags:
                if value in session.tags:
                    continue
                if len(session.tags) >= self._MAX_SESSION_TAGS:
                    break
                session.tags.add(value)
            self._sessions.move_to_end(session_id)
            return sorted(session.tags)

    def _session_tags_memory(self, session_id: str) -> list[str]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return []
            return sorted(session.tags)

    def _export_sessions_memory(self, *, limit: int, events_per_session: int) -> list[dict[str, Any]]:
        with self._lock:
            payload: list[dict[str, Any]] = []
            for session_id in reversed(self._created_sessions):
                session = self._sessions.get(session_id)
                if session is None:
                    continue
                retained_events = list(session.events)
                events = retained_events[-events_per_session:] if events_per_session > 0 else []
                payload.append(
                    {
                        "session_id": session.session_id,
                        "source_ip": session.source_ip,
                        "fingerprint": session.fingerprint or "",
                        "created_at": session.created_at.isoformat(timespec="microseconds"),
                        "event_count": session.event_count_total,
                        "tags": sorted(session.tags),
                        "narrative": dict(session.narrative),
                        "events": [
                            {
                                "timestamp": event.timestamp.isoformat(timespec="microseconds"),
                                "service": event.service,
                                "action": event.action,
                                "payload": event.payload,
                            }
                            for event in events
                        ],
                    }
                )
                if len(payload) >= limit:
                    break
            return payload

    def _export_session_memory(self, *, session_id: str, events_limit: int) -> dict[str, Any] | None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            retained_events = list(session.events)
            events = retained_events[-events_limit:] if events_limit > 0 else []
            return {
                "session_id": session.session_id,
                "source_ip": session.source_ip,
                "fingerprint": session.fingerprint or "",
                "created_at": session.created_at.isoformat(timespec="microseconds"),
                "event_count": session.event_count_total,
                "tags": sorted(session.tags),
                "narrative": dict(session.narrative),
                "events": [
                    {
                        "timestamp": event.timestamp.isoformat(timespec="microseconds"),
                        "service": event.service,
                        "action": event.action,
                        "payload": event.payload,
                    }
                    for event in events
                ],
            }

    def _get_or_create_redis(self, session_id: str, source_ip: str, fingerprint: str | None = None) -> Session:
        assert self._redis_client is not None
        created_at = datetime.now(UTC)
        session_key = self._session_key(session_id)
        events_key = self._events_key(session_id)
        tags_key = self._session_tags_key(session_id)
        payload = {
            "source_ip": source_ip,
            "fingerprint": fingerprint or "",
        }
        pipe = self._redis_client.pipeline()
        pipe.hsetnx(session_key, "created_at", created_at.isoformat(timespec="microseconds"))
        pipe.hsetnx(session_key, "event_count_total", 0)
        pipe.hset(session_key, mapping=payload)
        pipe.sadd(self._session_index_key(), session_id)
        pipe.zadd(self._session_created_index_key(), {session_id: created_at.timestamp()}, nx=True)
        pipe.expire(session_key, self.config.ttl_seconds)
        pipe.expire(events_key, self.config.ttl_seconds)
        pipe.expire(tags_key, self.config.ttl_seconds)
        results = pipe.execute()
        if int(results[3] or 0) > 0:
            self._redis_client.incr(self._metric_key("sessions"))

        return Session(
            session_id=session_id,
            source_ip=source_ip,
            fingerprint=fingerprint,
            created_at=created_at,
            events=deque(maxlen=self.config.max_events_per_session),
        )

    def _record_event_redis(
        self,
        session_id: str,
        service: str,
        action: str,
        payload: dict[str, Any],
    ) -> SessionEvent:
        assert self._redis_client is not None
        source_ip = str(payload.get("source_ip", "unknown"))
        self._get_or_create_redis(session_id=session_id, source_ip=source_ip)
        normalized_payload = dict(payload)
        if "session_tags" not in normalized_payload:
            tags = self._session_tags_redis(session_id)
            if tags:
                normalized_payload["session_tags"] = tags

        event = SessionEvent(
            timestamp=datetime.now(UTC),
            service=service,
            action=action,
            payload=normalized_payload,
        )
        event_json = json.dumps(
            {
                "timestamp": event.timestamp.isoformat(timespec="microseconds"),
                "service": service,
                "action": action,
                "payload": normalized_payload,
            },
            separators=(",", ":"),
        )
        session_key = self._session_key(session_id)
        events_key = self._events_key(session_id)
        tags_key = self._session_tags_key(session_id)
        pipe = self._redis_client.pipeline()
        pipe.rpush(events_key, event_json)
        pipe.ltrim(events_key, -self.config.max_events_per_session, -1)
        pipe.expire(events_key, self.config.ttl_seconds)
        pipe.hincrby(session_key, "event_count_total", 1)
        pipe.expire(session_key, self.config.ttl_seconds)
        pipe.expire(tags_key, self.config.ttl_seconds)
        pipe.incr(self._metric_key("events"))
        if action in self._AUTH_ACTIONS:
            pipe.incr(self._metric_key("credential_events"))
        if action in self._COMMAND_ACTIONS:
            pipe.incr(self._metric_key("command_events"))
        pipe.execute()
        return event

    def _resolve_narrative_context_redis(
        self,
        *,
        session_id: str,
        source_ip: str,
        tenant_id: str,
        service: str,
        action: str,
        hints: dict[str, Any] | None,
    ) -> dict[str, Any]:
        assert self._redis_client is not None
        self._get_or_create_redis(session_id=session_id, source_ip=source_ip)
        session_key = self._session_key(session_id)
        existing_raw = self._redis_client.hget(session_key, "narrative_json")
        existing = self._parse_narrative_json(existing_raw)
        narrative = self._default_narrative(
            session_id=session_id,
            source_ip=source_ip,
            tenant_id=tenant_id,
            existing=existing,
        )
        if service:
            touched = narrative.get("touched_services", [])
            if not isinstance(touched, list):
                touched = []
            if service not in touched:
                touched.append(service)
                if len(touched) > self._MAX_TOUCHED_SERVICES:
                    touched = touched[-self._MAX_TOUCHED_SERVICES :]
            narrative["touched_services"] = touched
            narrative["last_service"] = service
        if action:
            depth = int(narrative.get("discovery_depth", 0) or 0)
            narrative["discovery_depth"] = min(10_000, depth + 1)
            narrative["last_action"] = action
        hint_payload = self._sanitize_narrative_hints(hints)
        if hint_payload:
            narrative["last_hints"] = hint_payload
        narrative["updated_at"] = datetime.now(UTC).isoformat(timespec="microseconds")
        self._redis_client.hset(
            session_key,
            mapping={"narrative_json": json.dumps(narrative, separators=(",", ":"), ensure_ascii=True)},
        )
        self._redis_client.expire(session_key, self.config.ttl_seconds)
        return dict(narrative)

    def _snapshot_redis(self) -> dict[str, int | str]:
        assert self._redis_client is not None
        sessions = int(self._redis_client.scard(self._session_index_key()) or 0)
        events = int(self._redis_client.get(self._metric_key("events")) or 0)
        credential_events = int(self._redis_client.get(self._metric_key("credential_events")) or 0)
        command_events = int(self._redis_client.get(self._metric_key("command_events")) or 0)
        return {
            "backend": self._backend,
            "sessions": sessions,
            "events": events,
            "credential_events": credential_events,
            "command_events": command_events,
        }

    def _session_event_count_redis(self, session_id: str) -> int:
        assert self._redis_client is not None
        session_key = self._session_key(session_id)
        count_raw = self._redis_client.hget(session_key, "event_count_total")
        if count_raw is not None:
            return self._parse_event_count(count_raw)
        return int(self._redis_client.llen(self._events_key(session_id)) or 0)

    def _add_session_tags_redis(self, *, session_id: str, tags: Iterable[str], source_ip: str) -> list[str]:
        assert self._redis_client is not None
        normalized_tags = self._normalize_tag_values(tags)
        if not normalized_tags:
            return self._session_tags_redis(session_id)
        self._get_or_create_redis(session_id=session_id, source_ip=source_ip.strip() or "unknown")
        existing_tags = self._session_tags_redis(session_id)
        existing_set = set(existing_tags)
        available_slots = max(0, self._MAX_SESSION_TAGS - len(existing_set))
        if available_slots <= 0:
            return existing_tags
        additions: list[str] = []
        for tag in normalized_tags:
            if tag in existing_set:
                continue
            additions.append(tag)
            existing_set.add(tag)
            if len(additions) >= available_slots:
                break
        if not additions:
            return existing_tags
        tags_key = self._session_tags_key(session_id)
        pipe = self._redis_client.pipeline()
        for tag in additions:
            pipe.sadd(tags_key, tag)
        pipe.expire(tags_key, self.config.ttl_seconds)
        pipe.expire(self._session_key(session_id), self.config.ttl_seconds)
        pipe.execute()
        return self._session_tags_redis(session_id)

    def _session_tags_redis(self, session_id: str) -> list[str]:
        assert self._redis_client is not None
        raw = self._redis_client.smembers(self._session_tags_key(session_id))
        if not isinstance(raw, (set, list, tuple)):
            return []
        values = [str(item).strip().lower() for item in raw]
        values = [item for item in values if item]
        values.sort()
        deduped: list[str] = []
        for item in values:
            if deduped and deduped[-1] == item:
                continue
            deduped.append(item)
            if len(deduped) >= self._MAX_SESSION_TAGS:
                break
        return deduped

    def _export_sessions_redis(self, *, limit: int, events_per_session: int) -> list[dict[str, Any]]:
        assert self._redis_client is not None
        session_ids, using_created_index = self._collect_export_session_ids_redis(limit=limit)
        if not session_ids:
            return []

        # Batch session metadata in one Redis round trip.
        metadata_pipe = self._redis_client.pipeline()
        for session_id in session_ids:
            metadata_pipe.hgetall(self._session_key(session_id))
        metadata_results = metadata_pipe.execute()

        stale_session_ids: list[str] = []
        selected_session_ids: list[str] = []
        session_meta: dict[str, dict[str, Any]] = {}
        event_counts: dict[str, int] = {}
        for index, session_id in enumerate(session_ids):
            raw = metadata_results[index] or {}
            if not raw:
                stale_session_ids.append(session_id)
                continue
            selected_session_ids.append(session_id)
            session_meta[session_id] = raw
            event_count = self._parse_event_count(raw.get("event_count_total"), fallback=0)
            event_counts[session_id] = event_count
            if using_created_index and len(selected_session_ids) >= limit:
                break

        if stale_session_ids:
            cleanup_pipe = self._redis_client.pipeline()
            for session_id in stale_session_ids:
                cleanup_pipe.srem(self._session_index_key(), session_id)
                cleanup_pipe.zrem(self._session_created_index_key(), session_id)
            cleanup_pipe.execute()

        if not selected_session_ids:
            return []

        tags_by_session: dict[str, list[str]] = {session_id: [] for session_id in selected_session_ids}
        tags_pipe = self._redis_client.pipeline()
        for session_id in selected_session_ids:
            tags_pipe.smembers(self._session_tags_key(session_id))
        tags_results = tags_pipe.execute()
        for session_id, raw_tags in zip(selected_session_ids, tags_results, strict=False):
            if isinstance(raw_tags, (set, list, tuple)):
                normalized = [str(item).strip().lower() for item in raw_tags]
                normalized = [item for item in normalized if item]
                normalized.sort()
                deduped: list[str] = []
                for item in normalized:
                    if deduped and deduped[-1] == item:
                        continue
                    deduped.append(item)
                tags_by_session[session_id] = deduped

        events_by_session: dict[str, list[str]] = {session_id: [] for session_id in selected_session_ids}
        if events_per_session > 0:
            events_pipe = self._redis_client.pipeline()
            for session_id in selected_session_ids:
                events_pipe.lrange(self._events_key(session_id), -events_per_session, -1)
            events_results = events_pipe.execute()
            for session_id, raw_events in zip(selected_session_ids, events_results, strict=False):
                items = raw_events if isinstance(raw_events, list) else []
                events_by_session[session_id] = [str(item) for item in items]

        payload: list[dict[str, Any]] = []
        for session_id in selected_session_ids:
            raw = session_meta.get(session_id, {})
            source_ip = str(raw.get("source_ip", "unknown"))
            created_at = str(raw.get("created_at", ""))
            fingerprint = str(raw.get("fingerprint", ""))
            narrative = self._parse_narrative_json(raw.get("narrative_json"))

            event_count = event_counts.get(session_id, 0)
            events_raw = events_by_session.get(session_id, [])

            events: list[dict[str, Any]] = []
            for raw_event in events_raw:
                try:
                    parsed = json.loads(raw_event)
                    if isinstance(parsed, dict):
                        events.append(
                            {
                                "timestamp": str(parsed.get("timestamp", "")),
                                "service": str(parsed.get("service", "")),
                                "action": str(parsed.get("action", "")),
                                "payload": parsed.get("payload", {}),
                            }
                        )
                except json.JSONDecodeError:
                    continue

            payload.append(
                {
                    "session_id": session_id,
                    "source_ip": source_ip,
                    "fingerprint": fingerprint,
                    "created_at": created_at,
                    "event_count": event_count,
                    "tags": tags_by_session.get(session_id, []),
                    "narrative": narrative,
                    "events": events,
                }
                )

        if not using_created_index:
            payload.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
        return payload[:limit]

    def _collect_export_session_ids_redis(self, *, limit: int) -> tuple[list[str], bool]:
        assert self._redis_client is not None
        fetch_window = max(limit * 4, 128)
        recent_session_ids = [
            str(item)
            for item in self._redis_client.zrevrange(
                self._session_created_index_key(),
                0,
                fetch_window - 1,
            )
        ]
        if recent_session_ids:
            return recent_session_ids, True

        # Backward-compatible path for existing installs that only have set-based indexes.
        return sorted(str(item) for item in self._redis_client.smembers(self._session_index_key())), False

    def _export_session_redis(self, *, session_id: str, events_limit: int) -> dict[str, Any] | None:
        assert self._redis_client is not None
        session_key = self._session_key(session_id)
        raw = self._redis_client.hgetall(session_key) or {}
        if not raw:
            return None
        source_ip = str(raw.get("source_ip", "unknown"))
        created_at = str(raw.get("created_at", ""))
        fingerprint = str(raw.get("fingerprint", ""))
        narrative = self._parse_narrative_json(raw.get("narrative_json"))
        tags = self._session_tags_redis(session_id)

        events_key = self._events_key(session_id)
        event_count = self._parse_event_count(raw.get("event_count_total"), fallback=0)
        events_raw: list[str] = []
        if events_limit > 0:
            events_raw = [str(item) for item in self._redis_client.lrange(events_key, -events_limit, -1)]

        events: list[dict[str, Any]] = []
        for raw_event in events_raw:
            try:
                parsed = json.loads(raw_event)
                if isinstance(parsed, dict):
                    events.append(
                        {
                            "timestamp": str(parsed.get("timestamp", "")),
                            "service": str(parsed.get("service", "")),
                            "action": str(parsed.get("action", "")),
                            "payload": parsed.get("payload", {}),
                        }
                    )
            except json.JSONDecodeError:
                continue

        return {
            "session_id": session_id,
            "source_ip": source_ip,
            "fingerprint": fingerprint,
            "created_at": created_at,
            "event_count": event_count,
            "tags": tags,
            "narrative": narrative,
            "events": events,
        }

    @staticmethod
    def _parse_event_count(raw: Any, *, fallback: int = 0) -> int:
        try:
            return max(0, int(raw or fallback))
        except (TypeError, ValueError):
            return fallback

    @staticmethod
    def _parse_narrative_json(raw: Any) -> dict[str, Any]:
        if raw is None:
            return {}
        try:
            parsed = json.loads(str(raw))
        except Exception:
            return {}
        if not isinstance(parsed, dict):
            return {}
        payload: dict[str, Any] = {}
        payload["context_id"] = str(parsed.get("context_id", "")).strip()
        payload["tenant_id"] = str(parsed.get("tenant_id", "default")).strip() or "default"
        payload["discovery_depth"] = max(0, int(parsed.get("discovery_depth", 0) or 0))
        payload["last_service"] = str(parsed.get("last_service", "")).strip().lower()
        payload["last_action"] = str(parsed.get("last_action", "")).strip().lower()
        touched_raw = parsed.get("touched_services", [])
        touched: list[str] = []
        if isinstance(touched_raw, list):
            for item in touched_raw:
                normalized = str(item).strip().lower()
                if normalized and normalized not in touched:
                    touched.append(normalized)
                if len(touched) >= SessionManager._MAX_TOUCHED_SERVICES:
                    break
        payload["touched_services"] = touched
        hints_raw = parsed.get("last_hints", {})
        if isinstance(hints_raw, dict):
            payload["last_hints"] = SessionManager._sanitize_narrative_hints(hints_raw)
        else:
            payload["last_hints"] = {}
        payload["updated_at"] = str(parsed.get("updated_at", "")).strip()
        return payload

    @staticmethod
    def _sanitize_narrative_hints(hints: dict[str, Any] | None) -> dict[str, str]:
        if not hints:
            return {}
        payload: dict[str, str] = {}
        for key, value in hints.items():
            normalized_key = str(key).strip()
            if not normalized_key:
                continue
            payload[normalized_key] = str(value).strip()[:140]
            if len(payload) >= 10:
                break
        return payload

    @staticmethod
    def _default_narrative(
        *,
        session_id: str,
        source_ip: str,
        tenant_id: str,
        existing: dict[str, Any] | None,
    ) -> dict[str, Any]:
        seed = hashlib.sha1(
            f"{session_id}:{source_ip}:{tenant_id}".encode("utf-8"),
            usedforsecurity=False,
        ).hexdigest()[:16]
        payload = {
            "context_id": f"ctx-{seed}",
            "tenant_id": tenant_id.strip() or "default",
            "discovery_depth": 0,
            "last_service": "",
            "last_action": "",
            "touched_services": [],
            "last_hints": {},
            "updated_at": "",
        }
        if not isinstance(existing, dict):
            return payload
        merged = dict(payload)
        parsed = SessionManager._parse_narrative_json(json.dumps(existing, separators=(",", ":"), ensure_ascii=True))
        for key, value in parsed.items():
            if key in {"context_id", "tenant_id"} and not value:
                continue
            merged[key] = value
        return merged

    def _session_key(self, session_id: str) -> str:
        return f"{self.config.key_prefix}:session:{session_id}"

    def _events_key(self, session_id: str) -> str:
        return f"{self.config.key_prefix}:session:{session_id}:events"

    def _session_tags_key(self, session_id: str) -> str:
        return f"{self.config.key_prefix}:session:{session_id}:tags"

    def _session_index_key(self) -> str:
        return f"{self.config.key_prefix}:sessions:index"

    def _session_created_index_key(self) -> str:
        return f"{self.config.key_prefix}:sessions:created:index"

    def _metric_key(self, name: str) -> str:
        return f"{self.config.key_prefix}:metrics:{name}"
