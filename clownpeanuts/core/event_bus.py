"""Event bus with memory and Redis-backed pub/sub support."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import threading
import time
import uuid
from typing import Any, Callable
from urllib.parse import urlparse, urlunparse

from clownpeanuts.config.schema import EventBusConfig
from clownpeanuts.core.logging import get_logger


EventHandler = Callable[[dict[str, Any]], None]


@dataclass(slots=True)
class EventBusStats:
    backend: str
    published: int = 0
    delivered: int = 0
    subscriptions: int = 0


class EventBus:
    def __init__(self, config: EventBusConfig | None = None) -> None:
        self.config = config or EventBusConfig()
        self.logger = get_logger("clownpeanuts.event_bus")
        self._lock = threading.RLock()
        self._subscriptions: dict[str, list[EventHandler]] = defaultdict(list)
        self._recent_events: deque[dict[str, Any]] = deque(maxlen=200)
        self._next_event_id = 1
        self._stats = EventBusStats(backend="memory")
        self._redis_client: Any | None = None
        self._pubsub: Any | None = None
        self._listener_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

        if self.config.backend == "redis":
            self._initialize_redis()

    @property
    def backend(self) -> str:
        return self._stats.backend

    def subscribe(self, topic: str, handler: EventHandler) -> None:
        with self._lock:
            self._subscriptions[topic].append(handler)
            self._stats.subscriptions = sum(len(v) for v in self._subscriptions.values())
            if self._stats.backend == "redis":
                self._ensure_listener()

    def publish(self, topic: str, payload: dict[str, Any]) -> None:
        envelope = {
            "timestamp": datetime.now(UTC).isoformat(timespec="microseconds"),
            "topic": topic,
            "payload": payload,
            "event_uid": uuid.uuid4().hex,
        }
        with self._lock:
            if self._stats.backend != "redis" or not self._listener_active_locked():
                envelope = self._append_recent_event_locked(envelope)
            self._stats.published += 1

        if self._stats.backend == "redis":
            try:
                assert self._redis_client is not None
                self._redis_client.publish(self._channel(topic), json.dumps(envelope, separators=(",", ":")))
            except Exception as exc:
                self._degrade_to_memory(exc)
                self._dispatch_local(envelope)
                return
            return
        self._dispatch_local(envelope)

    def snapshot(self) -> dict[str, int | str]:
        with self._lock:
            return {
                "backend": self._stats.backend,
                "published": self._stats.published,
                "delivered": self._stats.delivered,
                "subscriptions": self._stats.subscriptions,
            }

    def recent_events(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._recent_events)

    def recent_events_since(
        self,
        *,
        cursor: int | None = None,
        limit: int = 200,
    ) -> tuple[list[dict[str, Any]], int]:
        safe_limit = max(1, min(1000, int(limit)))
        normalized_cursor = max(0, int(cursor or 0))
        with self._lock:
            if not self._recent_events:
                return [], normalized_cursor
            events = list(self._recent_events)
            floor = int(events[0].get("event_id", 0) or 0)
            ceiling = int(events[-1].get("event_id", 0) or 0)
            effective_cursor = normalized_cursor
            if effective_cursor < floor - 1:
                effective_cursor = floor - 1
            if effective_cursor > ceiling:
                effective_cursor = ceiling
            pending = [event for event in events if int(event.get("event_id", 0) or 0) > effective_cursor]
            if len(pending) > safe_limit:
                pending = pending[:safe_limit]
            next_cursor = effective_cursor
            if pending:
                next_cursor = int(pending[-1].get("event_id", effective_cursor) or effective_cursor)
            return pending, next_cursor

    def close(self) -> None:
        self._stop_event.set()
        if self._listener_thread and self._listener_thread.is_alive():
            self._listener_thread.join(timeout=1.0)
        self._listener_thread = None
        if self._pubsub:
            try:
                self._pubsub.close()
            except Exception:
                pass
            self._pubsub = None

    def _dispatch_local(self, envelope: dict[str, Any]) -> None:
        topic = str(envelope.get("topic", ""))
        handlers: list[EventHandler] = []
        with self._lock:
            handlers.extend(self._subscriptions.get(topic, []))
            handlers.extend(self._subscriptions.get("*", []))
        for handler in handlers:
            try:
                handler(envelope)
                with self._lock:
                    self._stats.delivered += 1
            except Exception:
                continue

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
            self._stats.backend = "redis"
            if not self._redis_url_has_credentials(self.config.redis_url):
                self.logger.warning(
                    "redis event bus configured without AUTH credentials",
                    extra={
                        "service": "event_bus",
                        "payload": {"backend": "redis", "redis_url": safe_redis_url},
                    },
                )
            self.logger.info(
                "event bus backend initialized",
                extra={
                    "service": "event_bus",
                    "payload": {"backend": "redis", "redis_url": safe_redis_url},
                },
            )
        except Exception as exc:
            if self.config.required:
                raise RuntimeError(f"failed to initialize required redis event bus backend: {exc}") from exc
            self._stats.backend = "memory"
            self._redis_client = None
            self.logger.warning(
                "redis event bus unavailable, falling back to memory",
                extra={
                    "service": "event_bus",
                    "payload": {"backend": "memory", "error": str(exc)},
                },
            )

    def _degrade_to_memory(self, exc: Exception) -> None:
        if self._stats.backend == "memory":
            return
        self._stats.backend = "memory"
        self._redis_client = None
        self._pubsub = None
        self._stop_event.set()
        self.logger.error(
            "redis event bus failed, switched to memory",
            extra={
                "service": "event_bus",
                "payload": {"backend": "memory", "error": str(exc)},
            },
        )

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

    def _ensure_listener(self) -> None:
        if self._listener_thread and self._listener_thread.is_alive():
            return
        if not self._redis_client:
            return
        self._stop_event.clear()
        self._listener_thread = threading.Thread(target=self._listener_loop, name="event-bus-listener", daemon=True)
        self._listener_thread.start()

    def _listener_loop(self) -> None:
        try:
            assert self._redis_client is not None
            pubsub = self._redis_client.pubsub(ignore_subscribe_messages=True)
            self._pubsub = pubsub
            pubsub.psubscribe(self._channel("*"))
            while not self._stop_event.is_set():
                message = pubsub.get_message(timeout=0.2)
                if not message:
                    time.sleep(0.01)
                    continue
                data = message.get("data")
                if not data:
                    continue
                try:
                    envelope = json.loads(str(data))
                except json.JSONDecodeError:
                    continue
                with self._lock:
                    envelope = self._append_recent_event_locked(envelope)
                self._dispatch_local(envelope)
        except Exception as exc:
            self._degrade_to_memory(exc)

    def _append_recent_event_locked(self, envelope: dict[str, Any]) -> dict[str, Any]:
        event_uid = str(envelope.get("event_uid", "")).strip()
        if event_uid:
            for existing in reversed(self._recent_events):
                if str(existing.get("event_uid", "")).strip() == event_uid:
                    return dict(existing)
        normalized = dict(envelope)
        normalized["event_id"] = self._next_event_id
        self._next_event_id += 1
        self._recent_events.append(normalized)
        return normalized

    def _listener_active_locked(self) -> bool:
        return bool(self._listener_thread and self._listener_thread.is_alive())

    def _channel(self, topic: str) -> str:
        return f"{self.config.channel_prefix}:events:{topic}"
