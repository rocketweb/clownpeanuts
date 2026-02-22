from clownpeanuts.config.schema import SessionConfig
from clownpeanuts.core.session import SessionManager
import pytest


class _FakeRedisPipeline:
    def __init__(self, client: "_FakeRedis") -> None:
        self._client = client
        self._ops: list[tuple[str, tuple[object, ...], dict[str, object]]] = []

    def execute(self) -> list[object]:
        results: list[object] = []
        for method_name, args, kwargs in self._ops:
            method = getattr(self._client, f"_apply_{method_name}")
            results.append(method(*args, **kwargs))
        self._ops.clear()
        return results

    def hsetnx(self, key: str, field: str, value: object) -> "_FakeRedisPipeline":
        self._ops.append(("hsetnx", (key, field, value), {}))
        return self

    def hset(self, key: str, *, mapping: dict[str, object]) -> "_FakeRedisPipeline":
        self._ops.append(("hset", (key,), {"mapping": mapping}))
        return self

    def sadd(self, key: str, member: str) -> "_FakeRedisPipeline":
        self._ops.append(("sadd", (key, member), {}))
        return self

    def srem(self, key: str, member: str) -> "_FakeRedisPipeline":
        self._ops.append(("srem", (key, member), {}))
        return self

    def zadd(
        self,
        key: str,
        mapping: dict[str, float],
        *,
        nx: bool = False,
    ) -> "_FakeRedisPipeline":
        self._ops.append(("zadd", (key, mapping), {"nx": nx}))
        return self

    def zrem(self, key: str, member: str) -> "_FakeRedisPipeline":
        self._ops.append(("zrem", (key, member), {}))
        return self

    def expire(self, key: str, ttl: int) -> "_FakeRedisPipeline":
        self._ops.append(("expire", (key, ttl), {}))
        return self

    def hincrby(self, key: str, field: str, amount: int) -> "_FakeRedisPipeline":
        self._ops.append(("hincrby", (key, field, amount), {}))
        return self

    def incr(self, key: str) -> "_FakeRedisPipeline":
        self._ops.append(("incr", (key,), {}))
        return self

    def hgetall(self, key: str) -> "_FakeRedisPipeline":
        self._ops.append(("hgetall", (key,), {}))
        return self

    def lrange(self, key: str, start: int, end: int) -> "_FakeRedisPipeline":
        self._ops.append(("lrange", (key, start, end), {}))
        return self

    def smembers(self, key: str) -> "_FakeRedisPipeline":
        self._ops.append(("smembers", (key,), {}))
        return self

    def rpush(self, key: str, value: str) -> "_FakeRedisPipeline":
        self._ops.append(("rpush", (key, value), {}))
        return self

    def ltrim(self, key: str, start: int, end: int) -> "_FakeRedisPipeline":
        self._ops.append(("ltrim", (key, start, end), {}))
        return self


class _FakeRedis:
    def __init__(self, *, raise_on_smembers: bool = False) -> None:
        self.hashes: dict[str, dict[str, object]] = {}
        self.lists: dict[str, list[str]] = {}
        self.sets: dict[str, set[str]] = {}
        self.zsets: dict[str, dict[str, float]] = {}
        self.values: dict[str, int] = {}
        self.raise_on_smembers = raise_on_smembers
        self.smembers_calls = 0
        self.session_index_smembers_calls = 0

    def pipeline(self) -> _FakeRedisPipeline:
        return _FakeRedisPipeline(self)

    def _apply_hsetnx(self, key: str, field: str, value: object) -> int:
        bucket = self.hashes.setdefault(key, {})
        if field in bucket:
            return 0
        bucket[field] = value
        return 1

    def _apply_hset(self, key: str, *, mapping: dict[str, object]) -> int:
        bucket = self.hashes.setdefault(key, {})
        for field, value in mapping.items():
            bucket[field] = value
        return len(mapping)

    def _apply_sadd(self, key: str, member: str) -> int:
        bucket = self.sets.setdefault(key, set())
        if member in bucket:
            return 0
        bucket.add(member)
        return 1

    def _apply_srem(self, key: str, member: str) -> int:
        bucket = self.sets.setdefault(key, set())
        if member in bucket:
            bucket.remove(member)
            return 1
        return 0

    def _apply_zadd(self, key: str, mapping: dict[str, float], *, nx: bool = False) -> int:
        bucket = self.zsets.setdefault(key, {})
        added = 0
        for member, score in mapping.items():
            if nx and member in bucket:
                continue
            if member not in bucket:
                added += 1
            bucket[member] = float(score)
        return added

    def _apply_zrem(self, key: str, member: str) -> int:
        bucket = self.zsets.setdefault(key, {})
        if member in bucket:
            del bucket[member]
            return 1
        return 0

    def _apply_expire(self, key: str, ttl: int) -> int:
        _ = key, ttl
        return 1

    def _apply_hincrby(self, key: str, field: str, amount: int) -> int:
        bucket = self.hashes.setdefault(key, {})
        current = int(bucket.get(field, 0) or 0)
        updated = current + int(amount)
        bucket[field] = updated
        return updated

    def _apply_incr(self, key: str) -> int:
        updated = int(self.values.get(key, 0) or 0) + 1
        self.values[key] = updated
        return updated

    def incr(self, key: str) -> int:
        return self._apply_incr(key)

    def _apply_hgetall(self, key: str) -> dict[str, object]:
        return dict(self.hashes.get(key, {}))

    def hgetall(self, key: str) -> dict[str, object]:
        return self._apply_hgetall(key)

    @staticmethod
    def _slice(values: list[str], start: int, end: int) -> list[str]:
        size = len(values)
        if size == 0:
            return []
        if start < 0:
            start += size
        if end < 0:
            end += size
        start = max(0, start)
        end = min(size - 1, end)
        if end < start or start >= size:
            return []
        return values[start : end + 1]

    def _apply_lrange(self, key: str, start: int, end: int) -> list[str]:
        return self._slice(self.lists.get(key, []), start, end)

    def lrange(self, key: str, start: int, end: int) -> list[str]:
        return self._apply_lrange(key, start, end)

    def _apply_smembers(self, key: str) -> set[str]:
        return self.smembers(key)

    def _apply_rpush(self, key: str, value: str) -> int:
        bucket = self.lists.setdefault(key, [])
        bucket.append(str(value))
        return len(bucket)

    def _apply_ltrim(self, key: str, start: int, end: int) -> bool:
        self.lists[key] = self._slice(self.lists.get(key, []), start, end)
        return True

    def hget(self, key: str, field: str) -> object | None:
        return self.hashes.get(key, {}).get(field)

    def get(self, key: str) -> int | None:
        return self.values.get(key)

    def llen(self, key: str) -> int:
        return len(self.lists.get(key, []))

    def scard(self, key: str) -> int:
        return len(self.sets.get(key, set()))

    def smembers(self, key: str) -> set[str]:
        self.smembers_calls += 1
        if key.endswith(":sessions:index"):
            self.session_index_smembers_calls += 1
        if self.raise_on_smembers and key.endswith(":sessions:index"):
            raise AssertionError("smembers should not be called when created index is populated")
        return set(self.sets.get(key, set()))

    def zrevrange(self, key: str, start: int, end: int) -> list[str]:
        entries = sorted(self.zsets.get(key, {}).items(), key=lambda item: (-item[1], item[0]))
        members = [member for member, _ in entries]
        return self._slice(members, start, end)


def _redis_manager(client: _FakeRedis) -> SessionManager:
    manager = SessionManager(SessionConfig(backend="memory"))
    manager._backend = "redis"
    manager._redis_client = client
    return manager


def test_session_manager_memory_snapshot_includes_backend() -> None:
    manager = SessionManager(SessionConfig(backend="memory"))
    manager.get_or_create(session_id="s1", source_ip="10.0.0.5")
    manager.record_event(
        session_id="s1",
        service="ssh",
        action="auth_attempt",
        payload={"source_ip": "10.0.0.5", "username": "root"},
    )
    manager.record_event(
        session_id="s1",
        service="ssh",
        action="command",
        payload={"source_ip": "10.0.0.5", "command": "whoami"},
    )
    snapshot = manager.snapshot()
    assert snapshot["backend"] == "memory"
    assert snapshot["sessions"] == 1
    assert snapshot["credential_events"] == 1
    assert snapshot["command_events"] == 1
    assert manager.session_event_count("s1") == 2

    exported = manager.export_sessions(limit=10, events_per_session=10)
    assert len(exported) == 1
    assert exported[0]["session_id"] == "s1"
    assert exported[0]["event_count"] == 2

    replay = manager.export_session("s1", events_limit=1)
    assert replay is not None
    assert replay["session_id"] == "s1"
    assert replay["event_count"] == 2
    assert len(replay["events"]) == 1


def test_session_manager_memory_session_tags_are_exported_and_attached_to_events() -> None:
    manager = SessionManager(SessionConfig(backend="memory"))
    manager.get_or_create(session_id="s-tags", source_ip="10.0.0.9")
    tags = manager.add_session_tags(
        session_id="s-tags",
        tags=["Witchbait", "witchbait:cred-1", "witchbait"],
    )
    assert tags == ["witchbait", "witchbait:cred-1"]

    manager.record_event(
        session_id="s-tags",
        service="ssh",
        action="command",
        payload={"source_ip": "10.0.0.9", "command": "id"},
    )

    replay = manager.export_session("s-tags", events_limit=10)
    assert replay is not None
    assert replay["tags"] == ["witchbait", "witchbait:cred-1"]
    assert replay["events"][0]["payload"]["session_tags"] == ["witchbait", "witchbait:cred-1"]


def test_session_manager_memory_session_tags_are_capped() -> None:
    manager = SessionManager(SessionConfig(backend="memory"))
    manager.get_or_create(session_id="s-tags-cap", source_ip="10.0.0.90")
    incoming_tags = [f"tag-{index:03d}" for index in range(SessionManager._MAX_SESSION_TAGS + 32)]
    tags = manager.add_session_tags(session_id="s-tags-cap", tags=incoming_tags)
    assert len(tags) == SessionManager._MAX_SESSION_TAGS
    assert tags[0] == "tag-000"
    assert tags[-1] == f"tag-{SessionManager._MAX_SESSION_TAGS - 1:03d}"


def test_session_manager_memory_retention_cap_preserves_total_counts() -> None:
    manager = SessionManager(SessionConfig(backend="memory", max_events_per_session=3))
    manager.get_or_create(session_id="s-cap", source_ip="10.10.10.10")
    for index in range(5):
        manager.record_event(
            session_id="s-cap",
            service="ssh",
            action="command",
            payload={"source_ip": "10.10.10.10", "command": f"cmd-{index}"},
        )

    snapshot = manager.snapshot()
    assert snapshot["events"] == 5
    assert snapshot["command_events"] == 5
    assert manager.session_event_count("s-cap") == 5

    replay = manager.export_session("s-cap", events_limit=10)
    assert replay is not None
    assert replay["event_count"] == 5
    assert [item["payload"]["command"] for item in replay["events"]] == ["cmd-2", "cmd-3", "cmd-4"]


def test_session_manager_memory_evicts_oldest_session_when_capacity_reached() -> None:
    manager = SessionManager(SessionConfig(backend="memory"))
    manager._MAX_MEMORY_SESSIONS = 2

    manager.get_or_create(session_id="s1", source_ip="10.10.10.1")
    manager.get_or_create(session_id="s2", source_ip="10.10.10.2")
    manager.get_or_create(session_id="s1", source_ip="10.10.10.1")
    manager.get_or_create(session_id="s3", source_ip="10.10.10.3")

    assert manager.export_session("s2", events_limit=10) is None
    assert manager.export_session("s1", events_limit=10) is not None
    assert manager.export_session("s3", events_limit=10) is not None


def test_session_manager_export_sessions_preserves_creation_order_when_activity_reorders_lru() -> None:
    manager = SessionManager(SessionConfig(backend="memory"))
    manager.get_or_create(session_id="s1", source_ip="10.10.20.1")
    manager.get_or_create(session_id="s2", source_ip="10.10.20.2")
    manager.get_or_create(session_id="s3", source_ip="10.10.20.3")
    manager.get_or_create(session_id="s1", source_ip="10.10.20.1")

    exported = manager.export_sessions(limit=3, events_per_session=0)
    assert [item["session_id"] for item in exported] == ["s3", "s2", "s1"]


def test_session_manager_export_sessions_skips_evicted_creation_slots() -> None:
    manager = SessionManager(SessionConfig(backend="memory"))
    manager._MAX_MEMORY_SESSIONS = 2
    manager.get_or_create(session_id="s1", source_ip="10.10.21.1")
    manager.get_or_create(session_id="s2", source_ip="10.10.21.2")
    manager.get_or_create(session_id="s1", source_ip="10.10.21.1")
    manager.get_or_create(session_id="s3", source_ip="10.10.21.3")

    exported = manager.export_sessions(limit=5, events_per_session=0)
    assert [item["session_id"] for item in exported] == ["s3", "s1"]


def test_session_manager_export_session_returns_none_when_missing() -> None:
    manager = SessionManager(SessionConfig(backend="memory"))
    assert manager.export_session("missing", events_limit=50) is None


def test_session_manager_resolve_narrative_context_tracks_progression() -> None:
    manager = SessionManager(SessionConfig(backend="memory"))
    context_one = manager.resolve_narrative_context(
        session_id="s-narrative",
        source_ip="10.0.0.8",
        tenant_id="default",
        service="ssh",
        action="command",
        hints={"command": "ls -la"},
    )
    context_two = manager.resolve_narrative_context(
        session_id="s-narrative",
        source_ip="10.0.0.8",
        tenant_id="default",
        service="postgres-db",
        action="query",
        hints={"query": "select * from users"},
    )

    assert context_one["context_id"] == context_two["context_id"]
    assert context_one["tenant_id"] == "default"
    assert context_one["discovery_depth"] == 1
    assert context_two["discovery_depth"] == 2
    assert context_two["last_service"] == "postgres-db"
    assert context_two["last_action"] == "query"
    assert "ssh" in context_two["touched_services"]
    assert "postgres-db" in context_two["touched_services"]

    replay = manager.export_session("s-narrative", events_limit=10)
    assert replay is not None
    assert replay["narrative"]["discovery_depth"] == 2
    assert replay["narrative"]["context_id"] == context_one["context_id"]


def test_session_manager_narrative_touched_services_are_capped() -> None:
    manager = SessionManager(SessionConfig(backend="memory"))
    for index in range(SessionManager._MAX_TOUCHED_SERVICES + 20):
        manager.resolve_narrative_context(
            session_id="s-narrative-cap",
            source_ip="10.0.8.8",
            tenant_id="default",
            service=f"svc-{index:03d}",
            action="command",
            hints={"command": "whoami"},
        )
    replay = manager.export_session("s-narrative-cap", events_limit=1)
    assert replay is not None
    touched = replay["narrative"]["touched_services"]
    assert len(touched) == SessionManager._MAX_TOUCHED_SERVICES
    assert touched[0] == f"svc-{20:03d}"
    assert touched[-1] == f"svc-{SessionManager._MAX_TOUCHED_SERVICES + 19:03d}"


def test_session_manager_redis_falls_back_when_unavailable() -> None:
    manager = SessionManager(
        SessionConfig(
            backend="redis",
            redis_url="redis://127.0.0.1:0/0",
            connect_timeout_seconds=0.05,
            required=False,
        )
    )
    assert manager.backend == "memory"


def test_session_manager_required_redis_raises() -> None:
    with pytest.raises(RuntimeError):
        SessionManager(
            SessionConfig(
                backend="redis",
                redis_url="redis://127.0.0.1:0/0",
                connect_timeout_seconds=0.05,
                required=True,
            )
        )


def test_session_manager_redis_url_credential_detection() -> None:
    assert SessionManager._redis_url_has_credentials("redis://:strong-password@redis:6379/0")
    assert SessionManager._redis_url_has_credentials("rediss://user:strong-password@redis:6379/0")
    assert SessionManager._redis_url_has_credentials("redis://user:strong-password@127.0.0.1:6379/0")
    assert SessionManager._redis_url_has_credentials("redis://user:strong-password@localhost:6379/0")
    assert not SessionManager._redis_url_has_credentials("redis://redis:6379/0")
    assert not SessionManager._redis_url_has_credentials("redis://user@redis:6379/0")


def test_session_manager_redacts_redis_url_passwords() -> None:
    assert SessionManager._redact_redis_url("redis://:strong-password@redis:6379/0") == "redis://:***@redis:6379/0"
    assert (
        SessionManager._redact_redis_url("rediss://user:strong-password@redis:6379/0")
        == "rediss://user:***@redis:6379/0"
    )
    assert SessionManager._redact_redis_url("redis://redis:6379/0") == "redis://redis:6379/0"


def test_session_manager_redis_export_prefers_created_index_without_smembers() -> None:
    client = _FakeRedis(raise_on_smembers=True)
    manager = _redis_manager(client)

    manager.get_or_create(session_id="s1", source_ip="10.0.31.1")
    manager.get_or_create(session_id="s2", source_ip="10.0.31.2")
    manager.get_or_create(session_id="s3", source_ip="10.0.31.3")

    created_index = manager._session_created_index_key()
    client.zsets[created_index] = {"s1": 1.0, "s2": 2.0, "s3": 3.0}

    exported = manager.export_sessions(limit=2, events_per_session=0)
    assert [item["session_id"] for item in exported] == ["s3", "s2"]
    assert client.session_index_smembers_calls == 0
    assert manager.backend == "redis"


def test_session_manager_redis_session_tags_are_exported_and_attached_to_events() -> None:
    client = _FakeRedis()
    manager = _redis_manager(client)

    manager.get_or_create(session_id="redis-tags", source_ip="10.0.44.9")
    tags = manager.add_session_tags(
        session_id="redis-tags",
        source_ip="10.0.44.9",
        tags=["Witchbait", "witchbait:cred-2"],
    )
    assert tags == ["witchbait", "witchbait:cred-2"]

    manager.record_event(
        session_id="redis-tags",
        service="postgres",
        action="query",
        payload={"source_ip": "10.0.44.9", "query": "select 1"},
    )
    replay = manager.export_session("redis-tags", events_limit=10)
    assert replay is not None
    assert replay["tags"] == ["witchbait", "witchbait:cred-2"]
    assert replay["events"][0]["payload"]["session_tags"] == ["witchbait", "witchbait:cred-2"]


def test_session_manager_redis_export_prunes_stale_index_entries() -> None:
    client = _FakeRedis()
    manager = _redis_manager(client)

    manager.get_or_create(session_id="stale", source_ip="10.0.32.10")
    client.hashes.pop(manager._session_key("stale"), None)

    assert manager.export_sessions(limit=5, events_per_session=0) == []
    assert "stale" not in client.sets.get(manager._session_index_key(), set())
    assert "stale" not in client.zsets.get(manager._session_created_index_key(), {})


def test_session_manager_redis_export_falls_back_to_set_index_for_legacy_data() -> None:
    client = _FakeRedis()
    manager = _redis_manager(client)

    client.sets[manager._session_index_key()] = {"legacy-a", "legacy-b"}
    client.hashes[manager._session_key("legacy-a")] = {
        "source_ip": "10.0.33.1",
        "created_at": "2026-01-01T10:00:00.000000+00:00",
        "fingerprint": "",
        "event_count_total": 0,
    }
    client.hashes[manager._session_key("legacy-b")] = {
        "source_ip": "10.0.33.2",
        "created_at": "2026-01-02T10:00:00.000000+00:00",
        "fingerprint": "",
        "event_count_total": 0,
    }

    exported = manager.export_sessions(limit=2, events_per_session=0)
    assert [item["session_id"] for item in exported] == ["legacy-b", "legacy-a"]
    assert client.session_index_smembers_calls == 1
