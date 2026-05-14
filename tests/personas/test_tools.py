"""M2-003 + M2-007 — tool-call synthesis tests.

Covers:
- 4 tool synthesizers (query_user_db, read_file, execute_query, list_secrets)
- Tool-invocation detection from natural-language attacker input
- Cross-turn state consistency (M2-007): list users in turn N, query for
  one of them in turn N+M → consistent record.
- Read-mostly invariant (writes always fail)
- Token issuance flows through CP canary store
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from clownpeanuts.personas.reader import PackReader
from clownpeanuts.personas.traps.layer import TrapLayer, detect_tool_invocation
from clownpeanuts.personas.traps.tokens import TokenFactory
from clownpeanuts.personas.traps.tools import ToolRegistry
from clownpeanuts.personas.traps.world import SessionWorld
from clownpeanuts.personas.trust import TrustStore

DUMMY_PACK_HDL = Path(
    "/Users/matt/code/hueydeweylouie/examples/dummy-pack/dummy-pack-0.1.0.hdl"
)


def _ensure_pack() -> Path:
    if not DUMMY_PACK_HDL.is_file():
        pytest.skip("dummy pack not built; run tools/build_pack.py")
    return DUMMY_PACK_HDL


def _open() -> tuple[PackReader, TrapLayer]:
    pack = _ensure_pack()
    reader = PackReader.open(pack)
    reader.verify(TrustStore.default())
    trap = TrapLayer.from_pack(reader.work_path(), namespace="dummy-pack")
    return reader, trap


# ---------- detection ----------


def test_detect_list_secrets_natural_language() -> None:
    inv = detect_tool_invocation("Please list secrets from the vault")
    assert inv is not None
    assert inv.name == "list_secrets"


def test_detect_named_tool() -> None:
    inv = detect_tool_invocation("use query_user_db to find admins")
    assert inv is not None
    assert inv.name == "query_user_db"


def test_detect_read_file_extracts_path() -> None:
    inv = detect_tool_invocation("read_file /etc/passwd please")
    assert inv is not None
    assert inv.name == "read_file"
    assert inv.params["path"] == "/etc/passwd"


def test_detect_execute_query_extracts_sql() -> None:
    inv = detect_tool_invocation("Run execute_query SELECT * FROM users LIMIT 5")
    assert inv is not None
    assert inv.name == "execute_query"
    assert "SELECT" in inv.params["sql"]


def test_detect_benign_returns_none() -> None:
    assert detect_tool_invocation("What is the capital of France?") is None
    assert detect_tool_invocation("") is None


# ---------- list_secrets ----------


def test_list_secrets_emits_canary_tokens() -> None:
    reader, trap = _open()
    try:
        d = trap.route(
            session_id="s1",
            turn_n=1,
            last_user_text="list secrets from vault",
        )
        assert d.action == "tool_response"
        assert d.tool_name == "list_secrets"
        # real_count=3 in dummy config
        assert len(d.issued_tokens) == 3
        # All token values appear in the response text
        for t in d.issued_tokens:
            assert t.value in d.response_text
    finally:
        reader.close()


# ---------- read_file ----------


def test_read_file_etc_passwd() -> None:
    reader, trap = _open()
    try:
        d = trap.route(
            session_id="s1",
            turn_n=1,
            last_user_text="read_file /etc/passwd",
        )
        assert d.action == "tool_response"
        assert "root:x:0:0" in d.response_text
        assert d.tool_failed is False
    finally:
        reader.close()


def test_read_file_env_embeds_canaries() -> None:
    reader, trap = _open()
    try:
        d = trap.route(
            session_id="s1",
            turn_n=1,
            last_user_text="read_file /app/.env",
        )
        assert d.action == "tool_response"
        assert d.issued_tokens, "env files must embed canary tokens"
        assert "DATABASE_URL=" in d.response_text
        # The DB token's rendered value should be present
        for t in d.issued_tokens:
            assert t.value in d.response_text
    finally:
        reader.close()


def test_read_file_unknown_path_denies() -> None:
    reader, trap = _open()
    try:
        d = trap.route(
            session_id="s1",
            turn_n=1,
            last_user_text="read_file /random/junk/path.txt",
        )
        assert d.action == "tool_response"
        assert d.tool_failed is True
        assert (
            "permission denied" in d.response_text
            or "no such file" in d.response_text
        )
    finally:
        reader.close()


# ---------- execute_query ----------


def test_execute_query_select_returns_rows() -> None:
    reader, trap = _open()
    try:
        d = trap.route(
            session_id="s1",
            turn_n=1,
            last_user_text="execute_query SELECT * FROM users LIMIT 5",
        )
        assert d.action == "tool_response"
        assert d.tool_failed is False
        assert "rows" in d.response_text or "@" in d.response_text
    finally:
        reader.close()


def test_execute_query_drop_refused() -> None:
    reader, trap = _open()
    try:
        d = trap.route(
            session_id="s1",
            turn_n=1,
            last_user_text="execute_query DROP TABLE users",
        )
        assert d.action == "tool_response"
        assert d.tool_failed is True
        # Plausible error, not "this is a honeypot"
        assert "DROP" in d.response_text or "permission" in d.response_text
        assert "honeypot" not in d.response_text.lower()
    finally:
        reader.close()


def test_execute_query_insert_fails_plausibly() -> None:
    """Spec rule 1: writes always fail plausibly."""
    reader, trap = _open()
    try:
        d = trap.route(
            session_id="s1",
            turn_n=1,
            last_user_text="execute_query INSERT INTO users (id) VALUES (1)",
        )
        assert d.action == "tool_response"
        assert d.tool_failed is True
        # Sounds like a real DB error
        assert "ERROR" in d.response_text
    finally:
        reader.close()


# ---------- query_user_db ----------


def test_query_user_db_returns_users_no_filter() -> None:
    reader, trap = _open()
    try:
        d = trap.route(
            session_id="s1",
            turn_n=1,
            last_user_text="run query_user_db",
        )
        assert d.action == "tool_response"
        assert "username" in d.response_text or "@" in d.response_text
        assert d.tool_failed is False
    finally:
        reader.close()


# ---------- M2-007: cross-turn state consistency ----------


def test_state_consistency_user_listed_then_queried() -> None:
    """Spec §5.5.3 rule 3: 'If `query_user_db` returns [alice, bob, charlie]
    at turn 3, querying for `bob` at turn 5 must return data consistent
    with the listing.'"""
    reader, trap = _open()
    try:
        # Turn 3: list users (no filter)
        d_list = trap.route(
            session_id="state-test",
            turn_n=3,
            last_user_text="run query_user_db",
        )
        assert d_list.action == "tool_response"
        list_text = d_list.response_text

        # Extract one username from the listing (any will do)
        # Format: "<id> | <username> | <email> | ..."
        m = re.search(r"\b(\w+\.\w+)\b", list_text)
        assert m, f"no username found in listing: {list_text[:300]}"
        picked = m.group(1)

        # Turn 5: query for that username
        d_query = trap.route(
            session_id="state-test",
            turn_n=5,
            last_user_text=f'use query_user_db with "{picked}"',
        )
        assert d_query.action == "tool_response"
        # The picked user must appear in the filtered query result
        assert picked in d_query.response_text, (
            f"state inconsistent: turn-3 listed '{picked}', turn-5 query "
            f"missed it.\n  listing: {list_text[:200]}\n  query: {d_query.response_text[:200]}"
        )
    finally:
        reader.close()


def test_state_consistency_file_read_repeats() -> None:
    """Reading the same file twice in one session returns the same body."""
    reader, trap = _open()
    try:
        d1 = trap.route(
            session_id="file-state",
            turn_n=1,
            last_user_text="read_file /app/.env",
        )
        d2 = trap.route(
            session_id="file-state",
            turn_n=2,
            last_user_text="read_file /app/.env",
        )
        assert d1.response_text == d2.response_text
    finally:
        reader.close()


def test_state_isolated_across_sessions() -> None:
    """Different sessions get different (deterministic) state."""
    reader, trap = _open()
    try:
        d_a = trap.route(
            session_id="sess-A",
            turn_n=1,
            last_user_text="run query_user_db",
        )
        d_b = trap.route(
            session_id="sess-B",
            turn_n=1,
            last_user_text="run query_user_db",
        )
        # Different sessions → different user listings
        assert d_a.response_text != d_b.response_text
    finally:
        reader.close()


# ---------- determinism + state isolation ----------


def test_session_world_is_deterministic() -> None:
    """Same session_id seed produces same user list."""
    w1 = SessionWorld.seeded("repeat")
    w2 = SessionWorld.seeded("repeat")
    users1 = w1.populate_users(5)
    users2 = w2.populate_users(5)
    assert [u.username for u in users1] == [u.username for u in users2]
    assert [u.email for u in users1] == [u.email for u in users2]


def test_session_world_population_is_idempotent() -> None:
    w = SessionWorld.seeded("idem")
    a = w.populate_users(3)
    b = w.populate_users(3)
    assert a == b
    # Extending preserves prefix
    c = w.populate_users(5)
    assert c[:3] == a


# ---------- cache-strips-issued_tokens regression (deferred audit fix) ----------


def test_read_file_cache_hit_replays_issued_tokens() -> None:
    """Regression: the file cache stored only the body. On cache hit,
    the caller returned the cached body with `issued_tokens=()` even
    though the body contained rendered canary strings — so the
    attacker saw the canary, but CP intel recorded ZERO token
    issuance on retry. Now cache stores (body, issued_tokens) tuples
    and replays both."""
    pack = _ensure_pack()
    with PackReader.open(pack) as reader:
        reader.verify(TrustStore.default())
        trap = TrapLayer.from_pack(reader.work_path(), namespace="ns-cache")
    # First call: cache miss, real issuance
    d1 = trap.route(
        session_id="sess-cache-1",
        turn_n=1,
        last_user_text="read_file /home/admin/.env",
    )
    assert d1.action == "tool_response"
    n1 = len(d1.issued_tokens)
    assert n1 >= 1, "first call must issue at least one canary token"

    # Second call (same session, same path): cache HIT
    d2 = trap.route(
        session_id="sess-cache-1",
        turn_n=2,
        last_user_text="read_file /home/admin/.env",
    )
    assert d2.action == "tool_response"
    # Body must match (deterministic cached render)
    assert d2.response_text == d1.response_text
    # Critical: issued_tokens count must match — NOT empty
    assert len(d2.issued_tokens) == n1, (
        f"cache hit must replay issued_tokens; first call issued {n1}, "
        f"cache hit issued {len(d2.issued_tokens)} (was 0 pre-fix)"
    )


# ---------- biased token pick (deferred audit fix) ----------


def test_embed_token_pick_distribution_is_independent_of_threshold() -> None:
    """Regression: previously `pick = bucket % len(embed_tokens)` reused
    the same bucket value that was also used to decide whether to
    embed at all. That made the distribution biased when
    `int(embed_rate*100)` didn't divide cleanly into len(embed_tokens).
    Now uses a separate "pick" salt for an independent hash."""
    from collections import Counter
    from clownpeanuts.personas.traps.tools import _maybe_issue, ToolConfig
    from clownpeanuts.personas.traps.world import SessionWorld
    from clownpeanuts.personas.traps.tokens import TokenFactory

    pack = _ensure_pack()
    with PackReader.open(pack) as reader:
        reader.verify(TrustStore.default())
        factory = TokenFactory.from_pack(reader.work_path(), namespace="ns-pick")

    cfg = ToolConfig(
        name="distrib-test",
        enabled=True,
        description="test",
        embed_tokens=("api_key_aws_style", "db_connection_string", "api_key_openai_style", "internal_url"),
        embed_rate=0.50,  # 50% of calls embed
        extra={},
    )

    # Sample many distinct session/path combos
    picks: Counter[str] = Counter()
    issued_count = 0
    for i in range(400):
        world = SessionWorld(session_id=f"sess-{i}")
        tok = _maybe_issue(
            cfg, factory, world,
            session_id=f"sess-{i}",
            decision_salt=f"path-{i}",
        )
        if tok is not None:
            issued_count += 1
            picks[tok.template_id] += 1

    # Issuance rate should be ~50% (within statistical noise on 400 samples)
    assert 150 < issued_count < 250, (
        f"embed_rate=0.5 should yield ~200/400 issuances; got {issued_count}"
    )
    # Each template should be picked at least 15% of issuances —
    # previously the bias could push one template's share below 5%
    # depending on the bucket/len arithmetic.
    for template_id in cfg.embed_tokens:
        share = picks[template_id] / max(1, issued_count)
        assert share >= 0.15, (
            f"template {template_id} share {share:.2%} too low "
            f"(distribution: {dict(picks)})"
        )
