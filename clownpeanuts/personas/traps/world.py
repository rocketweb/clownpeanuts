"""Per-session synthetic state for tool-call synthesis.

Each session gets a `SessionWorld` deterministically seeded by its
`session_id`, so:
- the same session reproduces the same data across turns (state
  consistency, spec §5.5.3 rule 3)
- different sessions are uncorrelated (no leakage between attackers)
- state is reproducible for testing

State lives in memory only. Not persisted across `vuln_llm` restarts —
acceptable for v1 since attacker sessions are typically short-lived.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any


_FIRST_NAMES = (
    "alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi",
    "ivan", "judy", "kyle", "laura", "mallory", "niaj", "oscar", "peggy",
    "rupert", "sybil", "trent", "victor", "wendy", "xander", "yvonne", "zara",
)
_LAST_NAMES = (
    "anderson", "barker", "chen", "diaz", "evans", "foster", "gao", "hill",
    "ibarra", "jones", "kim", "lopez", "mehta", "nguyen", "okafor", "patel",
    "qureshi", "rivera", "shah", "thomas", "ueda", "vargas", "wong", "xu",
)
_ROLES = (
    "engineer", "ops", "analyst", "intern", "support",
    "admin", "tech-lead", "manager",
)
_DOMAINS = ("acme.local", "internal.acme.com", "corp.acme.io")


@dataclass(slots=True)
class FakeUser:
    id: int
    username: str
    email: str
    role: str
    last_login: str

    def to_row(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "last_login": self.last_login,
        }


@dataclass(slots=True)
class SessionWorld:
    """Per-session deterministic synthetic state."""

    session_id: str
    users: list[FakeUser] = field(default_factory=list)
    # Cache of (table, query) → rows for SELECT consistency
    sql_cache: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # Cache of file path → body for read_file consistency
    file_cache: dict[str, str] = field(default_factory=dict)

    @classmethod
    def seeded(cls, session_id: str) -> "SessionWorld":
        return cls(session_id=session_id)

    def _seed_int(self, *salt: str) -> int:
        h = hashlib.sha256(self.session_id.encode("utf-8"))
        for s in salt:
            h.update(b":")
            h.update(s.encode("utf-8"))
        return int.from_bytes(h.digest()[:8], "big")

    def populate_users(self, count: int) -> list[FakeUser]:
        """Generate `count` deterministic users for this session.

        Idempotent: if already populated with ≥count, returns the prefix.
        Otherwise extends the list deterministically.
        """
        while len(self.users) < count:
            i = len(self.users)
            seed = self._seed_int("user", str(i))
            first = _FIRST_NAMES[seed % len(_FIRST_NAMES)]
            last = _LAST_NAMES[(seed >> 8) % len(_LAST_NAMES)]
            role = _ROLES[(seed >> 16) % len(_ROLES)]
            domain = _DOMAINS[(seed >> 24) % len(_DOMAINS)]
            day = ((seed >> 32) % 28) + 1
            month = ((seed >> 40) % 12) + 1
            self.users.append(
                FakeUser(
                    id=1000 + i,
                    username=f"{first}.{last}",
                    email=f"{first}.{last}@{domain}",
                    role=role,
                    last_login=f"2026-{month:02d}-{day:02d}T09:30:00Z",
                )
            )
        return self.users[:count]


class WorldRegistry:
    """Thread-safe per-session world registry."""

    def __init__(self) -> None:
        self._worlds: dict[str, SessionWorld] = {}
        self._lock = threading.Lock()

    def get_or_create(self, session_id: str) -> SessionWorld:
        with self._lock:
            world = self._worlds.get(session_id)
            if world is None:
                world = SessionWorld.seeded(session_id)
                self._worlds[session_id] = world
            return world

    def reset(self, session_id: str) -> None:
        with self._lock:
            self._worlds.pop(session_id, None)
