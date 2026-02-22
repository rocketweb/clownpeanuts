"""Skill-adaptive policy presets for optional runtime control loops."""

from __future__ import annotations

from typing import Any


_POLICIES: dict[str, dict[str, Any]] = {
    "script_kiddie": {
        "cascade_depth": 2,
        "phantom_lateral": False,
        "tarpit_minutes": 0,
        "theater_auto": False,
        "toxicity_level": 1,
    },
    "intermediate": {
        "cascade_depth": 4,
        "phantom_lateral": True,
        "tarpit_minutes": 15,
        "theater_auto": False,
        "toxicity_level": 2,
    },
    "advanced": {
        "cascade_depth": 6,
        "phantom_lateral": True,
        "tarpit_minutes": 30,
        "theater_auto": False,
        "toxicity_level": 2,
    },
    "apt": {
        "cascade_depth": 8,
        "phantom_lateral": True,
        "tarpit_minutes": 60,
        "theater_auto": True,
        "toxicity_level": 3,
    },
}


def policy_for_skill(skill: str) -> dict[str, Any]:
    normalized = skill.strip().lower()
    return dict(_POLICIES.get(normalized, _POLICIES["intermediate"]))

