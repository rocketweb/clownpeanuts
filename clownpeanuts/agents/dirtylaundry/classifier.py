"""Skill classification helpers for optional attribution flows."""

from __future__ import annotations


def classify_skill_level(metrics: dict[str, float]) -> str:
    """Classify skill level using simple weighted thresholding."""

    tool_customization = max(0.0, float(metrics.get("tool_signatures", 0.0)))
    opsec = max(0.0, float(metrics.get("temporal_pattern", 0.0)))
    persistence = max(0.0, float(metrics.get("credential_reuse", 0.0)))
    command_depth = max(0.0, float(metrics.get("command_vocabulary", 0.0)))

    composite = (0.35 * tool_customization) + (0.25 * opsec) + (0.20 * persistence) + (0.20 * command_depth)
    if composite >= 0.85:
        return "apt"
    if composite >= 0.65:
        return "advanced"
    if composite >= 0.40:
        return "intermediate"
    return "script_kiddie"

