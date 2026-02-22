"""Reward-scoring helpers for adaptive lure selection."""

from __future__ import annotations

from typing import Any

from clownpeanuts.config.schema import BanditRewardWeightsConfig


def compute_bandit_reward(*, weights: BanditRewardWeightsConfig, signals: dict[str, float | int]) -> float:
    """Compute a normalized reward score in the [0.0, 1.0] interval."""

    normalized = normalize_reward_signals(signals)
    weighted_sum = 0.0
    total_weight = 0.0
    for signal_name, weight in (
        ("dwell_time", float(weights.dwell_time)),
        ("cross_protocol_pivot", float(weights.cross_protocol_pivot)),
        ("technique_novelty", float(weights.technique_novelty)),
        ("alert_quality", float(weights.alert_quality)),
        ("analyst_feedback", float(weights.analyst_feedback)),
    ):
        bounded_weight = max(0.0, weight)
        total_weight += bounded_weight
        weighted_sum += bounded_weight * normalized.get(signal_name, 0.0)
    if total_weight <= 0.0:
        return 0.0
    return max(0.0, min(1.0, float(weighted_sum / total_weight)))


def normalize_reward_signals(signals: dict[str, float | int | str | Any]) -> dict[str, float]:
    payload: dict[str, float] = {}
    for signal_name in (
        "dwell_time",
        "cross_protocol_pivot",
        "technique_novelty",
        "alert_quality",
        "analyst_feedback",
    ):
        raw = signals.get(signal_name, 0.0)
        try:
            numeric = float(raw or 0.0)
        except (TypeError, ValueError):
            numeric = 0.0
        payload[signal_name] = max(0.0, min(1.0, numeric))
    return payload
