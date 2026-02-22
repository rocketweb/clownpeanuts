"""Adaptive lure bandit scaffolding."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import math
import random
import time

from clownpeanuts.config.schema import BanditConfig


@dataclass(slots=True)
class LureArmDecision:
    context_key: str
    selected_arm: str | None
    algorithm: str
    exploration_floor: float
    exploration_applied: bool = False
    eligible_arms: list[str] = field(default_factory=list)
    blocked_arms: dict[str, str] = field(default_factory=dict)
    arm_scores: dict[str, float] = field(default_factory=dict)
    total_selections: int = 0
    override_applied: bool = False
    override_expires_at: str = ""


@dataclass(slots=True)
class LureArmStats:
    pulls: int = 0
    reward_sum: float = 0.0
    reward_updates: int = 0
    last_selected_at_epoch: float = 0.0
    last_reward_at_epoch: float = 0.0


class LureBandit:
    """Contextual lure selector with Thompson/UCB scoring and safety caps."""

    def __init__(self, config: BanditConfig) -> None:
        self.config = config
        self._arm_stats: dict[str, LureArmStats] = {}
        self._overrides: dict[str, tuple[str, float]] = {}
        self._total_selections = 0
        seed = int(
            hashlib.sha1(
                f"{config.algorithm}:{config.exploration_floor}".encode("utf-8"),
                usedforsecurity=False,
            ).hexdigest()[:16],
            16,
        )
        self._rng = random.Random(seed)

    def select_arm(self, *, context_key: str, candidates: list[str], now_epoch: float | None = None) -> LureArmDecision:
        normalized_context = context_key.strip() or "default"
        normalized_candidates = sorted({item.strip() for item in candidates if item.strip()})
        if not self.config.enabled or not normalized_candidates:
            return LureArmDecision(
                context_key=normalized_context,
                selected_arm=None,
                algorithm=self.config.algorithm,
                exploration_floor=self.config.exploration_floor,
                total_selections=self._total_selections,
            )

        now = float(now_epoch) if now_epoch is not None else time.time()
        eligible: list[str] = []
        blocked: dict[str, str] = {}
        for arm in normalized_candidates:
            reason = self._blocked_reason(arm=arm, now_epoch=now)
            if reason:
                blocked[arm] = reason
                continue
            eligible.append(arm)

        if not eligible:
            return LureArmDecision(
                context_key=normalized_context,
                selected_arm=None,
                algorithm=self.config.algorithm,
                exploration_floor=self.config.exploration_floor,
                eligible_arms=[],
                blocked_arms=blocked,
                total_selections=self._total_selections,
            )

        scores = self._arm_scores(context_key=normalized_context, arms=eligible)
        override_arm, override_expires_at_epoch = self._active_override(context_key=normalized_context, now_epoch=now)
        exploration_applied = False
        override_applied = False
        if override_arm and override_arm in eligible:
            selected = override_arm
            override_applied = True
        else:
            exploration_applied = self._should_explore(context_key=normalized_context, now_epoch=now)
            if exploration_applied:
                selected = self._pick_exploration_arm(context_key=normalized_context, arms=eligible)
            else:
                selected = sorted(eligible, key=lambda arm: (-scores.get(arm, 0.0), arm))[0]

        stats = self._stats_for_arm(selected)
        stats.pulls += 1
        stats.last_selected_at_epoch = now
        self._total_selections += 1
        return LureArmDecision(
            context_key=normalized_context,
            selected_arm=selected,
            algorithm=self.config.algorithm,
            exploration_floor=self.config.exploration_floor,
            exploration_applied=exploration_applied,
            eligible_arms=eligible,
            blocked_arms=blocked,
            arm_scores={arm: round(scores.get(arm, 0.0), 6) for arm in eligible},
            total_selections=self._total_selections,
            override_applied=override_applied,
            override_expires_at=self._iso_timestamp(override_expires_at_epoch),
        )

    def record_reward(self, *, context_key: str, arm: str, reward: float, now_epoch: float | None = None) -> dict[str, object]:
        normalized_context = context_key.strip() or "default"
        normalized_arm = arm.strip()
        if not self.config.enabled or not normalized_arm:
            return {
                "recorded": False,
                "context_key": normalized_context,
                "arm": normalized_arm,
                "reward": 0.0,
            }
        bounded_reward = min(1.0, max(0.0, float(reward)))
        now = float(now_epoch) if now_epoch is not None else time.time()
        stats = self._stats_for_arm(normalized_arm)
        stats.reward_sum += bounded_reward
        stats.reward_updates += 1
        stats.last_reward_at_epoch = now
        return {
            "recorded": True,
            "context_key": normalized_context,
            "arm": normalized_arm,
            "reward": round(bounded_reward, 6),
            "reward_updates": stats.reward_updates,
            "reward_avg": round(self._mean_reward(stats), 6),
        }

    def snapshot(self) -> dict[str, object]:
        return {
            "enabled": self.config.enabled,
            "algorithm": self.config.algorithm,
            "exploration_floor": self.config.exploration_floor,
            "reward_weights": {
                "dwell_time": self.config.reward_weights.dwell_time,
                "cross_protocol_pivot": self.config.reward_weights.cross_protocol_pivot,
                "technique_novelty": self.config.reward_weights.technique_novelty,
                "alert_quality": self.config.reward_weights.alert_quality,
                "analyst_feedback": self.config.reward_weights.analyst_feedback,
            },
            "safety_caps": {
                "max_arm_exposure_percent": self.config.safety_caps.max_arm_exposure_percent,
                "cooldown_seconds": self.config.safety_caps.cooldown_seconds,
                "denylist": list(self.config.safety_caps.denylist),
            },
            "total_selections": self._total_selections,
            "tracked_arm_count": len(self._arm_stats),
            "arms": self._arm_snapshot(),
            "arm_confidence": self.arm_confidence_map(),
            "overrides": self._override_snapshot(),
        }

    def arm_confidence(self, *, arm: str) -> float:
        normalized_arm = arm.strip()
        if not normalized_arm:
            return 0.0
        stats = self._arm_stats.get(normalized_arm)
        if stats is None:
            return 0.0
        pulls_factor = min(1.0, float(stats.pulls) / 20.0)
        reward_component = min(1.0, max(0.0, self._mean_reward(stats)))
        stability_component = min(1.0, float(stats.reward_updates) / max(1.0, float(stats.pulls)))
        confidence = (reward_component * 0.55) + (pulls_factor * 0.35) + (stability_component * 0.10)
        return round(max(0.0, min(1.0, confidence)), 6)

    def arm_confidence_map(self) -> dict[str, float]:
        return {arm: self.arm_confidence(arm=arm) for arm in sorted(self._arm_stats.keys())}

    def set_override(
        self,
        *,
        context_key: str,
        arm: str,
        duration_seconds: float,
        now_epoch: float | None = None,
    ) -> dict[str, object]:
        normalized_context = context_key.strip() or "default"
        normalized_arm = arm.strip()
        if not normalized_arm:
            return {
                "applied": False,
                "context_key": normalized_context,
                "arm": normalized_arm,
                "expires_at": "",
            }
        now = float(now_epoch) if now_epoch is not None else time.time()
        expires_at_epoch = now + max(1.0, float(duration_seconds))
        self._overrides[normalized_context] = (normalized_arm, expires_at_epoch)
        return {
            "applied": True,
            "context_key": normalized_context,
            "arm": normalized_arm,
            "expires_at": self._iso_timestamp(expires_at_epoch),
            "duration_seconds": max(1.0, float(duration_seconds)),
        }

    def clear_override(self, *, context_key: str | None = None) -> dict[str, object]:
        if context_key is None or context_key.strip() == "":
            cleared = len(self._overrides)
            self._overrides.clear()
            return {"cleared": cleared, "scope": "all"}
        normalized_context = context_key.strip()
        if normalized_context in self._overrides:
            del self._overrides[normalized_context]
            return {"cleared": 1, "scope": normalized_context}
        return {"cleared": 0, "scope": normalized_context}

    def reset(self, *, reason: str = "manual") -> dict[str, object]:
        cleared_arms = len(self._arm_stats)
        cleared_overrides = len(self._overrides)
        previous_total = self._total_selections
        self._arm_stats.clear()
        self._overrides.clear()
        self._total_selections = 0
        return {
            "reason": reason.strip() or "manual",
            "cleared_arms": cleared_arms,
            "cleared_overrides": cleared_overrides,
            "previous_total_selections": previous_total,
            "reset_at": datetime.now(UTC).isoformat(timespec="seconds"),
        }

    def _arm_snapshot(self) -> list[dict[str, object]]:
        payload: list[dict[str, object]] = []
        for arm in sorted(self._arm_stats.keys()):
            stats = self._arm_stats[arm]
            payload.append(
                {
                    "arm": arm,
                    "pulls": stats.pulls,
                    "reward_updates": stats.reward_updates,
                    "reward_sum": round(stats.reward_sum, 6),
                    "reward_avg": round(self._mean_reward(stats), 6),
                    "last_selected_at": self._iso_timestamp(stats.last_selected_at_epoch),
                    "last_reward_at": self._iso_timestamp(stats.last_reward_at_epoch),
                }
            )
        return payload

    def _override_snapshot(self) -> list[dict[str, str]]:
        now = time.time()
        self._cleanup_expired_overrides(now_epoch=now)
        payload: list[dict[str, str]] = []
        for context_key in sorted(self._overrides.keys()):
            arm, expires_at_epoch = self._overrides[context_key]
            payload.append(
                {
                    "context_key": context_key,
                    "arm": arm,
                    "expires_at": self._iso_timestamp(expires_at_epoch),
                }
            )
        return payload

    def _blocked_reason(self, *, arm: str, now_epoch: float) -> str:
        if arm in set(self.config.safety_caps.denylist):
            return "denylist"
        stats = self._stats_for_arm(arm)
        cooldown = max(0.0, float(self.config.safety_caps.cooldown_seconds))
        if cooldown > 0 and stats.last_selected_at_epoch > 0 and (now_epoch - stats.last_selected_at_epoch) < cooldown:
            return "cooldown"
        max_exposure = min(1.0, max(0.0, float(self.config.safety_caps.max_arm_exposure_percent)))
        if self._total_selections > 0 and max_exposure < 1.0:
            exposure = float(stats.pulls) / float(self._total_selections)
            if exposure >= max_exposure:
                return "max_exposure"
        return ""

    def _arm_scores(self, *, context_key: str, arms: list[str]) -> dict[str, float]:
        scores: dict[str, float] = {}
        for arm in arms:
            stats = self._stats_for_arm(arm)
            if self.config.algorithm == "ucb":
                scores[arm] = self._ucb_score(stats)
            else:
                scores[arm] = self._thompson_score(context_key=context_key, arm=arm, stats=stats)
        return scores

    def _thompson_score(self, *, context_key: str, arm: str, stats: LureArmStats) -> float:
        alpha = 1.0 + max(0.0, stats.reward_sum)
        beta = 1.0 + max(0.0, float(stats.pulls) - stats.reward_sum)
        sample_seed = int(
            hashlib.sha1(
                f"{context_key}:{arm}:{stats.pulls}:{stats.reward_updates}:{self._total_selections}".encode("utf-8"),
                usedforsecurity=False,
            ).hexdigest()[:16],
            16,
        )
        sampler = random.Random(sample_seed)
        return float(sampler.betavariate(alpha, beta))

    def _ucb_score(self, stats: LureArmStats) -> float:
        if stats.pulls <= 0:
            return 1.0 + float(self.config.exploration_floor)
        total = max(1, self._total_selections)
        mean = self._mean_reward(stats)
        bonus = math.sqrt((2.0 * math.log(float(total) + 1.0)) / float(stats.pulls))
        return float(mean + bonus)

    def _pick_exploration_arm(self, *, context_key: str, arms: list[str]) -> str:
        if len(arms) == 1:
            return arms[0]
        seed = int(
            hashlib.sha1(
                f"explore:{context_key}:{self._total_selections}:{len(arms)}".encode("utf-8"),
                usedforsecurity=False,
            ).hexdigest()[:8],
            16,
        )
        return arms[seed % len(arms)]

    def _active_override(self, *, context_key: str, now_epoch: float) -> tuple[str, float]:
        self._cleanup_expired_overrides(now_epoch=now_epoch)
        direct = self._overrides.get(context_key)
        if direct is not None:
            return direct
        wildcard = self._overrides.get("*")
        if wildcard is not None:
            return wildcard
        return ("", 0.0)

    def _cleanup_expired_overrides(self, *, now_epoch: float) -> None:
        expired = [
            context_key
            for context_key, (_arm, expires_at_epoch) in self._overrides.items()
            if expires_at_epoch <= now_epoch
        ]
        for context_key in expired:
            del self._overrides[context_key]

    def _should_explore(self, *, context_key: str, now_epoch: float) -> bool:
        floor = min(1.0, max(0.0, float(self.config.exploration_floor)))
        if floor <= 0.0:
            return False
        if floor >= 1.0:
            return True
        probe = int(
            hashlib.sha1(
                f"floor:{context_key}:{self._total_selections}:{int(now_epoch)}".encode("utf-8"),
                usedforsecurity=False,
            ).hexdigest()[:8],
            16,
        )
        ratio = float(probe % 10_000) / 10_000.0
        return ratio < floor

    def _stats_for_arm(self, arm: str) -> LureArmStats:
        stats = self._arm_stats.get(arm)
        if stats is None:
            stats = LureArmStats()
            self._arm_stats[arm] = stats
        return stats

    @staticmethod
    def _mean_reward(stats: LureArmStats) -> float:
        if stats.reward_updates <= 0:
            return 0.0
        return float(stats.reward_sum / float(stats.reward_updates))

    @staticmethod
    def _iso_timestamp(value: float) -> str:
        if value <= 0:
            return ""
        return datetime.fromtimestamp(value, tz=UTC).isoformat(timespec="seconds")
