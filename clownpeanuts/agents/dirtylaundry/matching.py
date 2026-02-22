"""Weighted matching helpers for optional cross-session attribution."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class MatchResult:
    profile_id: str
    score: float
    breakdown: dict[str, dict[str, float]] = field(default_factory=dict)


class MatchingEngine:
    """Compute weighted cosine similarity across simple metric vectors."""

    _WEIGHTS = {
        "typing_cadence": 0.30,
        "command_vocabulary": 0.25,
        "tool_signatures": 0.20,
        "temporal_pattern": 0.15,
        "credential_reuse": 0.10,
    }

    def __init__(self, *, threshold: float = 0.75) -> None:
        self.threshold = max(0.0, min(1.0, float(threshold)))

    def score_breakdown(
        self,
        *,
        current: dict[str, float],
        existing: dict[str, float],
    ) -> dict[str, dict[str, float]]:
        breakdown: dict[str, dict[str, float]] = {}
        for key, weight in self._WEIGHTS.items():
            a = max(0.0, float(current.get(key, 0.0)))
            b = max(0.0, float(existing.get(key, 0.0)))
            if a == 0.0 and b == 0.0:
                similarity = 1.0
            else:
                baseline = max(a, b)
                similarity = 0.0 if baseline == 0 else 1.0 - (abs(a - b) / baseline)
            breakdown[key] = {
                "weight": float(weight),
                "current": float(a),
                "existing": float(b),
                "similarity": float(max(0.0, min(1.0, similarity))),
                "weighted_score": float(max(0.0, min(1.0, similarity)) * weight),
            }
        return breakdown

    def score(self, *, current: dict[str, float], existing: dict[str, float]) -> float:
        breakdown = self.score_breakdown(current=current, existing=existing)
        return self._score_from_breakdown(breakdown)

    def ranked_matches(
        self,
        *,
        current: dict[str, float],
        profiles: dict[str, dict[str, float]],
        limit: int = 5,
        include_breakdown: bool = True,
    ) -> list[MatchResult]:
        safe_limit = max(1, min(1000, int(limit)))
        ranked: list[MatchResult] = []
        for profile_id, metrics in profiles.items():
            breakdown = self.score_breakdown(current=current, existing=metrics)
            score = self._score_from_breakdown(breakdown)
            ranked.append(
                MatchResult(
                    profile_id=profile_id,
                    score=score,
                    breakdown=breakdown if include_breakdown else {},
                )
            )
        ranked.sort(key=lambda item: item.score, reverse=True)
        return ranked[:safe_limit]

    def match(
        self,
        *,
        current: dict[str, float],
        profiles: dict[str, dict[str, float]],
    ) -> MatchResult | None:
        ranked = self.ranked_matches(current=current, profiles=profiles, limit=1, include_breakdown=True)
        best = ranked[0] if ranked else None
        if best is None or best.score < self.threshold:
            return None
        return best

    @staticmethod
    def _score_from_breakdown(breakdown: dict[str, dict[str, float]]) -> float:
        total = sum(item["weighted_score"] for item in breakdown.values())
        return max(0.0, min(1.0, total))
