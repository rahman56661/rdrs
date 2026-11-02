"""Transparent weighted threat scoring (0-100) with per-signal explanation."""

from __future__ import annotations

from dataclasses import dataclass, field

NORMAL, WARNING, CRITICAL = "Normal", "Warning", "Critical"


@dataclass(frozen=True, slots=True)
class Signal:
    """One detection signal: did it fire, and why."""

    name: str
    fired: bool
    reason: str = ""


@dataclass(slots=True)
class ScoreResult:
    """Final score plus the breakdown that explains every point."""

    score: int
    level: str
    breakdown: dict[str, dict] = field(default_factory=dict)  # name -> {points, reason}

    def explain(self) -> str:
        """Human-readable explanation, e.g. 'rapid_encryption +40 | mass_rename +30 = 70/100 (Critical)'."""
        parts = " | ".join(f"{k} +{v['points']}" for k, v in self.breakdown.items()) or "no signals"
        return f"{parts} = {self.score}/100 ({self.level})"


def level_for(score: int, levels: dict[str, int]) -> str:
    """Map a score to Normal / Warning / Critical using the configured bands."""
    if score >= levels["critical"]:
        return CRITICAL
    if score >= levels["warning"]:
        return WARNING
    return NORMAL


def compute_score(signals: list[Signal], weights: dict[str, int], levels: dict[str, int]) -> ScoreResult:
    """Add the weights of fired signals, cap at 100, and attach the explanation."""
    breakdown = {s.name: {"points": int(weights.get(s.name, 0)), "reason": s.reason} for s in signals if s.fired}
    score = min(100, sum(v["points"] for v in breakdown.values()))
    return ScoreResult(score=score, level=level_for(score, levels), breakdown=breakdown)
