from __future__ import annotations

from dataclasses import dataclass, field

LEVELS = ["critical", "high", "medium", "unknown", "ok"]
SEVERITY = {"critical": 3, "high": 2, "medium": 1, "unknown": 0, "ok": 0}


@dataclass
class CheckResult:
    rows: list[dict]
    source: str
    window_days: int
    findings: list[dict] = field(default_factory=list)
    unavailable_signals: list[str] = field(default_factory=list)

    @property
    def degraded(self) -> list[str]:
        return self.unavailable_signals

    def counts(self) -> dict[str, int]:
        return {level: sum(r["risk_level"] == level for r in self.rows) for level in LEVELS}

    def worst(self) -> int:
        return max((SEVERITY[r["risk_level"]] for r in self.rows), default=0)
