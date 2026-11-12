from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Finding:
    """A single vulnerability finding on one asset."""

    cve: str
    asset: str
    cvss: float
    criticality: str = "medium"      # low | medium | high | critical
    exposure: str = "internal"       # internal | internet
    title: str = ""


@dataclass
class ScoredFinding:
    finding: Finding
    epss: float
    in_kev: bool
    score: float
    priority: str                    # P0..P3
    sla_days: int
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        f = self.finding
        return {
            "cve": f.cve,
            "asset": f.asset,
            "title": f.title,
            "cvss": f.cvss,
            "epss": round(self.epss, 4),
            "kev": self.in_kev,
            "criticality": f.criticality,
            "exposure": f.exposure,
            "score": round(self.score, 2),
            "priority": self.priority,
            "sla_days": self.sla_days,
            "reasons": self.reasons,
        }
