"""Scoring model.

The score blends three signals on a 0-100 scale:

* severity   (CVSS base score, 0-10)
* likelihood (EPSS probability of exploitation in the next 30 days, 0-1)
* context    (asset criticality and internet exposure)

A CVE listed in the CISA Known Exploited Vulnerabilities (KEV) catalog is
treated as an override: exploitation is confirmed, so it is always P0 for
internet-facing assets and at least P1 elsewhere.
"""
from __future__ import annotations

from .models import Finding, ScoredFinding

CRITICALITY_WEIGHT = {"low": 0.4, "medium": 0.7, "high": 1.0, "critical": 1.3}
EXPOSURE_WEIGHT = {"internal": 1.0, "internet": 1.25}

# (minimum score, label, SLA in days)
BUCKETS = [(75.0, "P0", 3), (50.0, "P1", 14), (25.0, "P2", 45), (0.0, "P3", 90)]

W_SEVERITY = 0.40
W_LIKELIHOOD = 0.45
W_CONTEXT = 0.15


def _bucket(score: float) -> tuple[str, int]:
    for threshold, label, sla in BUCKETS:
        if score >= threshold:
            return label, sla
    return "P3", 90


def score_finding(f: Finding, epss: float, in_kev: bool) -> ScoredFinding:
    if not 0.0 <= f.cvss <= 10.0:
        raise ValueError(f"CVSS out of range for {f.cve}: {f.cvss}")
    if not 0.0 <= epss <= 1.0:
        raise ValueError(f"EPSS out of range for {f.cve}: {epss}")

    crit = CRITICALITY_WEIGHT.get(f.criticality.lower(), 0.7)
    expo = EXPOSURE_WEIGHT.get(f.exposure.lower(), 1.0)

    severity = f.cvss / 10.0
    context = min(1.0, (crit * expo) / (1.3 * 1.25))
    raw = W_SEVERITY * severity + W_LIKELIHOOD * epss + W_CONTEXT * context
    score = round(raw * 100.0, 2)

    reasons = [f"CVSS {f.cvss}", f"EPSS {epss:.1%}"]
    if f.exposure.lower() == "internet":
        reasons.append("internet-facing")
    if f.criticality.lower() in ("high", "critical"):
        reasons.append(f"{f.criticality.lower()} asset")

    priority, sla = _bucket(score)

    if in_kev:
        reasons.append("listed in CISA KEV (exploited in the wild)")
        floor = "P0" if f.exposure.lower() == "internet" else "P1"
        if priority > floor:  # "P3" > "P1" lexicographically means less urgent
            priority = floor
            sla = {"P0": 3, "P1": 14}[floor]
        score = max(score, 75.0 if floor == "P0" else 50.0)

    return ScoredFinding(f, epss, in_kev, score, priority, sla, reasons)
