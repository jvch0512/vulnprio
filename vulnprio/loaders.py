from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import Finding


def load_findings(path: str | Path) -> list[Finding]:
    """Load findings from a JSON list or a CSV file."""
    p = Path(path)
    if p.suffix.lower() == ".csv":
        with p.open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
    else:
        rows = json.loads(p.read_text(encoding="utf-8"))
    out = []
    for r in rows:
        out.append(
            Finding(
                cve=r["cve"].strip().upper(),
                asset=r["asset"].strip(),
                cvss=float(r["cvss"]),
                criticality=(r.get("criticality") or "medium").strip().lower(),
                exposure=(r.get("exposure") or "internal").strip().lower(),
                title=(r.get("title") or "").strip(),
            )
        )
    return out


def load_epss(path: str | Path) -> dict[str, float]:
    """CSV with columns cve,epss (the format of the public FIRST EPSS feed)."""
    with Path(path).open(newline="", encoding="utf-8") as fh:
        return {r["cve"].strip().upper(): float(r["epss"]) for r in csv.DictReader(fh)}


def load_kev(path: str | Path) -> set[str]:
    """CISA KEV JSON feed (uses the 'vulnerabilities' list with 'cveID')."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {v["cveID"].strip().upper() for v in data.get("vulnerabilities", [])}
