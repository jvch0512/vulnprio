from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import report
from .loaders import load_epss, load_findings, load_kev
from .scoring import score_finding

FORMATS = {"json": report.to_json, "csv": report.to_csv, "md": report.to_markdown, "html": report.to_html}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vulnprio", description="Prioritize vulnerabilities by real-world risk.")
    p.add_argument("findings", help="findings file (.json or .csv)")
    p.add_argument("--epss", required=True, help="EPSS CSV (cve,epss)")
    p.add_argument("--kev", required=True, help="CISA KEV JSON feed")
    p.add_argument("--format", choices=sorted(FORMATS), default="md")
    p.add_argument("-o", "--output", help="write report to this file (default: stdout)")
    p.add_argument("--min-priority", choices=["P0", "P1", "P2", "P3"], default="P3",
                   help="only include findings at or above this priority")
    p.add_argument("--fail-on", choices=["P0", "P1"], help="exit with code 2 if any finding at or above this priority exists (CI gate)")
    return p


def run(args: argparse.Namespace) -> int:
    findings = load_findings(args.findings)
    epss = load_epss(args.epss)
    kev = load_kev(args.kev)

    scored = [score_finding(f, epss.get(f.cve, 0.0), f.cve in kev) for f in findings]
    scored.sort(key=lambda s: (-s.score, s.finding.cve, s.finding.asset))
    scored = [s for s in scored if s.priority <= args.min_priority]

    out = FORMATS[args.format](scored)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out)

    if args.fail_on and any(s.priority <= args.fail_on for s in scored):
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
