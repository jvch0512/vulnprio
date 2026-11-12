from __future__ import annotations

import csv
import io
import json
from collections import Counter
from html import escape

from .models import ScoredFinding


def summary(items: list[ScoredFinding]) -> dict:
    c = Counter(i.priority for i in items)
    return {
        "total": len(items),
        "by_priority": {p: c.get(p, 0) for p in ("P0", "P1", "P2", "P3")},
        "kev": sum(1 for i in items if i.in_kev),
        "internet_facing": sum(1 for i in items if i.finding.exposure == "internet"),
    }


def to_json(items: list[ScoredFinding]) -> str:
    return json.dumps(
        {"summary": summary(items), "findings": [i.as_dict() for i in items]},
        indent=2,
        ensure_ascii=False,
    )


def to_csv(items: list[ScoredFinding]) -> str:
    buf = io.StringIO()
    cols = ["priority", "score", "cve", "asset", "cvss", "epss", "kev", "exposure", "criticality", "sla_days", "title"]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for i in items:
        w.writerow(i.as_dict())
    return buf.getvalue()


def to_markdown(items: list[ScoredFinding]) -> str:
    s = summary(items)
    lines = [
        "# Vulnerability prioritization report",
        "",
        f"**{s['total']} findings** | KEV: {s['kev']} | Internet-facing: {s['internet_facing']}",
        "",
        "| Priority | Count |",
        "|---|---|",
    ]
    lines += [f"| {p} | {n} |" for p, n in s["by_priority"].items()]
    lines += ["", "| Priority | Score | CVE | Asset | CVSS | EPSS | KEV | SLA (days) |", "|---|---|---|---|---|---|---|---|"]
    for i in items:
        d = i.as_dict()
        lines.append(
            f"| {d['priority']} | {d['score']} | {d['cve']} | {d['asset']} | {d['cvss']} | "
            f"{d['epss']:.2%} | {'yes' if d['kev'] else 'no'} | {d['sla_days']} |"
        )
    return "\n".join(lines) + "\n"


def to_html(items: list[ScoredFinding]) -> str:
    s = summary(items)
    color = {"P0": "#b91c1c", "P1": "#c2410c", "P2": "#a16207", "P3": "#15803d"}
    rows = []
    for i in items:
        d = i.as_dict()
        rows.append(
            "<tr>"
            f"<td><span class='pill' style='background:{color[d['priority']]}'>{d['priority']}</span></td>"
            f"<td>{d['score']}</td><td>{escape(d['cve'])}</td><td>{escape(d['asset'])}</td>"
            f"<td>{d['cvss']}</td><td>{d['epss']:.2%}</td><td>{'yes' if d['kev'] else 'no'}</td>"
            f"<td>{d['sla_days']}</td><td>{escape('; '.join(d['reasons']))}</td></tr>"
        )
    cards = "".join(
        f"<div class='card'><b style='color:{color[p]}'>{n}</b><span>{p}</span></div>"
        for p, n in s["by_priority"].items()
    )
    return f"""<!doctype html><meta charset="utf-8"><title>vulnprio report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;color:#111}}
.cards{{display:flex;gap:1rem;margin:1rem 0}}
.card{{border:1px solid #ddd;border-radius:10px;padding:.8rem 1.2rem;display:flex;flex-direction:column;min-width:80px}}
.card b{{font-size:1.8rem}}
table{{border-collapse:collapse;width:100%;font-size:.9rem}}
th,td{{border-bottom:1px solid #eee;padding:.45rem .6rem;text-align:left}}
.pill{{color:#fff;border-radius:999px;padding:.1rem .6rem;font-weight:600}}
</style>
<h1>Vulnerability prioritization report</h1>
<p>{s['total']} findings, {s['kev']} in CISA KEV, {s['internet_facing']} internet-facing.</p>
<div class="cards">{cards}</div>
<table><tr><th>Priority</th><th>Score</th><th>CVE</th><th>Asset</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>SLA days</th><th>Why</th></tr>
{''.join(rows)}</table>"""
