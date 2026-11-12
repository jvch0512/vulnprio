# vulnprio

Risk-based vulnerability prioritization. Instead of sorting a scanner export by CVSS alone, `vulnprio` combines **severity (CVSS)**, **likelihood of exploitation (EPSS)**, **confirmed exploitation (CISA KEV)** and **asset context** (criticality and internet exposure) into one score, a priority bucket (P0 to P3) and an SLA in days.

Zero runtime dependencies. Python 3.10+.

## Why

A CVSS 9.8 on an isolated build agent with a 1% exploitation probability is not the same risk as a CVSS 7.5 on an internet-facing system with a public exploit. Teams that patch by CVSS alone burn their budget on noise. This tool makes the reasoning explicit and auditable: every finding carries the reasons behind its priority.

## Quick start

```bash
pip install -e .
vulnprio data/sample_findings.json --epss data/sample_epss.csv --kev data/sample_kev.json --format md
```

Output formats: `md`, `html` (standalone report with summary cards), `json`, `csv`.

### Use it as a CI gate

```bash
vulnprio findings.csv --epss epss.csv --kev kev.json --format json --fail-on P0 -o report.json
# exit code 2 when any P0 finding exists
```

## Scoring model

```
score = 100 * (0.40 * CVSS/10  +  0.45 * EPSS  +  0.15 * context)
context = (criticality_weight * exposure_weight) / max_possible
```

| Bucket | Score | SLA |
|---|---|---|
| P0 | >= 75 | 3 days |
| P1 | >= 50 | 14 days |
| P2 | >= 25 | 45 days |
| P3 | < 25 | 90 days |

**KEV override:** a CVE in the CISA KEV catalog is confirmed exploited, so it is P0 on internet-facing assets and at least P1 elsewhere, whatever the formula says.

Weights live in `vulnprio/scoring.py` and are meant to be tuned to your risk appetite.

## Input formats

* Findings: JSON list or CSV with `cve, asset, cvss, criticality, exposure, title`
* EPSS: CSV `cve,epss` (same shape as the public FIRST.org EPSS feed)
* KEV: the CISA KEV JSON feed (`vulnerabilities[].cveID`)

> The files in `data/` are small illustrative samples for demos and tests. EPSS values there are not live data. For real use, download the current feeds from FIRST.org and CISA.

## Development

```bash
pip install -e .[dev]
pytest -q
```

## Design notes

* Scoring is pure and deterministic, which makes it trivial to unit test and to explain in an audit.
* Loaders are separated from scoring so new sources (Qualys, Nessus, ManageEngine Vulnerability Manager exports) only need a new loader.
* Possible next steps: live feed refresh, SSVC decision trees, ticket creation (Jira/ServiceNow) per P0.

## License

MIT
