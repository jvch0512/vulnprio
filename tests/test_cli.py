import json
from pathlib import Path

from vulnprio.cli import main

D = Path(__file__).parent.parent / "data"
ARGS = [str(D / "sample_findings.json"), "--epss", str(D / "sample_epss.csv"), "--kev", str(D / "sample_kev.json")]


def test_json_output_sorted(tmp_path):
    out = tmp_path / "r.json"
    assert main(ARGS + ["--format", "json", "-o", str(out)]) == 0
    data = json.loads(out.read_text())
    scores = [x["score"] for x in data["findings"]]
    assert scores == sorted(scores, reverse=True)
    assert data["summary"]["total"] == 9


def test_fail_on_gate():
    assert main(ARGS + ["--format", "json", "-o", "/dev/null", "--fail-on", "P0"]) == 2


def test_min_priority_filter(tmp_path):
    out = tmp_path / "r.json"
    main(ARGS + ["--format", "json", "--min-priority", "P1", "-o", str(out)])
    assert all(x["priority"] in ("P0", "P1") for x in json.loads(out.read_text())["findings"])


def test_html_and_csv_render(tmp_path):
    for fmt in ("html", "csv", "md"):
        out = tmp_path / f"r.{fmt}"
        assert main(ARGS + ["--format", fmt, "-o", str(out)]) == 0
        assert out.stat().st_size > 100
