import pytest

from vulnprio.models import Finding
from vulnprio.scoring import score_finding


def f(cvss=7.0, crit="medium", expo="internal"):
    return Finding("CVE-2024-0001", "host", cvss, crit, expo)


def test_kev_internet_is_p0():
    s = score_finding(f(cvss=5.0, crit="low", expo="internet"), epss=0.01, in_kev=True)
    assert s.priority == "P0" and s.sla_days == 3


def test_kev_internal_is_at_least_p1():
    s = score_finding(f(cvss=4.0, crit="low", expo="internal"), epss=0.01, in_kev=True)
    assert s.priority in ("P0", "P1")


def test_high_epss_beats_high_cvss_low_epss():
    noisy = score_finding(f(cvss=9.8), epss=0.001, in_kev=False)
    real = score_finding(f(cvss=7.0), epss=0.90, in_kev=False)
    assert real.score > noisy.score


def test_low_risk_is_p3():
    s = score_finding(f(cvss=3.0, crit="low"), epss=0.0005, in_kev=False)
    assert s.priority == "P3" and s.sla_days == 90


def test_internet_exposure_raises_score():
    a = score_finding(f(expo="internal"), 0.2, False)
    b = score_finding(f(expo="internet"), 0.2, False)
    assert b.score > a.score


@pytest.mark.parametrize("cvss,epss", [(-1, 0.1), (11, 0.1), (5, -0.1), (5, 1.1)])
def test_invalid_inputs_rejected(cvss, epss):
    with pytest.raises(ValueError):
        score_finding(f(cvss=cvss), epss, False)
