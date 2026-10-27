import pytest
from vulngraph.cvss import cvss3_base
from vulngraph.models import Advisory, Context
from vulngraph.scoring import rank


def vuln(cvss=None, epss=None, kev=False):
    return Advisory("CVE-2026-12345", "Test", ("pkg",), cvss=cvss, epss=epss, kev=kev)


@pytest.mark.parametrize("vector,expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss3_known_vectors(vector, expected):
    assert cvss3_base(vector) == expected


def test_unsupported_cvss4():
    assert cvss3_base("CVSS:4.0/AV:N") is None


def test_invalid_cvss():
    assert cvss3_base("CVSS:3.1/AV:invalid") is None


def test_score_exact_breakdown():
    r = rank(vuln(9, .8, True), Context(True, 5))
    assert r["score"] == 91.5  # 31.5 + 20 + 25 + 10 + 5
    assert r["level"] == "critical"
    assert r["missing"] == []
    assert sum(f["points"] for f in r["factors"]) == r["score"]


def test_missing_signals_never_invented():
    r = rank(vuln(), Context(False, 1))
    assert r["score"] == 0
    assert r["missing"] == ["CVSS", "EPSS"]


def test_context_changes_score():
    v = vuln(8, .2)
    assert rank(v, Context(True, 5))["score"] - rank(v, Context(False, 1))["score"] == 15


def test_classification_bounds():
    assert rank(vuln(10), Context(False, 1))["level"] == "medium"
    assert rank(vuln(10, 1), Context(False, 1))["level"] == "high"
    assert rank(vuln(10, 1, True), Context(False, 1))["level"] == "critical"
