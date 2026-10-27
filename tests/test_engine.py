from vulngraph.demo import sample_report
from vulngraph.engine import build_report
from vulngraph.models import Advisory, Analysis, Context
from vulngraph.sbom import parse_cyclonedx


def test_demo_is_explicitly_fake():
    r = sample_report()
    assert r["demo"] is True
    assert len(r["findings"]) == 8
    assert all(f["id"].startswith("DEMO-") for f in r["findings"])
    assert "DEMO DATA" in r["warnings"][0]
    assert r["summary"]["findings"] == sum(r["summary"][x] for x in ("critical", "high", "medium", "low"))


def test_demo_has_explainable_top_score():
    r = sample_report()
    assert r["findings"][0]["score"] >= r["findings"][-1]["score"]
    assert r["summary"]["highest_score"] == r["findings"][0]["score"]


def test_demo_context_is_dynamic():
    high = sample_report(True, 5)
    low = sample_report(False, 1)
    assert high["summary"]["highest_score"] == low["summary"]["highest_score"] + 15


def test_deduplicates_same_id_package(small_sbom):
    inv, advisories = parse_cyclonedx(small_sbom)
    report = build_report(Analysis(inv, advisories * 2, Context()))
    assert report["summary"]["findings"] == 1


def test_sbom_inventory_only(small_sbom):
    small_sbom["vulnerabilities"] = []
    inv, advisories = parse_cyclonedx(small_sbom)
    report = build_report(Analysis(inv, advisories, Context()))
    assert report["findings"] == []
    assert report["summary"]["affected_packages"] == 0
    assert "inventory-only" in " ".join(report["warnings"])


def test_multiple_affected_packages(small_sbom):
    small_sbom["components"].append({"bom-ref":"second","name":"second","version":"1"})
    small_sbom["vulnerabilities"][0]["affects"]=[{"ref":"one"},{"ref":"second"}]
    inv, advisories = parse_cyclonedx(small_sbom)
    report=build_report(Analysis(inv, advisories, Context()))
    assert report["summary"]["findings"]==2
    assert report["summary"]["affected_packages"]==2
