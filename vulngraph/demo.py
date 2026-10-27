"""Reproducible and prominently labeled illustrative demo, never real CVE claims."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from .engine import build_report
from .models import Analysis, Context
from .sbom import parse_cyclonedx

DEMO_SBOM = Path(__file__).resolve().parent.parent / "demo" / "demo-sbom.cdx.json"
FAKE_ENRICHMENT = {
    "DEMO-VULN-001": {"epss": .91, "kev": True},
    "DEMO-VULN-002": {"epss": .69, "kev": False},
    "DEMO-VULN-003": {"epss": .13, "kev": True},
    "DEMO-VULN-004": {"epss": .82, "kev": True},
    "DEMO-VULN-005": {"epss": .05, "kev": False},
    "DEMO-VULN-006": {"epss": .01, "kev": False},
    "DEMO-VULN-007": {"epss": .08, "kev": False},
    "DEMO-VULN-008": {"epss": .32, "kev": False},
}


def sample_report(internet_facing: bool = True, business_criticality: int = 4) -> dict:
    raw = json.loads(DEMO_SBOM.read_text(encoding="utf-8"))
    inventory, advisories = parse_cyclonedx(raw)
    enriched = tuple(replace(a, **FAKE_ENRICHMENT.get(a.identifier, {}), source="SYNTHETIC DEMO") for a in advisories)
    report = build_report(Analysis(inventory, enriched, Context(internet_facing, business_criticality),
                                   is_demo=True, data_sources=("Synthetic illustrative scenario (not live data)",)))
    for finding in report["findings"]:
        for factor in finding["factors"]:
            if factor["key"] in {"cvss", "epss", "kev"}:
                factor["evidence"] = "synthetic illustrative value"
    return report
