import asyncio
import json
import pytest
from vulngraph.cli import analyze_file
from vulngraph.sbom import InputError
from vulngraph.demo import DEMO_SBOM


def test_demo_file_cannot_claim_live_checks():
    with pytest.raises(InputError, match="demo fixture"):
        asyncio.run(analyze_file(DEMO_SBOM, online=True))


def test_cli_report_preserves_synthetic_disclaimer(tmp_path):
    r=asyncio.run(analyze_file(DEMO_SBOM))
    assert r["demo"] is True
    assert r["summary"]["findings"]==8
    assert "Synthetic" in r["sources"][0]


def test_cli_real_sbom(tmp_path,small_sbom):
    f=tmp_path/"bom.json"
    f.write_text(json.dumps(small_sbom))
    r=asyncio.run(analyze_file(f,criticality=2,internet_facing=True))
    assert r["demo"] is False
    assert r["summary"]["findings"]==1
    assert r["context"]["business_criticality"]==2
