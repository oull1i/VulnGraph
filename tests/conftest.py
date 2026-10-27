import copy
import json
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def sample_sbom():
    return json.loads((ROOT / "demo" / "demo-sbom.cdx.json").read_text())


@pytest.fixture
def small_sbom():
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "metadata": {"component": {"bom-ref": "root", "name": "Sample"}},
        "components": [{"bom-ref": "one", "name": "jinja2", "version": "3.1.3", "purl": "pkg:pypi/jinja2@3.1.3"}],
        "dependencies": [{"ref": "root", "dependsOn": ["one"]}],
        "vulnerabilities": [{"id": "CVE-2026-99999", "ratings": [{"score": 7.8}], "affects": [{"ref": "one"}]}],
    }
