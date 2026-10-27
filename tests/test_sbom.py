import pytest
from vulngraph.sbom import InputError, parse_cyclonedx, parse_purl, safe_https


def test_sample_has_all_components(sample_sbom):
    inv, vulns = parse_cyclonedx(sample_sbom)
    assert len(inv.components) == 11
    assert len(vulns) == 8
    assert inv.name.startswith("Northstar Commerce")
    assert inv.components[0].depth == 1
    assert inv.components[1].depth == 2


def test_valid_small_bom(small_sbom):
    inv, vulns = parse_cyclonedx(small_sbom)
    assert inv.name == "Sample"
    assert inv.components[0].direct
    assert vulns[0].cvss == 7.8


@pytest.mark.parametrize("bad", [None, {}, {"bomFormat": "SPDX"}, {"bomFormat": "CycloneDX", "specVersion": "9"}])
def test_invalid_format(bad):
    with pytest.raises(InputError):
        parse_cyclonedx(bad)


def test_duplicate_bom_refs(small_sbom):
    small_sbom["components"].append(small_sbom["components"][0].copy())
    with pytest.raises(InputError, match="Duplicate"):
        parse_cyclonedx(small_sbom)


def test_oversized_inventory(small_sbom):
    small_sbom["components"] *= 251
    with pytest.raises(InputError, match="at most"):
        parse_cyclonedx(small_sbom)


def test_no_vulnerability_assertion(small_sbom):
    small_sbom.pop("vulnerabilities")
    inv, vulns = parse_cyclonedx(small_sbom)
    assert vulns == ()
    assert "No vulnerability" in inv.warnings[0]


def test_orphan_advisory_ignored(small_sbom):
    small_sbom["vulnerabilities"][0]["affects"] = [{"ref": "unknown"}]
    assert parse_cyclonedx(small_sbom)[1] == ()


def test_purl_variants():
    assert parse_purl("pkg:pypi/requests@2.1.0") == ("PyPI", "requests")
    assert parse_purl("pkg:npm/%40scope/name@1.0.0")[1] == "@scope/name"
    assert parse_purl("abc") == (None, None)


def test_safe_https():
    assert safe_https("https://example.org/advisory") == "https://example.org/advisory"
    assert safe_https("javascript:alert(1)") is None
    assert safe_https("http://example.org") is None
    assert safe_https("https://user:pass@example.org") is None


def test_cvss_rejects_bad_score(small_sbom):
    small_sbom["vulnerabilities"][0]["ratings"] = [{"score": "9.8"}, {"score": 400}]
    assert parse_cyclonedx(small_sbom)[1][0].cvss is None


def test_dependency_cycle_is_bounded(small_sbom):
    small_sbom["dependencies"].append({"ref": "one", "dependsOn": ["root", "one"]})
    inv, _ = parse_cyclonedx(small_sbom)
    assert len(inv.components) == 1


def test_bad_dependency_type(small_sbom):
    small_sbom["dependencies"] = ["not a dependency object"]
    with pytest.raises(InputError):
        parse_cyclonedx(small_sbom)


def test_alias_preserved_as_data(small_sbom):
    small_sbom["vulnerabilities"][0]["name"] = '<img src=x onerror=alert(1)>'
    _, adv = parse_cyclonedx(small_sbom)
    assert "onerror" in adv[0].title

@pytest.mark.parametrize("value", [None, [], "not a dict", {"component": None}])
def test_bad_metadata_is_validation_error(small_sbom, value):
    small_sbom["metadata"] = value
    with pytest.raises(InputError):
        parse_cyclonedx(small_sbom)


def test_bad_rating_is_nonfatal(small_sbom):
    small_sbom["vulnerabilities"][0]["ratings"] = None
    _, adv = parse_cyclonedx(small_sbom)
    assert adv[0].cvss is None


def test_malformed_url_cannot_crash():
    assert safe_https("https://[invalid-ipv6") is None
