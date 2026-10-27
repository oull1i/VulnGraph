import json
import pytest
import httpx
from vulngraph.models import Component
from vulngraph.osv import enrich_osv, _parse_detail


@pytest.mark.asyncio
async def test_osv_mocked_integration():
    calls=[]
    def responder(request: httpx.Request):
        calls.append(str(request.url))
        if request.url.path.endswith("querybatch"):
            assert request.method=="POST"
            assert json.loads(request.content)["queries"][0]["package"]["purl"]=="pkg:pypi/testlib@1.0"
            return httpx.Response(200,json={"results":[{"vulns":[{"id":"OSV-2026-SYNTHETIC"}]}]})
        if "vulns" in request.url.path:
            return httpx.Response(200,json={"id":"OSV-2026-SYNTHETIC","summary":"Unit test advisory","aliases":["CVE-2026-12345"],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"references":[{"url":"https://osv.dev/vulnerability/OSV-2026-SYNTHETIC"}]})
        if "epss" in request.url.path:
            return httpx.Response(200,json={"data":[{"cve":"CVE-2026-12345","epss":"0.810"}]})
        if "known_exploited" in request.url.path:
            return httpx.Response(200,json={"vulnerabilities":[{"cveID":"CVE-2026-12345"}]})
        return httpx.Response(404)
    async with httpx.AsyncClient(transport=httpx.MockTransport(responder)) as client:
        results,warnings=await enrich_osv((Component("c1","testlib","1.0","pkg:pypi/testlib@1.0","PyPI"),),client=client)
    assert warnings==()
    assert len(results)==1
    assert results[0].cvss==9.8
    assert results[0].epss==.81
    assert results[0].kev is True
    assert len(calls)==4


@pytest.mark.asyncio
async def test_osv_empty_eligible_no_network():
    results, warnings=await enrich_osv((Component("one","lib","unknown",None,None),))
    assert results==()
    assert "No versioned" in warnings[0]


@pytest.mark.asyncio
async def test_osv_failure_is_not_fabricated():
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(503))) as client:
        results,warnings=await enrich_osv((Component("c","lib","1","pkg:pypi/lib@1","PyPI"),),client=client)
    assert results==()
    assert "OSV request failed" in warnings[0]


def test_osv_detail_rejects_invalid_link():
    doc={"id":"GHSA-aaaa-bbbb-cccc","references":[{"url":"javascript:alert(1)"}]}
    result=_parse_detail(doc,"p")
    assert result.link.startswith("https://osv.dev/")


@pytest.mark.asyncio
async def test_osv_missing_epss_and_kev_warning():
    def handler(r):
        if r.method=="POST": return httpx.Response(200,json={"results":[{"vulns":[{"id":"GHSA-test-1234-abcd"}]}]})
        if "/v1/vulns" in r.url.path:return httpx.Response(200,json={"id":"GHSA-test-1234-abcd","aliases":["CVE-2026-55555"]})
        return httpx.Response(503)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        results, warnings=await enrich_osv((Component("c","x","1","pkg:npm/x@1","npm"),),client=client)
    assert len(results)==1
    assert results[0].epss is None
    assert results[0].kev is False
    assert len(warnings)==2


def test_fix_does_not_cross_package_boundaries():
    raw={"id":"GHSA-test-fix-scope","affected":[
        {"package":{"name":"other","ecosystem":"PyPI"},"ranges":[{"events":[{"fixed":"2.0"}]}]},
        {"package":{"name":"testlib","ecosystem":"PyPI"},"ranges":[{"events":[{"fixed":"1.2"}]}]}
    ]}
    c=Component("c","testlib","1.0","pkg:pypi/testlib@1.0","PyPI")
    assert _parse_detail(raw,"c",package=c).fixed_version=="1.2"
