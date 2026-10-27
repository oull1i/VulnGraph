import json
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from vulngraph.server import app, MAX_BODY


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c


@pytest.mark.asyncio
async def test_home(client):
    response = await client.get("/")
    assert response.status_code == 200
    assert "VulnGraph" in response.text
    assert "'self'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert "no-store" in response.headers["cache-control"]


@pytest.mark.asyncio
async def test_health(client):
    r = await client.get("/api/health")
    assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_demo_endpoint(client):
    r = await client.get("/api/demo?internet_facing=false&business_criticality=2")
    assert r.status_code == 200
    assert r.json()["demo"] is True
    assert r.json()["context"]["business_criticality"] == 2


@pytest.mark.asyncio
async def test_demo_rejects_invalid_context(client):
    r = await client.get("/api/demo?business_criticality=99")
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_analyze_user_supplied_sbom(client, small_sbom):
    r = await client.post("/api/analyze", json={"sbom": small_sbom})
    assert r.status_code == 200, r.text
    obj=r.json()
    assert obj["demo"] is False
    assert obj["summary"]["findings"] == 1
    assert obj["findings"][0]["source"] == "sbom"


@pytest.mark.asyncio
async def test_malformed_json(client):
    r = await client.post("/api/analyze", content="{not json}", headers={"Content-Type":"application/json"})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_wrong_content_type(client):
    r = await client.post("/api/analyze", content="{}", headers={"Content-Type":"text/plain"})
    assert r.status_code == 415


@pytest.mark.asyncio
async def test_oversized_payload(client):
    r = await client.post("/api/analyze", content=b" "*(MAX_BODY+1),headers={"Content-Type":"application/json"})
    assert r.status_code == 413


@pytest.mark.asyncio
@pytest.mark.parametrize("context",[{"internet_facing":"yes"},{"business_criticality":0},{"business_criticality":True},None])
async def test_context_validation(client,small_sbom,context):
    r=await client.post("/api/analyze",json={"sbom":small_sbom,"context":context})
    assert r.status_code==422


@pytest.mark.asyncio
async def test_disallowed_mode(client,small_sbom):
    r=await client.post("/api/analyze",json={"sbom":small_sbom,"mode":"scan-internet"})
    assert r.status_code==422


@pytest.mark.asyncio
async def test_security_no_cors_and_non_persistent(client,small_sbom):
    r=await client.post("/api/analyze",json={"sbom":small_sbom})
    assert r.status_code==200
    assert "access-control-allow-origin" not in r.headers
    assert not any(x.startswith("Set-Cookie") for x in r.headers)


@pytest.mark.asyncio
async def test_live_mode_is_opt_in_and_mocked(client,small_sbom,monkeypatch):
    from vulngraph.models import Advisory
    async def mock_enrich(components):
        return (Advisory("CVE-2026-99999","Test",("one",),cvss=9.8,epss=.5,kev=True,source="OSV"),),()
    monkeypatch.setattr("vulngraph.server.enrich_osv",mock_enrich)
    r=await client.post("/api/analyze",json={"sbom":small_sbom,"mode":"osv"})
    assert r.status_code==200
    assert any(f["source"]=="OSV" for f in r.json()["findings"]) is False  # same ID/ref: SBOM record kept first
    assert r.json()["summary"]["findings"]==1

@pytest.mark.asyncio
async def test_importing_demo_sbom_preserves_demo_label(client,sample_sbom):
    r=await client.post("/api/analyze",json={"sbom":sample_sbom})
    assert r.status_code==200
    assert r.json()["demo"] is True
    assert r.json()["findings"][0]["source"]=="sbom"


@pytest.mark.asyncio
async def test_demo_sbom_cannot_mix_with_osv(client,sample_sbom):
    r=await client.post("/api/analyze",json={"sbom":sample_sbom,"mode":"osv"})
    assert r.status_code==422
