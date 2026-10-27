"""Explicit opt-in read-only enrichment against fixed trusted public endpoints."""
from __future__ import annotations

import asyncio
import json
import re

import httpx

from .cvss import cvss3_base
from .models import Advisory, Component
from .sbom import safe_https, string

OSV_API = "https://api.osv.dev"
EPSS_API = "https://api.first.org"
KEV_API = "https://www.cisa.gov"
KEV_PATH = "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
MAX_OSV_LOOKUPS = 100
MAX_DETAIL = 120


class UpstreamError(RuntimeError):
    pass


async def _get_json(client: httpx.AsyncClient, url: str, *, max_bytes: int = 2_500_000, params: dict | None = None) -> dict:
    async with client.stream("GET", url, params=params) as response:
        response.raise_for_status()
        size = 0
        body = bytearray()
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > max_bytes:
                raise UpstreamError("Public data response was too large.")
            body.extend(chunk)
        data = json.loads(body)
        if not isinstance(data, dict):
            raise UpstreamError("Upstream returned an invalid JSON object.")
        return data


async def _post_json(client: httpx.AsyncClient, url: str, payload: dict) -> dict:
    async with client.stream("POST", url, json=payload) as response:
        response.raise_for_status()
        body = bytearray()
        async for chunk in response.aiter_bytes():
            if len(body) + len(chunk) > 2_500_000:
                raise UpstreamError("OSV query response was too large.")
            body.extend(chunk)
    data = json.loads(body)
    if not isinstance(data, dict):
        raise UpstreamError("OSV returned an invalid JSON object.")
    return data


def _parse_detail(raw: dict, ref: str, *, package: Component | None = None) -> Advisory | None:
    ident = string(raw.get("id"), 100)
    if not ident:
        return None
    aliases = tuple(string(s, 100) for s in raw.get("aliases", [])[:20] if isinstance(s, str)) if isinstance(raw.get("aliases"), list) else ()
    metrics = []
    if isinstance(raw.get("severity"), list):
        metrics.extend(cvss3_base(s.get("score", "")) for s in raw["severity"] if isinstance(s, dict))
    metrics = [s for s in metrics if s is not None]
    links = raw.get("references", [])
    link = next((url for record in links if isinstance(record, dict) and (url := safe_https(record.get("url")))), None) if isinstance(links, list) else None
    if not link:
        link = safe_https(f"https://osv.dev/vulnerability/{ident}")
    fixed = None
    for affected in raw.get("affected", [])[:30] if isinstance(raw.get("affected"), list) else []:
        if not isinstance(affected, dict):
            continue
        affected_pkg = affected.get("package", {})
        if package is not None:
            if not isinstance(affected_pkg, dict):
                continue
            their_purl = affected_pkg.get("purl")
            if their_purl and package.purl and their_purl.split("@", 1)[0] != package.purl.split("@", 1)[0]:
                continue
            if not their_purl and (str(affected_pkg.get("name") or "").lower() != package.name.lower() or affected_pkg.get("ecosystem") != package.ecosystem):
                continue
        for rng in affected.get("ranges", [])[:30] if isinstance(affected.get("ranges"), list) else []:
            for event in rng.get("events", [])[:30] if isinstance(rng, dict) else []:
                if isinstance(event, dict) and event.get("fixed"):
                    fixed = string(event["fixed"], 90)
                    break
            if fixed:
                break
        if fixed:
            break
    return Advisory(identifier=ident, aliases=aliases, title=string(raw.get("summary"), 160) or ident,
                    refs=(ref,), cvss=max(metrics) if metrics else None,
                    link=link, fixed_version=fixed, description=string(raw.get("details"), 600), source="OSV")


async def enrich_osv(components: tuple[Component, ...], *, client: httpx.AsyncClient | None = None) -> tuple[tuple[Advisory, ...], tuple[str, ...]]:
    """Query package versions against OSV, then optionally enrich known CVEs with EPSS and KEV."""
    own = client is None
    if own:
        client = httpx.AsyncClient(timeout=httpx.Timeout(12.0), follow_redirects=False,
                                   headers={"User-Agent": "VulnGraph/1.0 (+defensive-sbom-triage)"})
    assert client is not None
    warnings = []
    try:
        eligible = [c for c in components if c.purl and c.ecosystem and c.version != "unknown"][:MAX_OSV_LOOKUPS]
        total = sum(bool(c.purl and c.ecosystem and c.version != "unknown") for c in components)
        if total > MAX_OSV_LOOKUPS:
            warnings.append(f"OSV lookup is limited to the first {MAX_OSV_LOOKUPS} eligible packages.")
        if not eligible:
            return (), ("No versioned and supported package URLs are available for OSV lookup.",)
        queries = [{"package": {"purl": c.purl}} for c in eligible]
        try:
            response = await _post_json(client, f"{OSV_API}/v1/querybatch", {"queries": queries})
        except (httpx.HTTPError, ValueError, UpstreamError) as exc:
            return (), (f"OSV request failed: {type(exc).__name__}. No online vulnerabilities were returned.",)
        results = response.get("results", [])
        if not isinstance(results, list) or len(results) != len(eligible):
            return (), ("OSV returned an unexpected result count; no findings were accepted.",)
        pairs = []
        for c, item in zip(eligible, results):
            if not isinstance(item, dict):
                continue
            if item.get("next_page_token"):
                warnings.append(f"OSV results for {c.name} may be incomplete due to pagination.")
            for vuln in item.get("vulns", [])[:100] if isinstance(item.get("vulns"), list) else []:
                ident = string(vuln.get("id"), 100) if isinstance(vuln, dict) else ""
                if ident and re.fullmatch(r"[A-Za-z0-9._-]{3,100}", ident):
                    pairs.append((ident, c.ref))
        unique = list(dict.fromkeys(pairs))
        component_by_ref = {c.ref: c for c in eligible}
        if len(unique) > MAX_DETAIL:
            warnings.append(f"Advisory detail retrieval was capped at {MAX_DETAIL} matches.")
            unique = unique[:MAX_DETAIL]
        sem = asyncio.Semaphore(8)

        async def load(ident: str, ref: str):
            async with sem:
                try:
                    import urllib.parse
                    doc = await _get_json(client, f"{OSV_API}/v1/vulns/{urllib.parse.quote(ident, safe='')}")
                    return _parse_detail(doc, ref, package=component_by_ref.get(ref))
                except (httpx.HTTPError, ValueError, UpstreamError, TypeError):
                    return None
        found = await asyncio.gather(*(load(i, ref) for i, ref in unique))
        adv = [a for a in found if a]
        if len(adv) < len(unique):
            warnings.append("Some OSV details could not be fetched; results may be incomplete.")
        # Optional enrichments: errors degrade gracefully and never invent data.
        cves = sorted({alias.upper() for a in adv for alias in (a.identifier, *a.aliases) if CVE_ID.fullmatch(alias.upper())})
        epss_scores = {}
        kev_cves = set()
        if cves:
            try:
                for i in range(0, min(len(cves), 100), 20):
                    data = await _get_json(client, f"{EPSS_API}/data/v1/epss", params={"cve": ",".join(cves[i:i+20])})
                    for record in data.get("data", []):
                        if not isinstance(record, dict):
                            continue
                        score = float(record.get("epss", "nan"))
                        if CVE_ID.fullmatch(str(record.get("cve", ""))) and 0 <= score <= 1:
                            epss_scores[record["cve"].upper()] = score
            except (httpx.HTTPError, ValueError, UpstreamError, TypeError):
                warnings.append("EPSS scores unavailable from FIRST; omitted, not estimated.")
            try:
                data = await _get_json(client, f"{KEV_API}{KEV_PATH}", max_bytes=6_000_000)
                for record in data.get("vulnerabilities", []):
                    if isinstance(record, dict):
                        cve = string(record.get("cveID"), 40).upper()
                        if CVE_ID.fullmatch(cve):
                            kev_cves.add(cve)
            except (httpx.HTTPError, ValueError, UpstreamError, TypeError):
                warnings.append("CISA KEV catalog unavailable; absence is not evidence of non-exploitation.")
        from dataclasses import replace
        enriched = []
        for a in adv:
            ids = [s.upper() for s in (a.identifier, *a.aliases) if CVE_ID.fullmatch(s.upper())]
            epss = max((epss_scores[id] for id in ids if id in epss_scores), default=None)
            enriched.append(replace(a, epss=epss, kev=any(id in kev_cves for id in ids)))
        return tuple(enriched), tuple(dict.fromkeys(warnings))
    finally:
        if own:
            await client.aclose()
