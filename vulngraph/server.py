"""Read-only API and private-by-default web UI."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from .demo import sample_report
from .cli import is_demo_fixture
from .engine import build_report
from .models import Analysis, Context
from .osv import enrich_osv
from .sbom import InputError, parse_cyclonedx

ROOT = Path(__file__).resolve().parent.parent
MAX_BODY = 1_500_000
app = FastAPI(title="VulnGraph API", version="1.0.0", docs_url="/api/docs", redoc_url=None,
              openapi_url="/api/openapi.json", description="Explainable vulnerability triage from CycloneDX SBOMs and opt-in OSV enrichment.")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@app.middleware("http")
async def safe_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.update({
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
        "Cache-Control": "no-store",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    })
    return response


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "vulngraph", "version": "1.0.0"}


@app.get("/api/demo")
def demo(internet_facing: bool = True,
         business_criticality: int = Query(default=4, ge=1, le=5)):
    return sample_report(internet_facing, business_criticality)


def _context(raw: object) -> Context:
    if not isinstance(raw, dict):
        raise InputError("context must be an object.")
    facing = raw.get("internet_facing", False)
    criticality = raw.get("business_criticality", 1)
    if type(facing) is not bool:
        raise InputError("internet_facing must be a boolean.")
    if type(criticality) is not int or not 1 <= criticality <= 5:
        raise InputError("business_criticality must be an integer from 1 to 5.")
    return Context(facing, criticality)


@app.post("/api/analyze")
async def analyze(request: Request):
    if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
        raise HTTPException(status_code=415, detail="Content-Type must be application/json.")
    try:
        chunks = bytearray()
        async for part in request.stream():
            if len(chunks) + len(part) > MAX_BODY:
                raise HTTPException(status_code=413, detail="Maximum JSON request size is 1.5 MB.")
            chunks.extend(part)
        raw = json.loads(chunks)
        if not isinstance(raw, dict):
            raise InputError("Body must be a JSON object.")
        mode = raw.get("mode", "offline")
        if mode not in ("offline", "osv"):
            raise InputError("mode must be offline or osv.")
        inv, advisories = parse_cyclonedx(raw.get("sbom"))
        context = _context(raw.get("context", {}))
        synthetic = is_demo_fixture(inv.name, [a.identifier for a in advisories])
        if synthetic and mode == "osv":
            raise InputError("This is the synthetic demonstration fixture. Import a real SBOM for OSV live checks.")
        notices = ()
        sources = ["CycloneDX supplied by user"]
        if mode == "osv":
            online, notices = await enrich_osv(inv.components)
            sources.append("OSV public API (opt-in)")
            # Keep independently supplied SBOM records; prevent duplicate (id, ref) in report.
            advisories = (*advisories, *online)
            if online:
                sources.extend(("FIRST EPSS (where available)", "CISA KEV (where available)"))
        if synthetic:
            sources = ["Synthetic demonstration SBOM; fictional advisories"]
        return JSONResponse(build_report(Analysis(inv, tuple(advisories), context, is_demo=synthetic,
                                                  data_sources=tuple(sources), warnings=notices)))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Malformed JSON request.") from exc
    except InputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
