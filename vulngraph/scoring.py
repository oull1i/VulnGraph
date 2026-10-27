"""Transparent heuristic triage score: NOT a CVSS replacement or exploit probability."""
from __future__ import annotations

from .models import Advisory, Context


def rank(advisory: Advisory, context: Context) -> dict:
    cvss_pts = round((advisory.cvss or 0.0) * 3.5, 2)
    epss_pts = round((advisory.epss or 0.0) * 25, 2)
    kev_pts = 25.0 if advisory.kev else 0.0
    exposure_pts = 10.0 if context.internet_facing else 0.0
    criticality_pts = float(max(0, context.business_criticality - 1) * 1.25)
    factors = [
        {"key": "cvss", "points": cvss_pts, "max": 35, "evidence": "reported CVSS" if advisory.cvss is not None else "not provided"},
        {"key": "epss", "points": epss_pts, "max": 25, "evidence": "FIRST EPSS" if advisory.epss is not None else "not provided"},
        {"key": "kev", "points": kev_pts, "max": 25, "evidence": "CISA KEV listed" if advisory.kev else "not known to be listed"},
        {"key": "exposure", "points": exposure_pts, "max": 10, "evidence": "user supplied asset context"},
        {"key": "criticality", "points": criticality_pts, "max": 5, "evidence": "user supplied asset context"},
    ]
    score = round(min(100.0, sum(f["points"] for f in factors)), 1)
    level = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"
    missing = [k for k, v in (("CVSS", advisory.cvss), ("EPSS", advisory.epss)) if v is None]
    return {"score": score, "level": level, "factors": factors, "missing": missing,
            "rationale": " + ".join(f'{f["key"]}: {f["points"]:g}' for f in factors if f["points"] > 0) or "No positive scoring signals",
            "methodology": "Heuristic prioritization, not exploitability, a validated ML model, or a CVSS score."}
