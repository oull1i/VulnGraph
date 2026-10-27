"""Correlate vulnerabilities, dependency paths and environment into triage records."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from .models import Analysis
from .scoring import rank


def build_report(analysis: Analysis) -> dict:
    inv = analysis.inventory
    by_ref = {c.ref: c for c in inv.components}
    findings = []
    dedupe: dict[tuple[str, str], object] = {}
    for advisory in analysis.advisories:
        for ref in advisory.refs:
            if ref not in by_ref:
                continue
            key = (advisory.identifier, ref)
            # Duplicates from provider aliasing are not counted twice.
            if key in dedupe:
                continue
            dedupe[key] = True
            c = by_ref[ref]
            prioritized = rank(advisory, analysis.context)
            findings.append({
                "id": advisory.identifier, "title": advisory.title,
                "component_ref": ref, "component": c.name, "version": c.version,
                "ecosystem": c.ecosystem or "unknown", "depth": c.depth,
                "direct": c.direct, "cvss": advisory.cvss, "epss": advisory.epss,
                "kev": advisory.kev, "source": advisory.source, "aliases": list(advisory.aliases),
                "link": advisory.link, "fixed_version": advisory.fixed_version,
                "description": advisory.description, **prioritized,
            })
    findings.sort(key=lambda x: (-x["score"], x["component"].lower(), x["id"]))
    buckets = dict(Counter(f["level"] for f in findings))
    impacted = {f["component_ref"] for f in findings}
    package_by_ref = defaultdict(list)
    for f in findings:
        package_by_ref[f["component_ref"]].append(f["id"])
    nodes = [{"ref": c.ref, "label": c.name, "version": c.version, "ecosystem": c.ecosystem,
              "depth": c.depth, "direct": c.direct, "findings": list(dict.fromkeys(package_by_ref[c.ref])),
              "max_score": max((f["score"] for f in findings if f["component_ref"] == c.ref), default=0)} for c in inv.components]
    remediations = []
    for f in findings:
        if f["fixed_version"]:
            action = f'Assess upgrade to {f["fixed_version"]} after verifying compatibility.'
        else:
            action = 'Check the advisory and maintainer releases for a fixed version; test a safe upgrade.'
        remediations.append({"finding": f["id"], "component": f["component"], "priority": f["level"], "action": action})
    warnings = list(dict.fromkeys((*inv.warnings, *analysis.warnings)))
    if findings and any(f["missing"] for f in findings):
        warnings.append("Missing CVSS/EPSS values are not estimated; scores may under-prioritize those findings.")
    if analysis.is_demo:
        warnings.insert(0, "DEMO DATA: all vulnerability records and scores in this example are illustrative, not verified advisories.")
    return {
        "schema": "vulngraph.report.v1", "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": inv.name or "Imported application", "demo": analysis.is_demo,
        "sources": list(analysis.data_sources), "context": {"internet_facing": analysis.context.internet_facing,
        "business_criticality": analysis.context.business_criticality},
        "summary": {"packages": len(inv.components), "findings": len(findings), "affected_packages": len(impacted),
                    "critical": buckets.get("critical", 0), "high": buckets.get("high", 0),
                    "medium": buckets.get("medium", 0), "low": buckets.get("low", 0),
                    "highest_score": max((f["score"] for f in findings), default=0),
                    "kev_listed": sum(1 for f in findings if f["kev"])},
        "findings": findings, "dependency_graph": {"nodes": nodes, "edges": [{"source": a, "target": b} for a, b in inv.edges]},
        "remediation_queue": remediations,
        "warnings": warnings,
        "score_note": "Score combines CVSS (35), EPSS (25), KEV presence (25), internet exposure (10), and business criticality (5). Missing signals score zero. This is a prioritization heuristic, not a probability, calibrated model, or exploit chain.",
    }
