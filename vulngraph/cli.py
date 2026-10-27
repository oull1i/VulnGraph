"""Local dashboard runner and headless vulnerability triage for CI or automation."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

from .engine import build_report
from .models import Analysis, Context
from .osv import enrich_osv
from .sbom import InputError, parse_cyclonedx


def is_demo_fixture(name: str, ids: list[str]) -> bool:
    return "(SYNTHETIC DEMO)" in name and bool(ids) and all(i.startswith("DEMO-VULN-") for i in ids)


async def analyze_file(file: Path, *, online: bool = False, internet_facing: bool = False,
                       criticality: int = 1) -> dict:
    if file.stat().st_size > 1_500_000:
        raise InputError("SBOM must be 1.5 MB or smaller.")
    inventory, advisories = parse_cyclonedx(json.loads(file.read_text(encoding="utf-8")))
    demo = is_demo_fixture(inventory.name, [a.identifier for a in advisories])
    if demo and online:
        raise InputError("The demo fixture contains fictional vulnerabilities. Use a real SBOM for online enrichment.")
    if demo:
        from .demo import sample_report
        return sample_report(internet_facing, criticality)
    notes = ()
    sources = ["User-provided CycloneDX"]
    if online:
        new, notes = await enrich_osv(inventory.components)
        advisories = (*advisories, *new)
        sources.extend(["OSV public API (opt-in)", "FIRST EPSS / CISA KEV where available"])
    if demo:
        sources = ["Synthetic demonstration SBOM; fictional advisories"]
    return build_report(Analysis(inventory, tuple(advisories), Context(internet_facing, criticality),
                                 is_demo=demo, data_sources=tuple(sources), warnings=notes))


def main() -> None:
    parser = argparse.ArgumentParser(prog="vulngraph", description="Local-first vulnerability triage from a CycloneDX SBOM")
    modes = parser.add_subparsers(dest="command")
    server = modes.add_parser("serve", help="Run the web dashboard")
    server.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"))
    server.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    analyzer = modes.add_parser("analyze", help="Generate a machine-readable JSON report")
    analyzer.add_argument("sbom", type=Path, help="CycloneDX JSON SBOM input file")
    analyzer.add_argument("-o", "--output", type=Path, help="Write a report to this path; defaults to stdout")
    analyzer.add_argument("--online", action="store_true", help="Send package identifiers to OSV and public scoring feeds")
    analyzer.add_argument("--internet-facing", action="store_true", help="Assess the application as externally accessible")
    analyzer.add_argument("--criticality", type=int, default=1, choices=range(1, 6), metavar="1..5")
    args = parser.parse_args()
    if args.command in (None, "serve"):
        import uvicorn
        uvicorn.run("vulngraph.server:app", host=getattr(args, "host", os.getenv("HOST", "127.0.0.1")),
                    port=getattr(args, "port", int(os.getenv("PORT", "8000"))), log_level="info")
        return
    try:
        report = asyncio.run(analyze_file(args.sbom, online=args.online,
                                          internet_facing=args.internet_facing, criticality=args.criticality))
        content = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(content, encoding="utf-8")
            print(f"Wrote {report['summary']['findings']} findings to {args.output}")
        else:
            print(content, end="")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(status=2, message=f"Error: {exc}\n")


if __name__ == "__main__":
    main()
