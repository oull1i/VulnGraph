# Verification Record — 2026-10-24

This is a transparent engineering check record, **not** a claim of security certification or exhaustive vulnerability detection.

## Verified in the working environment

- `python -m pytest -q` — **63 passed** (CycloneDX parsing, CVSS v3 vector math, scoring, demo provenance, API requests, upload limits, hostile inputs, mocked OSV/EPSS/KEV interactions, CLI).
- `python -m compileall -q vulngraph` — passed.
- `node --check static/app.js` — passed.
- CLI integration `python -m vulngraph.cli analyze demo/demo-sbom.cdx.json ...` — generated a valid report, explicitly flagged `demo: true`.
- Browser UI smoke in Chromium **with API responses simulated by fixture data** — loaded dashboard and 8 fictional findings, opened details drawer, toggled Arabic RTL, recalculated context-sensitive priority, and found no JavaScript exceptions.
- Standalone `docs/index.html` smoke in Chromium — controls for real imports and OSV disabled, demonstration active, JSON download worked, Arabic mode worked, no JavaScript exceptions.

## Not independently verified here

- Live network lookup against OSV, FIRST EPSS or CISA KEV. These API integrations were contract-checked with documentation and exercised through mocked HTTP responses. Availability, coverage and field formats can change.
- Docker build in this environment (Docker not installed). The GitHub Actions workflow is provided to build the image after publishing.
- Public multi-user hosting. It requires additional authorization controls and rate limiting before exposure.
- Cross-browser rendering outside Chromium, production scale, or genuine exploitability/reachability of listed packages.

## Interpreting results

- The demo SBOM contains synthetic advisory identifiers. It **must not** be cited as real vulnerability evidence.
- A report with zero findings is not proof of a secure application.
- The prioritization score is a reproducible heuristic, not a trained model, severity standard or empirically calibrated attack probability.
