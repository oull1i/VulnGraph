# Security and Trust Model

VulnGraph is **not** a penetration-testing agent, general-purpose website scanner, or substitute for an application security program. It performs authorized read-only supply-chain triage.

## Implemented controls

- Localhost bind by default; no auth token or long-lived sessions needed for local usage.
- JSON request body limited to 1.5 MB **while streaming**, plus bounded CycloneDX arrays.
- SBOM and vulnerability strings rendered as escaped text or into safe DOM nodes, never executed as HTML scripts.
- Tight content security policy; no third-party fonts/scripts, no permissive CORS, no file uploads to third-party endpoints.
- All online requests use fixed trusted provider hosts; user-supplied URL strings are never fetched.
- Upstream requests have timeouts, bounded concurrency and best-effort response-size checks.
- No local database or app-created user records; generated reports stay in request/browser memory until explicitly exported.
- Docker runs as a non-root user, read-only root filesystem via Compose, minimal container privileges.
- API tests use mock transports for OSV/EPSS/KEV; no unintended real traffic from tests.

## Trust boundaries

1. CycloneDX input, package names and embedded CVE assertions are **untrusted**. An uploaded SBOM is a claim by the source document; a missing finding says little about security posture.
2. Public feeds may be stale, incomplete, or temporarily unavailable. Unavailable EPSS and CVSS fields remain unknown. Absence from KEV is not a guarantee of no exploitation.
3. The prioritization score is a hand-designed **triage heuristic**, not calibrated threat probability, not runtime reachability, not CVSS, not an AI classification confidence score.
4. Version upgrade information is advisory and must be checked against the affected component and maintainers' release notes. Do not auto-upgrade production systems from this report.
5. When **OSV live** is requested, public providers receive package names and versions; do not use it on sensitive internal component names without authorization.

## Known limitations and future hardening

- **No multi-tenant authentication, gateway rate limiting, or isolation:** deploy behind strong access controls if ever exposed beyond a local/trusted environment.
- Online lookups intentionally cap packages and advisories; pagination is flagged when detected rather than silently promising complete coverage.
- CycloneDX support is **JSON** only, does not fully validate against official JSON Schema, and does not support SPDX or arbitrary lockfile formats.
- Direct/transitive dependency levels are based on supplied graph; they do not prove application reachability or that a vulnerable code path executes.
- CVSS v3.0/v3.1 vector scoring is supported; CVSS v4 is not computed.
- Current UI has no per-user retention because records are held only in memory; use caution with exported reports that may contain sensitive package details.
- Real provider integration is optional and can vary with network availability and upstream schema changes. CI tests use mocks.
- Dependency packages use compatible version ranges rather than a fully resolved lockfile. For public production deployments pin hashes, monitor CVEs, and add dependency audit and SCA scans.

## Reporting an issue

Avoid posting private SBOMs, credentials or sensitive logs publicly. Report security issues through the project's maintainer-approved private channel. If none is configured, open a GitHub issue **without exploit details or sensitive information** asking for a secure reporting method.
