# Engineering Roadmap

These are **not implemented**; they are proposed next steps:

1. **Complete provenance tracking:** source and timestamp per evidence field, response verification and reproducible snapshots.
2. **Coverage diagnostics:** confidence about SBOM composition completeness, advisory pagination and unsupported ecosystems.
3. **Reachability-informed analysis:** integrate build-time static usage or call-graph results without assuming package presence equals exploitability.
4. **Safe vulnerability workflows:** tickets, triage approval, suppression reasons, expiration and re-scanning with change history.
5. **First-class CVSS v4:** version-correct scoring and clear source-of-truth handling.
6. **SBOM diff view:** compare before/after package upgrades and report newly introduced/remediated vulnerabilities.
7. **Organizational deployment hardening:** authentication, per-tenant isolation, rate limiting, private egress policy, audit logs and backups.
8. **Measurement:** evaluate prioritization heuristics on longitudinal real-world remediation outcomes before implying predictive performance.

## Research project extension

A separate supervised learning experiment could estimate remediation priority from **historically labeled, permissioned** vulnerability outcomes. Validate using time-split data, calibration, external test sets and leakage controls. Never represent it as an existing feature until built and verified.
