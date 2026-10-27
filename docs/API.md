# VulnGraph API Reference

Base URL: `http://127.0.0.1:8000`. Interactive OpenAPI schema at `/api/docs`.

## `GET /api/health`

Returns `{"status":"ok","service":"vulngraph","version":"1.0.0"}`.

## `GET /api/demo`

Parameters: `internet_facing=true|false` (default `true`); `business_criticality=1..5` (default `4`). Returns fictional, labeled findings and dependency map. No network requests.

## `POST /api/analyze`

Content type: `application/json`; maximum request payload `1,500,000` bytes.

```json
{
  "sbom": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {"component": {"name": "My Service", "bom-ref": "app"}},
    "components": [{"bom-ref": "pkg-1", "name": "example", "version": "1.0.0", "purl": "pkg:pypi/example@1.0.0"}],
    "dependencies": [{"ref": "app", "dependsOn": ["pkg-1"]}],
    "vulnerabilities": []
  },
  "mode": "offline",
  "context": {"internet_facing": false, "business_criticality": 3}
}
```

`mode`: `offline` (default; no external requests) or `osv` (explicit outbound package/version queries to OSV plus attempts at FIRST EPSS and CISA KEV). Incoming input is **not stored** on disk. The shipped `demo/demo-sbom.cdx.json` is labeled synthetic; using `osv` against it is rejected to prevent mixing fictional and real records.

Response structure (abbreviated):

```json
{
  "schema": "vulngraph.report.v1",
  "demo": false,
  "sources": ["CycloneDX supplied by user"],
  "summary": {"packages": 1, "findings": 0, "affected_packages": 0},
  "findings": [],
  "dependency_graph": {"nodes": [], "edges": []},
  "remediation_queue": [],
  "warnings": ["No vulnerability assertions in this SBOM..."],
  "score_note": "Score combines ..."
}
```

**Error responses:** `400` invalid JSON, `413` excessive request size, `415` unsupported media type, `422` invalid SBOM, context or analysis mode. Online provider failures result in visible warnings and partial results, not fabricated findings.

## Limits

- Up to 250 components, 2,000 dependency declarations, 500 SBOM advisory assertions per import.
- Online lookup of up to 100 eligible versioned packages and 120 OSV detailed matches per request.
- Static OSV and upstream service hosts, bounded timeouts, no user-supplied fetch URL or arbitrary target scanning.
- No authentication or quota designed for public multi-tenant exposure. Run on loopback or trusted network by default.
