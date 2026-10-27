"""Defensive CycloneDX JSON import with strict limits and dependency mapping."""
from __future__ import annotations

import re
from collections import deque
from urllib.parse import unquote, urlsplit

from .models import Advisory, Component, Inventory

MAX_COMPONENTS = 250
MAX_EDGES = 2000
MAX_ADVISORIES = 500
MAX_TEXT = 600
SUPPORTED_SPECS = {"1.4", "1.5", "1.6", "1.7"}
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class InputError(ValueError):
    """Client supplied an unsupported or malformed artifact."""


def string(value: object, limit: int = MAX_TEXT) -> str:
    return str(value).strip()[:limit] if isinstance(value, (str, int, float)) else ""


def parse_purl(purl: str | None) -> tuple[str | None, str | None]:
    if not purl or not purl.startswith("pkg:") or len(purl) > 800:
        return None, None
    value = purl[4:].split("?", 1)[0].split("#", 1)[0]
    typ, sep, rest = value.partition("/")
    if not sep or "@" not in rest:
        return None, None
    name, _, version = rest.rpartition("@")
    if not name or not version:
        return None, None
    ecosystem = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "golang": "Go", "cargo": "crates.io", "nuget": "NuGet", "gem": "RubyGems"}.get(typ.lower())
    return ecosystem, unquote(name)


def safe_https(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 800:
        return None
    try:
        u = urlsplit(value)
        if u.scheme == "https" and u.hostname and not u.username and not u.password:
            return value
    except ValueError:
        pass
    return None


def _cvss(vuln: dict) -> float | None:
    values = []
    ratings = vuln.get("ratings", [])
    if not isinstance(ratings, list):
        return None
    for rating in ratings:
        if not isinstance(rating, dict):
            continue
        score = rating.get("score")
        if type(score) in (float, int) and 0 <= score <= 10:
            values.append(float(score))
    return max(values) if values else None


def _get_fixed(vuln: dict) -> str | None:
    properties = vuln.get("properties", [])
    if not isinstance(properties, list):
        return None
    for p in properties:
        if isinstance(p, dict) and p.get("name") in {"vulngraph:fixed-version", "fixed_version"}:
            version = string(p.get("value"), 80)
            return version or None
    return None


def parse_cyclonedx(payload: object) -> tuple[Inventory, tuple[Advisory, ...]]:
    if not isinstance(payload, dict):
        raise InputError("SBOM must be a JSON object.")
    if payload.get("bomFormat") != "CycloneDX":
        raise InputError("Only CycloneDX JSON SBOMs are supported.")
    spec = payload.get("specVersion")
    if spec not in SUPPORTED_SPECS:
        raise InputError(f"Supported CycloneDX versions: {', '.join(sorted(SUPPORTED_SPECS))}.")
    items = payload.get("components", [])
    if not isinstance(items, list) or len(items) > MAX_COMPONENTS:
        raise InputError(f"components must be an array with at most {MAX_COMPONENTS} entries.")
    raw_edges = payload.get("dependencies", [])
    if not isinstance(raw_edges, list) or len(raw_edges) > MAX_EDGES:
        raise InputError(f"dependencies must be an array with at most {MAX_EDGES} entries.")
    raw_vulns = payload.get("vulnerabilities", [])
    if not isinstance(raw_vulns, list) or len(raw_vulns) > MAX_ADVISORIES:
        raise InputError(f"vulnerabilities must be an array with at most {MAX_ADVISORIES} entries.")

    metadata = payload.get("metadata", {})
    if not isinstance(metadata, dict):
        raise InputError("metadata must be an object.")
    root_component = metadata.get("component", {})
    if not isinstance(root_component, dict):
        raise InputError("metadata.component must be an object.")
    root_ref = string(root_component.get("bom-ref"))
    all_refs = set()
    inputs: list[tuple[str, str, str, str | None, str | None]] = []
    for idx, c in enumerate(items):
        if not isinstance(c, dict):
            raise InputError(f"components[{idx}] must be an object.")
        ref = string(c.get("bom-ref")) or f"component-{idx+1}"
        if ref in all_refs:
            raise InputError(f"Duplicate component bom-ref: {ref}")
        all_refs.add(ref)
        name = string(c.get("name"), 150)
        if not name:
            raise InputError(f"components[{idx}] is missing name.")
        version = string(c.get("version"), 90) or "unknown"
        purl = string(c.get("purl"), 800) or None
        ecosystem, _ = parse_purl(purl)
        # Only queried packages with a full package URL and a concrete version are eligible.
        inputs.append((ref, name, version, purl, ecosystem))

    edges_set: set[tuple[str, str]] = set()
    for e in raw_edges:
        if not isinstance(e, dict):
            raise InputError("Dependency entries must be objects.")
        parent = string(e.get("ref"))
        children = e.get("dependsOn", [])
        if not isinstance(children, list) or len(children) > MAX_COMPONENTS:
            raise InputError("Invalid dependsOn list.")
        for child in children:
            cref = string(child)
            if cref in all_refs and (parent in all_refs or parent == root_ref) and cref != parent:
                edges_set.add((parent, cref))
                if len(edges_set) > MAX_EDGES:
                    raise InputError(f"Too many dependency relationships; maximum {MAX_EDGES}.")
    edges = tuple(sorted(edges_set))

    # BFS depth from the application root if present. Otherwise infer root components.
    adj: dict[str, set[str]] = {}
    for a, b in edges:
        adj.setdefault(a, set()).add(b)
    incoming = {b for _, b in edges}
    starts = [root_ref] if root_ref and root_ref in adj else [r for r in all_refs if r not in incoming]
    depth: dict[str, int] = {}
    todo = deque((ref, 0) for ref in starts)
    while todo:
        ref, d = todo.popleft()
        if ref in depth and depth[ref] <= d:
            continue
        depth[ref] = d
        for child in adj.get(ref, ()):
            todo.append((child, d + 1))
    components = tuple(
        Component(ref, name, version, purl, ecosystem, depth.get(ref) == 1, depth.get(ref))
        for ref, name, version, purl, ecosystem in inputs
    )
    advisory_list = []
    for idx, vuln in enumerate(raw_vulns):
        if not isinstance(vuln, dict):
            raise InputError(f"vulnerabilities[{idx}] must be an object.")
        ident = string(vuln.get("id"), 140)
        if not ident:
            raise InputError(f"vulnerabilities[{idx}] missing id.")
        affects = vuln.get("affects", [])
        if not isinstance(affects, list) or len(affects) > MAX_COMPONENTS:
            raise InputError("Invalid affects list.")
        refs = tuple(sorted({string(a.get("ref")) for a in affects if isinstance(a, dict)} & all_refs))
        if not refs:
            continue  # An unlinked advisory is not an assertion about this inventory.
        links = vuln.get("advisories", [])
        link = next((url for entry in links if isinstance(entry, dict) and (url := safe_https(entry.get("url")))), None) if isinstance(links, list) else None
        desc = string(vuln.get("description") or vuln.get("detail"), 600)
        advisory_list.append(Advisory(identifier=ident, title=string(vuln.get("name"), 160) or ident, refs=refs, cvss=_cvss(vuln), link=link, source="sbom", description=desc, fixed_version=_get_fixed(vuln)))
    warnings = []
    if not raw_vulns:
        warnings.append("No vulnerability assertions in this SBOM. Import is inventory-only until OSV lookup is requested.")
    if not edges:
        warnings.append("No dependency edges supplied; direct/transitive depth is unknown.")
    return Inventory(
        name=(string(root_component.get("name"), 160) if isinstance(root_component, dict) else "") or "Imported application",
        components=components, edges=edges, warnings=tuple(warnings)
    ), tuple(advisory_list)
