"""Generate a standalone GitHub Pages demo with precomputed fictional reports.

No scanning, no API calls, and no ability to import a real SBOM. This allows
reviewers to try the dashboard UI without installing Python.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from vulngraph.demo import sample_report

ROOT = Path(__file__).resolve().parents[1]
index = (ROOT / "static/index.html").read_text(encoding="utf-8")
css = (ROOT / "static/styles.css").read_text(encoding="utf-8")
js = (ROOT / "static/app.js").read_text(encoding="utf-8")

reports = {
    f"{str(facing).lower()}:{criticality}": sample_report(facing, criticality)
    for facing in (True, False)
    for criticality in range(1, 6)
}
# Neutralize script terminators in injected JSON. All data is controlled
# and fictional, but keep the builder robust.
serialized = json.dumps(reports, ensure_ascii=False).replace("<", "\\u003c")
bootstrap = r"""
window.VG_STATIC_DEMO = true;
const OFFLINE_REPORTS = __DEMO_REPORTS__;
window.fetch = async function(url) {
  const params = new URLSearchParams(String(url).split('?')[1] || '');
  const facing = params.get('internet_facing') === 'false' ? 'false' : 'true';
  const level = params.get('business_criticality') || '4';
  const value = OFFLINE_REPORTS[facing + ':' + level];
  return {ok: true, status: 200, json: async () => structuredClone(value)};
};
""".replace("__DEMO_REPORTS__", serialized)
index = index.replace('<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">', "")
index = index.replace('<link rel="stylesheet" href="/static/styles.css">', f"<style>\n{css}\n</style>")
index = index.replace('<script src="/static/app.js" defer></script>', f"<script>\n{bootstrap}\n</script>\n<script>\n{js}\n</script>")
index = index.replace('<div class="app-shell">', '<div class="static-ribbon">STATIC SHOWCASE · FICTIONAL DATA · NO BACKEND / لا يمثل فحصًا أمنيًا حقيقيًا</div><div class="app-shell">')
index = index.replace('<title>VulnGraph', '<title>VulnGraph DEMO')
index = index.replace('</style>', '.static-ribbon{background:#2e2418;color:#f3d1a0;border-bottom:1px solid #60452d;padding:9px 18px;text-align:center;font-size:11px;letter-spacing:.7px;font-weight:700}</style>', 1)
output = ROOT / "docs/index.html"
output.write_text(index, encoding="utf-8")
print(f"Generated static demonstration: {output.relative_to(ROOT)} ({output.stat().st_size} bytes)")
