"""Artifact exporters: endpoint catalog (JSON) and security report (JSON + HTML).

Produces the deliverables the assignment requires:
  * api_catalog.json      - discovered endpoints with security metadata
  * security_report.json  - machine-readable findings
  * security_report.html  - professional report (exec summary, findings,
                            CVSS scores, PoC evidence, remediation roadmap)
"""

import html
import json
from pathlib import Path
from typing import Dict

from .schemas import EndpointCatalog, SecurityReport

_SEVERITY_COLOR = {
    "Critical": "#b71c1c",
    "High": "#e65100",
    "Medium": "#f9a825",
    "Low": "#2e7d32",
}


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _severity_order(sev: str) -> int:
    return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(sev, 4)


def _render_html(catalog: EndpointCatalog, report: SecurityReport) -> str:
    vulns = sorted(report.vulnerabilities, key=lambda v: _severity_order(v.severity))
    counts: Dict[str, int] = {}
    for v in vulns:
        counts[v.severity] = counts.get(v.severity, 0) + 1
    summary_badges = " ".join(
        f'<span class="badge" style="background:{_SEVERITY_COLOR.get(s, "#555")}">{s}: {c}</span>'
        for s, c in sorted(counts.items(), key=lambda kv: _severity_order(kv[0]))
    ) or '<span class="badge" style="background:#2e7d32">No confirmed findings</span>'

    rows = ""
    for v in vulns:
        color = _SEVERITY_COLOR.get(v.severity, "#555")
        rows += f"""
        <div class="finding">
          <h3>{html.escape(v.id)} &middot; {html.escape(v.name)}
            <span class="badge" style="background:{color}">{html.escape(v.severity)} &middot; CVSS {v.cvss_score}</span>
          </h3>
          <table>
            <tr><th>OWASP</th><td>{html.escape(v.owasp_category)}</td></tr>
            <tr><th>Endpoint</th><td><code>{html.escape(v.endpoint)}</code></td></tr>
            <tr><th>CVSS Vector</th><td><code>{html.escape(v.cvss_vector or "n/a")}</code></td></tr>
            <tr><th>Description</th><td>{html.escape(v.description)}</td></tr>
            <tr><th>Evidence (PoC)</th><td><pre>{html.escape(v.evidence)}</pre></td></tr>
            <tr><th>Remediation</th><td>{html.escape(v.remediation)}</td></tr>
          </table>
        </div>"""

    endpoint_rows = "".join(
        f"<tr><td>{html.escape(e.id)}</td><td><code>{html.escape(e.method)}</code></td>"
        f"<td><code>{html.escape(e.path)}</code></td><td>{html.escape(e.category)}</td>"
        f"<td>{html.escape(e.risk_level)}</td></tr>"
        for e in catalog.endpoints
    )

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>VAmPI Security Assessment</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem auto; max-width: 900px; color: #1a1a1a; }}
  h1 {{ border-bottom: 3px solid #333; padding-bottom: .3rem; }}
  .badge {{ color: #fff; padding: 2px 10px; border-radius: 12px; font-size: .8rem; margin-left: 8px; }}
  table {{ border-collapse: collapse; width: 100%; margin: .5rem 0 1.5rem; }}
  th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }}
  th {{ background: #f5f5f5; width: 140px; }}
  .finding {{ border: 1px solid #e0e0e0; border-radius: 8px; padding: 1rem; margin: 1rem 0; }}
  pre {{ background: #f7f7f7; padding: 8px; border-radius: 6px; white-space: pre-wrap; word-break: break-word; }}
  code {{ background: #f0f0f0; padding: 1px 4px; border-radius: 4px; }}
</style></head><body>
  <h1>VAmPI API Security Assessment</h1>
  <p><strong>Target:</strong> <code>{html.escape(report.target)}</code></p>
  <p><strong>Summary:</strong> {summary_badges}</p>

  <h2>Executive Summary</h2>
  <p>{html.escape(report.executive_summary)}</p>

  <h2>Discovered Endpoints ({len(catalog.endpoints)})</h2>
  <table>
    <tr><th>ID</th><th>Method</th><th>Path</th><th>Category</th><th>Risk</th></tr>
    {endpoint_rows}
  </table>

  <h2>Vulnerability Findings ({len(vulns)})</h2>
  {rows or "<p>No vulnerabilities were empirically confirmed in this run.</p>"}
</body></html>"""


def write_all(catalog: EndpointCatalog, report: SecurityReport, out_dir: Path) -> Dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    catalog_path = out_dir / "api_catalog.json"
    report_json = out_dir / "security_report.json"
    report_html = out_dir / "security_report.html"

    _write_json(catalog_path, catalog.model_dump())
    _write_json(report_json, report.model_dump())
    report_html.write_text(_render_html(catalog, report), encoding="utf-8")

    return {
        "api_catalog": catalog_path,
        "security_report_json": report_json,
        "security_report_html": report_html,
    }
