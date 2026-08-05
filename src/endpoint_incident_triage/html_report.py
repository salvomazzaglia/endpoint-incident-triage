"""Standalone HTML triage report generation."""

from __future__ import annotations

import html
from pathlib import Path

from endpoint_incident_triage import TOOL_NAME, __version__
from endpoint_incident_triage.models import TriageReport

SYNTHETIC_BANNER = (
    "SYNTHETIC DEMONSTRATION DATA — This report contains synthetic endpoint-triage "
    "data created exclusively for demonstration, testing, and documentation purposes."
)


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _severity_class(severity: str) -> str:
    mapping = {
        "Critical": "sev-critical",
        "High": "sev-high",
        "Medium": "sev-medium",
        "Low": "sev-low",
        "Informational": "sev-info",
    }
    return mapping.get(severity, "sev-info")


def render_html_report(report: TriageReport) -> str:
    """Render a standalone HTML report with embedded CSS."""
    synthetic_banner = ""
    if report.synthetic:
        synthetic_banner = f"""
        <div class="banner synthetic" role="status">
          <strong>{_esc(SYNTHETIC_BANNER)}</strong>
        </div>
        """

    collector_rows = []
    for item in report.collector_results:
        collector_rows.append(
            "<tr>"
            f"<td>{_esc(item.get('collector_id', ''))}</td>"
            f"<td>{_esc(item.get('platform', ''))}</td>"
            f"<td>{_esc(item.get('status', ''))}</td>"
            f"<td>{_esc(item.get('record_count', 0))}</td>"
            f"<td>{_esc(item.get('duration_ms', 0))}</td>"
            "</tr>"
        )

    finding_rows = []
    for finding in report.findings[:100]:
        finding_rows.append(
            "<tr>"
            f"<td><span class='badge {_severity_class(finding.severity.value)}'>"
            f"{_esc(finding.severity.value)}</span></td>"
            f"<td>{_esc(finding.title)}</td>"
            f"<td>{_esc(finding.advisory_wording)}</td>"
            f"<td>{_esc(finding.platform)}</td>"
            f"<td>{_esc(finding.entity_id)}</td>"
            "</tr>"
        )

    status_cards = "".join(
        f"<div class='card'><div class='label'>{_esc(label)}</div>"
        f"<div class='value'>{_esc(value)}</div></div>"
        for label, value in [
            ("Report status", report.status.value),
            ("Integrity", report.integrity_status),
            ("Custody", report.custody_status),
            ("Findings", sum(report.finding_counts.values())),
            ("Highest severity", report.highest_finding_severity or "None"),
            ("Collectors", sum(report.collector_status_counts.values())),
        ]
    )

    limitations = "".join(f"<li>{_esc(item)}</li>" for item in report.limitations)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(TOOL_NAME)} triage report</title>
<style>
:root {{
  --bg: #f5f7fb;
  --card: #ffffff;
  --text: #1a1f36;
  --muted: #5b647a;
  --border: #d8deea;
  --accent: #1f4fd8;
  --warn-bg: #fff6db;
  --warn-text: #7a5b00;
  --synthetic-bg: #fff0f0;
  --synthetic-text: #8a1f1f;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
}}
header, main, footer {{ max-width: 1100px; margin: 0 auto; padding: 1rem; }}
header h1 {{ margin: 0 0 0.25rem; font-size: 1.6rem; }}
header p {{ margin: 0; color: var(--muted); }}
.banner {{
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.75rem 1rem;
  margin: 1rem 0;
}}
.banner.synthetic {{ background: var(--synthetic-bg); color: var(--synthetic-text); }}
.banner.privacy {{ background: var(--warn-bg); color: var(--warn-text); }}
.cards {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 0.75rem;
  margin: 1rem 0;
}}
.card {{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.75rem;
}}
.card .label {{ color: var(--muted); font-size: 0.85rem; }}
.card .value {{ font-size: 1.2rem; font-weight: 600; }}
section {{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem;
  margin-bottom: 1rem;
}}
section h2 {{ margin-top: 0; font-size: 1.1rem; }}
table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 0.92rem;
}}
th, td {{
  border-bottom: 1px solid var(--border);
  padding: 0.45rem 0.35rem;
  text-align: left;
  vertical-align: top;
}}
th {{ color: var(--muted); font-weight: 600; }}
.badge {{
  display: inline-block;
  padding: 0.1rem 0.45rem;
  border-radius: 999px;
  font-size: 0.78rem;
  font-weight: 600;
}}
.sev-critical {{ background: #fde8e8; color: #a11b1b; }}
.sev-high {{ background: #fff0e6; color: #9a3d00; }}
.sev-medium {{ background: #fff6db; color: #9a6b00; }}
.sev-low {{ background: #eef4ff; color: #1f4fd8; }}
.sev-info {{ background: #eef1f6; color: #4b5565; }}
footer {{ color: var(--muted); font-size: 0.85rem; padding-bottom: 2rem; }}
@media (max-width: 640px) {{
  table {{ font-size: 0.82rem; }}
}}
</style>
</head>
<body>
<header>
  <h1>{_esc(TOOL_NAME)} — Triage Report</h1>
  <p>Version {_esc(__version__)} · Package {_esc(report.package_id)} · Generated {_esc(report.generated_at_utc)}</p>
</header>
<main>
  {synthetic_banner}
  <div class="banner privacy" role="note">
    <strong>Privacy notice:</strong> {_esc(report.security_notice)}
    Privacy mode: {_esc(report.privacy_mode.value)}.
  </div>
  <div class="cards">{status_cards}</div>
  <section>
    <h2>Case summary</h2>
    <p><strong>Case ID:</strong> {_esc(report.case_summary.get("case_id", ""))}</p>
    <p><strong>Target:</strong> {_esc(report.case_summary.get("target_label", ""))}</p>
    <p><strong>Platform:</strong> {_esc(report.case_summary.get("platform", ""))}</p>
    <p><strong>Source mode:</strong> {_esc(report.case_summary.get("source_mode", ""))}</p>
  </section>
  <section>
    <h2>Collectors</h2>
    <table>
      <thead><tr><th>Collector</th><th>Platform</th><th>Status</th><th>Records</th><th>Duration ms</th></tr></thead>
      <tbody>{"".join(collector_rows) if collector_rows else '<tr><td colspan="5">No collectors</td></tr>'}</tbody>
    </table>
  </section>
  <section>
    <h2>Findings (heuristic, advisory)</h2>
    <table>
      <thead><tr><th>Severity</th><th>Title</th><th>Advisory</th><th>Platform</th><th>Entity</th></tr></thead>
      <tbody>{"".join(finding_rows) if finding_rows else '<tr><td colspan="5">No findings</td></tr>'}</tbody>
    </table>
  </section>
  <section>
    <h2>Timeline preview</h2>
    <p>Events: {_esc(report.timeline_summary.get("event_count", 0))}</p>
    <p>First: {_esc(report.timeline_summary.get("first_timestamp_utc") or "n/a")}</p>
    <p>Last: {_esc(report.timeline_summary.get("last_timestamp_utc") or "n/a")}</p>
  </section>
  <section>
    <h2>Limitations</h2>
    <ul>{limitations if limitations else "<li>None recorded</li>"}</ul>
  </section>
</main>
<footer>
  Exit code {_esc(report.exit_code)} — {_esc(TOOL_NAME)} {_esc(__version__)}.
  Heuristic findings require analyst validation; no malware verdict is implied.
</footer>
</body>
</html>
"""


def write_html_report(path: Path, report: TriageReport) -> None:
    """Write standalone HTML report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_report(report), encoding="utf-8")
