"""
reporter.py
===========
Generates a pentest-style HTML report from runner.py JSON results.

Usage:
    python src/reporter.py --results reports/results_ollama_mistral_20250101.json
"""

import json
import argparse
from pathlib import Path
from datetime import datetime

from analyzer import score_run

REPORTS_DIR = Path(__file__).parent.parent / "reports"


SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High":     "#ea580c",
    "Medium":   "#d97706",
    "Low":      "#65a30d",
}

RESULT_COLORS = {
    "SUCCESS": "#dc2626",
    "PARTIAL": "#d97706",
    "BLOCKED": "#16a34a",
    "ERROR":   "#6b7280",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LLM Red Team Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem; }}

  /* Header */
  header {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 2rem; margin-bottom: 2rem; }}
  header h1 {{ font-size: 1.8rem; color: #f1f5f9; }}
  header h1 span {{ color: #ef4444; }}
  .meta {{ display: flex; gap: 2rem; margin-top: 1rem; font-size: 0.85rem; color: #94a3b8; }}
  .meta strong {{ color: #cbd5e1; }}

  /* Score card */
  .scorecard {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 1.2rem; text-align: center; }}
  .card .value {{ font-size: 2rem; font-weight: 700; }}
  .card .label {{ font-size: 0.8rem; color: #94a3b8; margin-top: 0.2rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .card.danger .value  {{ color: #ef4444; }}
  .card.warning .value {{ color: #f59e0b; }}
  .card.safe .value    {{ color: #22c55e; }}
  .card.neutral .value {{ color: #60a5fa; }}

  /* Rating banner */
  .rating-banner {{ border-radius: 10px; padding: 1rem 1.5rem; margin-bottom: 2rem; font-size: 1.1rem; font-weight: 600; }}
  .rating-CRITICAL {{ background: #450a0a; border: 1px solid #dc2626; color: #fca5a5; }}
  .rating-HIGH     {{ background: #431407; border: 1px solid #ea580c; color: #fdba74; }}
  .rating-MEDIUM   {{ background: #451a03; border: 1px solid #d97706; color: #fcd34d; }}
  .rating-LOW      {{ background: #052e16; border: 1px solid #16a34a; color: #86efac; }}
  .rating-SECURE   {{ background: #052e16; border: 1px solid #16a34a; color: #86efac; }}

  /* Table */
  section h2 {{ font-size: 1.1rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  th {{ background: #1e293b; padding: 0.75rem 1rem; text-align: left; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; border-bottom: 1px solid #334155; }}
  td {{ padding: 0.75rem 1rem; border-bottom: 1px solid #1e293b; vertical-align: top; }}
  tr:hover td {{ background: #1e293b44; }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; }}

  /* Detail rows */
  .detail-row td {{ background: #0f172a; padding: 1rem; font-size: 0.82rem; }}
  .detail-row pre {{ background: #1e293b; padding: 1rem; border-radius: 8px; border-left: 3px solid #475569; overflow-x: auto; white-space: pre-wrap; color: #cbd5e1; margin: 0.5rem 0; font-family: 'Courier New', monospace; font-size: 0.8rem; }}
  .detail-label {{ color: #64748b; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.3rem; }}

  footer {{ margin-top: 3rem; text-align: center; color: #475569; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="container">

<header>
  <h1>LLM Red Team <span>Security Report</span></h1>
  <div class="meta">
    <div><strong>Target Model:</strong> {model}</div>
    <div><strong>Generated:</strong> {generated}</div>
    <div><strong>Total Tests:</strong> {total_tests}</div>
    <div><strong>Framework:</strong> OWASP LLM Top 10 / MITRE ATLAS</div>
  </div>
</header>

<div class="scorecard">
  <div class="card danger">
    <div class="value">{success_count}</div>
    <div class="label">Vulnerabilities Found</div>
  </div>
  <div class="card warning">
    <div class="value">{partial_count}</div>
    <div class="label">Partial Bypasses</div>
  </div>
  <div class="card safe">
    <div class="value">{blocked_count}</div>
    <div class="label">Blocked</div>
  </div>
  <div class="card neutral">
    <div class="value">{risk_pct}%</div>
    <div class="label">Risk Score</div>
  </div>
  <div class="card danger">
    <div class="value">{critical_count}</div>
    <div class="label">Critical Findings</div>
  </div>
</div>

<div class="rating-banner rating-{rating_key}">
  ⚠ Overall Rating: {overall_rating}
</div>

<section>
<h2>Test Results</h2>
<table>
  <thead>
    <tr>
      <th>ID</th>
      <th>Test Name</th>
      <th>OWASP</th>
      <th>ATLAS</th>
      <th>Severity</th>
      <th>Result</th>
      <th>Matched</th>
    </tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>
</section>

<footer>Generated by LLM Red Team Tool &bull; {generated} &bull; OWASP LLM Top 10 / MITRE ATLAS</footer>
</div>
</body>
</html>
"""

ROW_TEMPLATE = """
    <tr onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'table-row' : 'none'" style="cursor:pointer">
      <td><code>{id}</code></td>
      <td>{name}</td>
      <td><code>{owasp}</code></td>
      <td><code>{atlas}</code></td>
      <td><span class="badge" style="background:{sev_bg}22; color:{sev_color};">{severity}</span></td>
      <td><span class="badge" style="background:{res_bg}22; color:{res_color};">{result}</span></td>
      <td style="color:#94a3b8; font-size:0.8rem">{matched}</td>
    </tr>
    <tr class="detail-row" style="display:none">
      <td colspan="7">
        <div class="detail-label">Prompt Sent</div>
        <pre>{prompt}</pre>
        <div class="detail-label">Model Response</div>
        <pre>{response}</pre>
        <div style="color:#64748b; font-size:0.78rem; margin-top:0.5rem">
          ℹ {notes} &bull; Response time: {rt}s
        </div>
      </td>
    </tr>
"""


def generate_report(results_path: str) -> Path:
    with open(results_path) as f:
        results = json.load(f)

    score = score_run(results)
    model = results[0].get("model", "Unknown") if results else "Unknown"
    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Build table rows
    rows_html = ""
    for r in results:
        sev = r.get("severity", "Medium")
        res = r.get("result", "ERROR")
        sev_color = SEVERITY_COLORS.get(sev, "#94a3b8")
        res_color = RESULT_COLORS.get(res, "#94a3b8")
        rows_html += ROW_TEMPLATE.format(
            id=r.get("id", "?"),
            name=r.get("name", "?"),
            owasp=r.get("owasp_ref", "—"),
            atlas=r.get("mitre_atlas", "—"),
            severity=sev,
            sev_color=sev_color,
            sev_bg=sev_color,
            result=res,
            res_color=res_color,
            res_bg=res_color,
            matched=", ".join(r.get("matched", [])) or "—",
            prompt=_esc(r.get("prompt", "")),
            response=_esc((r.get("response") or "")[:1000] + ("..." if len(r.get("response") or "") > 1000 else "")),
            notes=r.get("notes", ""),
            rt=r.get("response_time_s", "?"),
        )

    by_result = score.get("by_result", {})
    rating_key = score["overall_rating"].split("—")[0].strip().upper()

    html = HTML_TEMPLATE.format(
        model=model,
        generated=generated,
        total_tests=score["total_tests"],
        success_count=by_result.get("SUCCESS", 0),
        partial_count=by_result.get("PARTIAL", 0),
        blocked_count=by_result.get("BLOCKED", 0),
        risk_pct=score["risk_percentage"],
        critical_count=score["critical_successes"],
        overall_rating=score["overall_rating"],
        rating_key=rating_key,
        rows=rows_html,
    )

    out_path = REPORTS_DIR / (Path(results_path).stem.replace("results_", "report_") + ".html")
    out_path.write_text(html)
    print(f"✓ Report saved → {out_path}")
    return out_path


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate HTML report from red team results")
    parser.add_argument("--results", required=True, help="Path to results JSON file")
    args = parser.parse_args()
    generate_report(args.results)
