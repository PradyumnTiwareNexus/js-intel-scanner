"""
Generates JSON, CSV, and a single-file HTML dashboard report from a scan summary.
"""
import csv
import json
from pathlib import Path

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>JS Intelligence Report — {domain}</title>
<style>
  :root {{ --bg:#0d1117; --panel:#161b22; --text:#c9d1d9; --accent:#58a6ff;
           --crit:#f85149; --high:#ff9f40; --med:#e3b341; --low:#3fb950; --info:#8b949e; }}
  body {{ background:var(--bg); color:var(--text); font-family:Segoe UI,Arial,sans-serif; margin:0; padding:24px; }}
  h1 {{ color:var(--accent); }}
  .stats {{ display:flex; gap:16px; flex-wrap:wrap; margin:20px 0; }}
  .card {{ background:var(--panel); padding:16px 20px; border-radius:8px; min-width:120px; text-align:center; }}
  .card .num {{ font-size:28px; font-weight:bold; color:var(--accent); }}
  table {{ width:100%; border-collapse:collapse; margin-top:20px; background:var(--panel); }}
  th, td {{ padding:10px 12px; border-bottom:1px solid #30363d; text-align:left; font-size:14px; }}
  th {{ color:var(--accent); }}
  .sev-Critical {{ color:var(--crit); font-weight:bold; }}
  .sev-High {{ color:var(--high); font-weight:bold; }}
  .sev-Medium {{ color:var(--med); }}
  .sev-Low {{ color:var(--low); }}
  .sev-Informational {{ color:var(--info); }}
</style></head>
<body>
<h1>JS Intelligence & Sensitive Info Report</h1>
<p>Domain: <b>{domain}</b> &nbsp;|&nbsp; Generated: {generated_at}</p>
<div class="stats">
  <div class="card"><div class="num">{subdomains}</div>Subdomains</div>
  <div class="card"><div class="num">{live_hosts}</div>Live Hosts</div>
  <div class="card"><div class="num">{js_files}</div>JS Files</div>
  <div class="card"><div class="num">{downloaded}</div>Downloaded</div>
  <div class="card"><div class="num">{finding_count}</div>Findings</div>
</div>
<table>
<thead><tr><th>Type</th><th>Severity</th><th>Detector</th><th>Confidence</th>
<th>Match Preview</th><th>Source</th><th>False Positive?</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body></html>"""

ROW_TEMPLATE = """<tr>
<td>{type}</td><td class="sev-{severity}">{severity}</td><td>{detector}</td>
<td>{confidence}</td><td><code>{match}</code></td><td>{source}</td><td>{fp}</td>
</tr>"""


def render_html(summary: dict) -> str:
    rows = []
    for f in summary["findings"]:
        rows.append(ROW_TEMPLATE.format(
            type=f.get("type", ""),
            severity=f.get("ai_severity") or f.get("severity", "Informational"),
            detector=f.get("detector", ""),
            confidence=f.get("confidence", "-"),
            match=f.get("match", ""),
            source=f.get("source", ""),
            fp=f.get("likely_false_positive", "-"),
        ))
    return HTML_TEMPLATE.format(
        domain=summary["domain"],
        generated_at=summary["generated_at"],
        subdomains=summary["subdomains"],
        live_hosts=summary["live_hosts"],
        js_files=summary["js_files"],
        downloaded=summary["downloaded"],
        finding_count=len(summary["findings"]),
        rows="\n".join(rows),
    )


def export_all(summary: dict, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "report.json").write_text(json.dumps(summary, indent=2, default=str))

    (out_dir / "report.html").write_text(render_html(summary))

    if summary["findings"]:
        fieldnames = sorted({k for f in summary["findings"] for k in f.keys()})
        with open(out_dir / "report.csv", "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(summary["findings"])

    return {
        "json": str(out_dir / "report.json"),
        "html": str(out_dir / "report.html"),
        "csv": str(out_dir / "report.csv") if summary["findings"] else None,
    }
