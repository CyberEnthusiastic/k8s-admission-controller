"""HTML report generator for the Kubernetes Admission Controller."""
import os
from html import escape


def generate_html(summary: dict, findings: list, output_path: str):
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    sev_colors = {"CRITICAL": "#ff3b30", "HIGH": "#ff9500", "MEDIUM": "#ffcc00", "LOW": "#34c759"}

    rows = []
    for i, f in enumerate(sorted(findings, key=lambda x: -x.risk_score)):
        color = sev_colors.get(f.severity, "#888")
        rows.append(f"""
        <div class="finding" data-severity="{f.severity}">
          <div class="fhead" onclick="toggleFinding({i})">
            <span class="sev" style="background:{color}">{f.severity}</span>
            <span class="fname">{escape(f.name)}</span>
            <span class="score">risk {f.risk_score}</span>
            <span class="chev">&#9656;</span>
          </div>
          <div class="fbody" id="fbody-{i}">
            <div class="row"><b>File:</b> <code>{escape(f.file)}</code></div>
            <div class="row"><b>Resource:</b> <code>{escape(f.kind)}/{escape(f.resource_name)}</code> (ns: <code>{escape(f.namespace)}</code>)</div>
            <div class="row"><b>Container:</b> <code>{escape(f.container) or '(pod-level)'}</code></div>
            <div class="row"><b>Rule:</b> {f.id} &nbsp; <b>CIS:</b> {escape(f.cis)}</div>
            <div class="row"><b>Evidence:</b> <code>{escape(f.evidence)}</code></div>
            <div class="row"><b>Remediation:</b> {escape(f.remediation)}</div>
            <div class="row"><b>Suggested fix:</b> <code>{escape(f.suggested_fix)}</code></div>
          </div>
        </div>
        """)

    by_sev = summary["by_severity"]
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>K8s Admission Controller Report</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#0d1117; color:#e6edf3; font-family:ui-sans-serif,system-ui,"Segoe UI",Roboto,sans-serif; margin:0; padding:24px; }}
  h1 {{ margin:0 0 8px; }}
  .meta {{ color:#8b949e; margin-bottom:20px; font-size:13px; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:24px; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:14px; }}
  .card .n {{ font-size:28px; font-weight:700; }}
  .card .l {{ color:#8b949e; font-size:12px; text-transform:uppercase; letter-spacing:.5px; }}
  .finding {{ background:#161b22; border:1px solid #30363d; border-radius:8px; margin-bottom:10px; }}
  .fhead {{ padding:10px 14px; cursor:pointer; display:flex; align-items:center; gap:10px; }}
  .fhead:hover {{ background:#1f242c; }}
  .sev {{ display:inline-block; color:#fff; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; }}
  .fname {{ flex:1; }}
  .score {{ color:#8b949e; font-size:12px; }}
  .chev {{ color:#8b949e; }}
  .fbody {{ display:none; padding:0 14px 14px; border-top:1px solid #30363d; }}
  .fbody.open {{ display:block; }}
  .row {{ margin:6px 0; font-size:13px; }}
  code {{ background:#0d1117; border:1px solid #30363d; padding:1px 6px; border-radius:4px; font-size:12px; }}
  .foot {{ color:#8b949e; margin-top:24px; font-size:12px; text-align:center; }}
</style></head><body>
  <h1>K8s Admission Controller Report</h1>
  <div class="meta">Generated {escape(summary["generated_at"])} &middot; {summary["total_findings"]} findings</div>
  <div class="cards">
    <div class="card"><div class="n" style="color:#ff3b30">{by_sev.get("CRITICAL",0)}</div><div class="l">Critical</div></div>
    <div class="card"><div class="n" style="color:#ff9500">{by_sev.get("HIGH",0)}</div><div class="l">High</div></div>
    <div class="card"><div class="n" style="color:#ffcc00">{by_sev.get("MEDIUM",0)}</div><div class="l">Medium</div></div>
    <div class="card"><div class="n" style="color:#34c759">{by_sev.get("LOW",0)}</div><div class="l">Low</div></div>
  </div>
  {''.join(rows)}
  <div class="foot">Kubernetes Admission Controller &middot; CyberEnthusiastic</div>
<script>
  function toggleFinding(i){{
    var el = document.getElementById('fbody-'+i);
    if(el) el.classList.toggle('open');
  }}
</script>
</body></html>"""
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
