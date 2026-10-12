"""Standalone HTML report generator (Part 29).

Renders a scan_result dict into a single self-contained dark-themed HTML file
(no external assets) suitable for sharing, printing, or the FYP appendix.
"""
from __future__ import annotations

import html

_SEV = {"critical": "#FB5C6B", "high": "#F5A524", "medium": "#EBCB4B", "low": "#35C08A", "info": "#5E6E88"}


def _esc(s: str) -> str:
    return html.escape(str(s))


def _finding_html(f: dict) -> str:
    c = _SEV.get(f["severity"], "#5E6E88")
    hops = []
    src = f["source"].replace("sa:", "")
    hops.append(f'<span class="hn src">{_esc(src)}</span>')
    for h in f["path"]["hops"]:
        loc = f' @{h["namespace"]}' if h.get("namespace") else ""
        dst = h["to"].replace("sa:", "").replace("sink:", "")
        sink = "sink" if h["to"].startswith("sink:") else ""
        hops.append(f'<span class="verb">{_esc(h["type"])}{_esc(loc)}</span>')
        hops.append(f'<span class="hn {sink}">{_esc(dst)}</span>')
    flow = '<span class="arr">▶</span>'.join(hops)
    mitre = "".join(f'<span class="mtag">{_esc(m)}</span>' for m in f["mitre"])
    fixes = "".join(f"<li>{_esc(x)}</li>" for x in f["remediation"])
    ev = f.get("evidence", {})
    evrows = "".join(f'<div class="ev">{_esc(b)}</div>' for b in (ev.get("bindings", []) + ev.get("roles", []))[:8])
    sysbadge = '<span class="sys">system controller — expected</span>' if f["system_expected"] else ""
    return f"""
    <div class="finding" style="--c:{c}">
      <div class="fhead">
        <div><span class="fid">{_esc(f['id'])}</span><span class="ftitle">{_esc(f['title'])}</span>{sysbadge}</div>
        <div class="frisk"><span class="sev" style="color:{c}">{_esc(f['severity'].upper())}</span>
          <b>{f['risk_score']}</b><small>/100</small> · {_esc(f['confidence'])}</div>
      </div>
      <div class="flow">{flow}</div>
      <div class="cols2">
        <div><h4>Evidence</h4>{evrows or '<div class="ev">—</div>'}</div>
        <div><h4>MITRE ATT&CK</h4><div class="mitre">{mitre}</div>
          <h4 style="margin-top:14px">Remediation</h4><ul class="fix">{fixes}</ul></div>
      </div>
    </div>"""


def render_html(result: dict) -> str:
    s = result["summary"]
    sev = s["severity"]
    total = max(1, s["escalation_paths"])
    bar = "".join(
        f'<span style="flex:{sev[k]};background:{_SEV[k]}"></span>'
        for k in ("critical", "high", "medium", "low") if sev[k]
    )
    legend = "".join(
        f'<div class="lg"><span class="sw" style="background:{_SEV[k]}"></span>{k.title()} <b>{sev[k]}</b></div>'
        for k in ("critical", "high", "medium", "low")
    )
    findings = "".join(_finding_html(f) for f in result["findings"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KSA Escalation Report — {_esc(result['cluster'])}</title>
<style>
:root{{--bg:#0B0E14;--panel:#111722;--panel2:#161E2B;--border:#232D3D;--ink:#E7ECF5;--ink2:#93A1B8;--ink3:#5E6E88;--accent:#4C8DFF}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);
font-family:"IBM Plex Sans",system-ui,sans-serif;line-height:1.5;padding:32px}}
.wrap{{max-width:980px;margin:0 auto}}
h1{{font-family:"Chivo",sans-serif;font-size:24px;margin:0 0 4px}}
.meta{{font-family:"IBM Plex Mono",monospace;color:var(--ink3);font-size:12.5px;margin-bottom:24px}}
.kpis{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:20px}}
.kpi{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px 18px;flex:1;min-width:130px}}
.kpi .v{{font-family:"Chivo",sans-serif;font-size:28px;font-weight:700}}
.kpi .l{{color:var(--ink3);font-size:11px;text-transform:uppercase;letter-spacing:.07em}}
.sevbar{{display:flex;height:13px;border-radius:7px;overflow:hidden;gap:2px;margin:6px 0 10px}}
.legend{{display:flex;gap:18px;font-size:13px;color:var(--ink2);margin-bottom:26px}}
.legend .sw{{width:10px;height:10px;border-radius:3px;display:inline-block;margin-right:6px}}
.finding{{background:var(--panel);border:1px solid var(--border);border-left:3px solid var(--c);
border-radius:12px;padding:18px;margin-bottom:16px}}
.fhead{{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:12px}}
.fid{{font-family:"IBM Plex Mono",monospace;color:var(--ink3);font-size:11px;margin-right:10px}}
.ftitle{{font-weight:600}}.sys{{font-family:"IBM Plex Mono",monospace;font-size:10px;color:var(--ink3);
border:1px solid var(--border);padding:2px 7px;border-radius:5px;margin-left:8px}}
.frisk{{font-family:"IBM Plex Mono",monospace;font-size:13px;color:var(--ink2)}}
.frisk b{{font-family:"Chivo",sans-serif;font-size:18px}}.sev{{font-weight:700;margin-right:8px}}
.flow{{display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:12px;background:#0C121C;
border-radius:9px;margin-bottom:14px;font-family:"IBM Plex Mono",monospace;font-size:12px}}
.hn{{background:var(--panel2);border:1px solid var(--border);border-radius:7px;padding:5px 10px}}
.hn.src{{border-color:var(--accent)}}.hn.sink{{border-color:#FB5C6B;color:#ffd9dd}}
.verb{{color:#FB5C6B;font-size:10.5px}}.arr{{color:var(--ink3)}}
.cols2{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
h4{{font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--ink3);margin:0 0 8px}}
.ev{{font-family:"IBM Plex Mono",monospace;font-size:11.5px;color:var(--ink2);margin-bottom:5px}}
.mtag{{font-family:"IBM Plex Mono",monospace;font-size:11px;background:var(--panel2);border:1px solid var(--border);
border-radius:6px;padding:3px 8px;color:#22C7B8;display:inline-block;margin:0 5px 5px 0}}
.fix{{margin:0;padding-left:18px;color:var(--ink2);font-size:12.5px}}.fix li{{margin-bottom:5px}}
@media(max-width:640px){{.cols2{{grid-template-columns:1fr}}}}
</style></head><body><div class="wrap">
<h1>Kubernetes ServiceAccount Escalation Report</h1>
<div class="meta">{_esc(result['cluster'])} · {_esc(result['scanned_at'])} · passive observer</div>
<div class="kpis">
  <div class="kpi"><div class="v">{s['service_accounts']}</div><div class="l">Service Accounts</div></div>
  <div class="kpi"><div class="v">{s['escalation_paths']}</div><div class="l">Escalation Paths</div></div>
  <div class="kpi"><div class="v">{s['non_system_paths']}</div><div class="l">Non-system</div></div>
  <div class="kpi"><div class="v" style="color:{_SEV['critical']}">{sev['critical']}</div><div class="l">Critical</div></div>
</div>
<div class="sevbar">{bar}</div>
<div class="legend">{legend}</div>
<h2 style="font-family:Chivo,sans-serif;font-size:16px">Findings</h2>
{findings}
</div></body></html>"""
