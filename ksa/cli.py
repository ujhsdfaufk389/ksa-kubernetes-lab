"""ksa-detector command-line interface (Part 28).

    ksa-detector scan   [--context ... | --directory ...] [--output reports]
    ksa-detector paths  --service-account dev/web-sa
    ksa-detector report [--output reports]

All collection is read-only. Against a real cluster, prefer --mode passive
(the default) which never mutates state or reads Secret values.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ksa.analyzer import Analyzer
from ksa.models import ClusterSnapshot

app = typer.Typer(add_completion=False, help="Kubernetes ServiceAccount privilege-escalation detector")
console = Console()

_SEV_COLOR = {"critical": "bold red", "high": "dark_orange", "medium": "yellow3",
              "low": "green", "info": "grey62"}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _load_snapshot(directory: Optional[str], kubeconfig: Optional[str],
                   context: Optional[str], namespaces: Optional[str]) -> tuple[ClusterSnapshot, str]:
    ns_list = [n.strip() for n in namespaces.split(",")] if namespaces else None
    if directory:
        from ksa.collector.directory_collector import DirectoryCollector
        return DirectoryCollector(directory).collect(), f"dir:{directory}"
    from ksa.collector.kubernetes_collector import KubernetesCollector
    snap = KubernetesCollector(kubeconfig=kubeconfig, context=context, namespaces=ns_list).collect()
    return snap, (context or "current-context")


@app.command()
def scan(
    context: Optional[str] = typer.Option(None, help="kube context, e.g. kind-ksa-lab"),
    kubeconfig: Optional[str] = typer.Option(None, help="path to kubeconfig"),
    directory: Optional[str] = typer.Option(None, help="offline: analyze a manifest directory"),
    namespaces: Optional[str] = typer.Option(None, help="comma-separated namespace filter"),
    output: str = typer.Option("reports", help="output directory"),
    max_hops: int = typer.Option(8, help="max escalation path length"),
    audit_log: Optional[str] = typer.Option(
        "cluster/audit/logs/audit.log", help="audit log for runtime correlation (live mode)"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Scan a cluster (or manifest dir), find escalation paths, write reports."""
    if verbose:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    with console.status("[cyan]Collecting cluster objects..."):
        snap, cluster = _load_snapshot(directory, kubeconfig, context, namespaces)
    audit = None if directory else (audit_log if audit_log and Path(audit_log).exists() else None)
    with console.status("[cyan]Building graph, finding paths, correlating audit..."):
        result = Analyzer(snap, max_hops=max_hops).scan_result(cluster=cluster, audit_path=audit)

    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "security-report.json").write_text(json.dumps(result, indent=2))
    (out / "graph.json").write_text(json.dumps(result["graph"], indent=2))
    _write_csv(out / "findings.csv", result["findings"])

    # snapshot for drift / attack-path diff, then show what changed since last scan
    from ksa.drift import diff, load_latest_two, write_snapshot
    write_snapshot(result, out / "history")
    prev, curr = load_latest_two(out / "history")
    _print_summary(result)
    if prev is not None:
        d = diff(prev, curr)
        c = d["counts"]
        if c["new"] or c["removed"]:
            console.print(f"\n[bold]Drift since last scan:[/] "
                          f"[red]+{c['new']} new[/] ({c['new_critical']} critical), "
                          f"[green]-{c['removed']} removed[/], {c['changed']} changed")
    console.print(f"\n[grey62]Reports written to[/] [cyan]{out}/security-report.json[/], "
                  f"[cyan]{out}/graph.json[/], [cyan]{out}/findings.csv[/]")


def _write_csv(path: Path, findings: list[dict]) -> None:
    import csv
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "severity", "risk_score", "confidence", "source", "target",
                    "primitive", "path_length", "mitre", "system_expected"])
        for f in findings:
            w.writerow([f["id"], f["severity"], f["risk_score"], f["confidence"],
                        f["source"], f["target"], f["primitive"], f["path"]["length"],
                        "; ".join(f["mitre"]), f["system_expected"]])


@app.command()
def paths(
    service_account: str = typer.Option(..., "--service-account", "-s", help="ns/name, e.g. dev/web-sa"),
    context: Optional[str] = typer.Option(None),
    kubeconfig: Optional[str] = typer.Option(None),
    directory: Optional[str] = typer.Option(None),
):
    """Show escalation paths for one ServiceAccount, fully explained."""
    snap, cluster = _load_snapshot(directory, kubeconfig, context, None)
    an = Analyzer(snap)
    sa_id = service_account if service_account.startswith("sa:") else f"sa:{service_account}"
    matches = [f for f in an.findings() if f.source == sa_id]
    if not matches:
        console.print(f"[green]No escalation paths found from[/] [cyan]{sa_id}[/].")
        raise typer.Exit()
    for f in matches:
        _print_finding(f)


@app.command()
def diff(output: str = typer.Option("reports", help="dir whose history/ holds snapshots")):
    """Show the attack-path drift between the two most recent scans."""
    from ksa.drift import diff as compute_diff
    from ksa.drift import load_latest_two
    prev, curr = load_latest_two(Path(output) / "history")
    if curr is None:
        console.print("[red]No snapshots yet. Run 'ksa-detector scan' at least twice.[/]")
        raise typer.Exit(1)
    if prev is None:
        console.print("[yellow]Only one snapshot exists — nothing to compare yet.[/]")
        raise typer.Exit()
    d = compute_diff(prev, curr)
    console.print(Panel(Text.assemble(
        ("Attack-path drift\n", "bold cyan"),
        (f"{d['previous_at']}  →  {d['current_at']}", "grey62"),
    ), border_style="cyan"))
    c = d["counts"]
    console.print(f"[red]+{c['new']} new[/] ({c['new_critical']} critical) · "
                  f"[green]-{c['removed']} removed[/] · {c['changed']} changed\n")
    for f in d["new_paths"]:
        console.print(f"  [red]NEW[/]  {f['source'].replace('sa:','')} → "
                      f"{f['target'].replace('sink:','')}  "
                      f"[magenta]{f['primitive']}[/] [grey62]({f['severity']})[/]")
    for f in d["removed_paths"]:
        console.print(f"  [green]GONE[/] {f['source'].replace('sa:','')} → "
                      f"{f['target'].replace('sink:','')}  [grey62]{f['primitive']}[/]")


@app.command()
def export(
    output: str = typer.Option("reports", help="dir containing security-report.json"),
    format: str = typer.Option("json", "--format", "-f", help="json | cef | syslog"),
    dest: Optional[str] = typer.Option(None, help="write to this file instead of stdout"),
):
    """Export findings for a SIEM (JSON lines, ArcSight CEF, or RFC5424 syslog)."""
    src = Path(output) / "security-report.json"
    if not src.exists():
        console.print(f"[red]No scan found at {src}. Run 'ksa-detector scan' first.[/]")
        raise typer.Exit(1)
    result = json.loads(src.read_text())
    lines = _siem_lines(result, format.lower())
    text = "\n".join(lines)
    if dest:
        Path(dest).write_text(text + "\n")
        console.print(f"[green]{len(lines)} events written to[/] [cyan]{dest}[/] [grey62]({format})[/]")
    else:
        print(text)


def _siem_lines(result: dict, fmt: str) -> list[str]:
    cluster = result.get("cluster", "")
    sev_num = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
    out: list[str] = []
    for f in result.get("findings", []):
        if fmt == "cef":
            # ArcSight Common Event Format
            ext = (f"src={f['source']} dst={f['target']} cs1Label=primitive cs1={f['primitive']} "
                   f"cs2Label=confidence cs2={f['confidence']} cs3Label=cluster cs3={cluster} "
                   f"cn1Label=risk cn1={f['risk_score']}")
            out.append(f"CEF:0|KSA|KSA-Detector|0.6|{f['primitive']}|{f['title']}|"
                       f"{sev_num.get(f['severity'],1)}|{ext}")
        elif fmt == "syslog":
            # RFC5424-ish structured line
            out.append(f"<{sev_num.get(f['severity'],1)}>1 {result.get('scanned_at','')} "
                       f"ksa-detector {f['id']} - - "
                       f"[ksa severity=\"{f['severity']}\" risk=\"{f['risk_score']}\" "
                       f"actor=\"{f['source']}\" target=\"{f['target']}\" "
                       f"primitive=\"{f['primitive']}\" confidence=\"{f['confidence']}\"] {f['title']}")
        else:  # json lines
            out.append(json.dumps({
                "id": f["id"], "cluster": cluster, "severity": f["severity"],
                "risk_score": f["risk_score"], "confidence": f["confidence"],
                "actor": f["source"], "target": f["target"], "primitive": f["primitive"],
                "mitre": f["mitre"], "scanned_at": result.get("scanned_at"),
            }))
    return out


@app.command()
def advanced(
    context: Optional[str] = typer.Option(None),
    kubeconfig: Optional[str] = typer.Option(None),
    directory: Optional[str] = typer.Option(None),
    audit_log: Optional[str] = typer.Option("cluster/audit/logs/audit.log"),
    output: str = typer.Option("reports", help="output directory"),
):
    """Research-grade analytics: blast radius, toxic identities, choke points +
    minimum-change remediation, toxic combos, invariants, cloud federation."""
    snap, _ = _load_snapshot(directory, kubeconfig, context, None)
    events = None
    if not directory and audit_log and Path(audit_log).exists():
        from ksa.collector.audit_collector import AuditCollector
        events = AuditCollector(audit_log).collect(limit=2000)
    adv = Analyzer(snap).advanced_analysis(audit_events=events)
    Path(output).mkdir(parents=True, exist_ok=True)
    (Path(output) / "advanced.json").write_text(json.dumps(adv, indent=2))

    inv = adv["invariants"]
    console.print(Panel(Text.assemble(("Advanced analytics", "bold cyan")), border_style="cyan"))
    console.print(f"[bold]Toxic identities (top 5):[/]")
    for r in adv["toxic_identities"][:5]:
        console.print(f"  {r['identity'].replace('sa:','')}  toxicity {r['toxicity']}  "
                      f"dist {r['privilege_distance']}  reach-in {r['reach_in']}")
    console.print(f"\n[bold]Minimum-change remediation:[/] {adv['min_fix']['fix_count']} removals "
                  f"break {adv['min_fix']['targeted_paths']} paths "
                  f"(remaining: {adv['min_fix']['paths_after']})")
    for fx in adv["min_fix"]["fixes"]:
        console.print(f"  remove [magenta]{fx['primitive']}[/] from "
                      f"[cyan]{fx['source'].replace('sa:','')}[/] [grey62]breaks {fx['breaks']}[/]")
    console.print(f"\n[bold]Toxic permission combinations:[/] {len(adv['toxic_combinations'])}")
    for t in adv["toxic_combinations"][:5]:
        console.print(f"  [yellow]{t['rule']}[/] on {t['source'].replace('sa:','')} "
                      f"@{','.join(t['namespaces'])}")
    if adv["cloud_escalations"]:
        console.print(f"\n[bold red]Kubernetes→Cloud escalations:[/] {len(adv['cloud_escalations'])}")
    fr = adv["fragility"]
    console.print(f"\n[bold]Privilege fragility:[/] {fr['fragility_score']}/100  "
                  f"security margin {fr['security_margin']}  "
                  f"({fr['exposed_identities']} identities one grant from admin)")
    onechg = sum(1 for c in adv["counterfactual"] if c["preventable_by_one_change"])
    console.print(f"[bold]Counterfactual:[/] {onechg}/{len(adv['counterfactual'])} top paths "
                  f"preventable by a single RBAC change")
    color = "green" if inv["failed"] == 0 else "red"
    console.print(f"\n[bold]Security invariants:[/] [{color}]{inv['passed']} pass / "
                  f"{inv['failed']} fail[/]")
    console.print(f"\n[grey62]Written to[/] [cyan]{output}/advanced.json[/]")


@app.command()
def invariants(
    context: Optional[str] = typer.Option(None),
    kubeconfig: Optional[str] = typer.Option(None),
    directory: Optional[str] = typer.Option(None),
    policy_file: Optional[str] = typer.Option(None, help="policy YAML (default: built-in config)"),
):
    """Verify continuous security invariants. Exit code 1 if any FAIL (CI gate)."""
    from ksa.analysis.invariants import check
    from ksa.policy import load as load_policy
    snap, _ = _load_snapshot(directory, kubeconfig, context, None)
    an = Analyzer(snap)
    res = check(an.action_graph, load_policy(policy_file))
    for r in res["results"]:
        mark = "[green]PASS[/]" if r["passed"] else "[red]FAIL[/]"
        console.print(f"{mark}  {r['id']} — {r['description']}")
        for v in r["violations"][:10]:
            console.print(f"       [red]violation:[/] {v.replace('sa:','')}")
    console.print(f"\n{res['passed']} pass / {res['failed']} fail")
    if res["failed"]:
        raise typer.Exit(1)


@app.command()
def whatif(
    candidate: str = typer.Option(..., "--candidate", "-c", help="manifest file/dir to simulate"),
    context: Optional[str] = typer.Option(None),
    kubeconfig: Optional[str] = typer.Option(None),
    directory: Optional[str] = typer.Option(None, help="base state from a manifest dir"),
):
    """Predict the attack-path impact of a change BEFORE applying it.
    Exit code 1 if it would introduce a critical path (CI/admission gate)."""
    from ksa.analysis.whatif import simulate
    snap, _ = _load_snapshot(directory, kubeconfig, context, None)
    r = simulate(snap, candidate)
    vcolor = {"DENY": "red", "WARN": "yellow", "ALLOW": "green"}[r["verdict"]]
    console.print(Panel(Text.assemble((f"What-if: {r['verdict']}", f"bold {vcolor}")),
                        border_style=vcolor))
    console.print(f"Escalation paths: {r['paths_before']} → {r['paths_after']}  "
                  f"(critical {r['critical_before']} → {r['critical_after']})")
    for f in r["new_paths"]:
        console.print(f"  [red]+NEW[/] {f['source'].replace('sa:','')} → "
                      f"{f['target'].replace('sink:','')}  [magenta]{f['primitive']}[/] "
                      f"[grey62]({f['severity']})[/]")
    for f in r["removed_paths"]:
        console.print(f"  [green]-GONE[/] {f['source'].replace('sa:','')} → "
                      f"{f['target'].replace('sink:','')}")
    if r["verdict"] == "DENY":
        raise typer.Exit(1)


@app.command(name="least-privilege")
def least_privilege(
    service_account: str = typer.Option(..., "--service-account", "-s", help="ns/name"),
    context: Optional[str] = typer.Option(None),
    kubeconfig: Optional[str] = typer.Option(None),
    directory: Optional[str] = typer.Option(None),
    audit_log: str = typer.Option("cluster/audit/logs/audit.log"),
):
    """Mine a minimal Role from what the SA actually used (vs. what it was granted)."""
    from ksa.analysis.leastpriv import analyze
    from ksa.collector.audit_collector import AuditCollector
    snap, _ = _load_snapshot(directory, kubeconfig, context, None)
    eff = Analyzer(snap)._effective
    sa_id = service_account if service_account.startswith("sa:") else f"sa:{service_account}"
    if sa_id not in eff:
        console.print(f"[red]Unknown ServiceAccount {sa_id}[/]")
        raise typer.Exit(1)
    events = AuditCollector(audit_log).collect(limit=5000) if Path(audit_log).exists() else []
    lp = analyze(sa_id, eff[sa_id], events)
    console.print(f"[bold]{sa_id}[/]  waste {int(lp.waste_ratio*100)}%  "
                  f"dormant={lp.dormant}  wildcard={lp.has_wildcard}")
    console.print(f"  granted {len(lp.granted)} · used {len(lp.used)} · unused {len(lp.unused)}")
    console.print("\n[grey62]Recommended least-privilege Role:[/]\n")
    console.print(lp.recommended_role_yaml)


@app.command()
def report(output: str = typer.Option("reports", help="dir containing security-report.json")):
    """Render an HTML report from a previous scan's security-report.json."""
    from ksa.report import render_html
    src = Path(output) / "security-report.json"
    if not src.exists():
        console.print(f"[red]No scan found at {src}. Run 'ksa-detector scan' first.[/]")
        raise typer.Exit(1)
    result = json.loads(src.read_text())
    dest = Path(output) / "security-report.html"
    dest.write_text(render_html(result))
    console.print(f"[green]HTML report:[/] [cyan]{dest}[/]")


# ---- pretty printing --------------------------------------------------------
def _print_summary(result: dict) -> None:
    s = result["summary"]
    sev = s["severity"]
    head = Text.assemble(
        ("KSA Detector  ", "bold cyan"),
        (f"· {result['cluster']}  ", "white"),
        (f"· {result['scanned_at']}", "grey62"),
    )
    body = Text()
    body.append(f"ServiceAccounts {s['service_accounts']}   ", "white")
    body.append(f"ClusterRoles {s['cluster_roles']}   ", "white")
    body.append(f"Bindings {s['bindings']}   ", "white")
    body.append(f"Graph {s['graph_nodes']}n/{s['graph_edges']}e\n", "grey62")
    body.append(f"Escalation paths: {s['escalation_paths']}  ", "bold white")
    body.append(f"({s['non_system_paths']} non-system)\n", "grey62")
    for k in _SEV_ORDER:
        if sev[k]:
            body.append(f" {k.upper()} {sev[k]} ", _SEV_COLOR[k])
    console.print(Panel(Text.assemble(head, "\n\n", body), border_style="cyan", padding=(1, 2)))

    t = Table(show_header=True, header_style="grey62", border_style="grey30", expand=True)
    t.add_column("ID", style="grey62", no_wrap=True)
    t.add_column("Sev", no_wrap=True)
    t.add_column("Risk", justify="right", no_wrap=True)
    t.add_column("Source", style="cyan")
    t.add_column("→ Target", style="red")
    t.add_column("Primitive", style="magenta")
    t.add_column("Conf", style="grey62", no_wrap=True)
    for f in result["findings"][:15]:
        sysmark = " [grey42](system)[/]" if f["system_expected"] else ""
        t.add_row(
            f["id"],
            Text(f["severity"].upper(), style=_SEV_COLOR[f["severity"]]),
            str(f["risk_score"]),
            f["source"].replace("sa:", "") + sysmark,
            f["target"].replace("sink:", ""),
            f["primitive"],
            f["confidence"],
        )
    console.print(t)


def _print_finding(f) -> None:
    color = _SEV_COLOR[f.severity]
    console.print(Panel(
        Text.assemble(
            (f"{f.id}  ", "grey62"), (f.title, "bold white"), "\n",
            (f"{f.severity.upper()} ", color), (f"· risk {f.risk_score}/100 · {f.confidence.label}", "white"),
        ),
        border_style=color.split()[-1] if " " in color else color,
    ))
    console.print(f"  [cyan]{f.source}[/]")
    for h in f.path.hops:
        loc = f" @{h.namespace}" if h.namespace else ""
        console.print(f"    [red]──[{h.edge_type}{loc}]──▶[/] {h.dst}")
        if h.action:
            console.print(f"       [grey54]{h.action}[/]")
    if getattr(f, "explanation", ""):
        console.print(f"  [grey62]Why:[/] {f.explanation}")
    console.print(f"  [grey62]MITRE:[/] {', '.join(f.mitre)}")
    console.print(f"  [grey62]Fix:[/] {f.remediation[0]}\n")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
