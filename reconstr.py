"""
reconstr.py — Entry point
Usage: python reconstr.py --log sample_logs/auth.log --output output/graph.html
       python reconstr.py --log sample_logs/auth.log --no-graph           # CLI only
       python reconstr.py --log sample_logs/auth.log --timeline out.json  # also export JSON
"""

import argparse
import sys
import os
from modules.parser import parse_auth_log, summarize
from modules.grapher import build_graph, export_html, export_timeline_json
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


def print_banner():
    console.print("""
[bold magenta]██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗███████╗████████╗██████╗[/bold magenta]
[bold magenta]██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║██╔════╝╚══██╔══╝██╔══██╗[/bold magenta]
[bold bright_magenta]██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║███████╗   ██║   ██████╔╝[/bold bright_magenta]
[bold cyan]██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║╚════██║   ██║   ██╔══██╗[/bold cyan]
[bold cyan]██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║███████║   ██║   ██║  ██║[/bold cyan]
[bold blue]╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝[/bold blue]
[yellow]  github.com/[/yellow][bold bright_magenta]4thul-505[/bold bright_magenta]

[bold yellow]  reconstruct · correlate · expose[/bold yellow]
[dim]  session-aware · mitre-tagged · attack-staged · json-export     v0.2[/dim]
""")

def print_summary(events, summary):
    console.print(f"\n[bold cyan]── Event Summary ──────────────────────────[/bold cyan]")
    console.print(f"  Total events parsed : [bold]{summary['total_events']}[/bold]")

    span = summary.get("span_seconds", 0)
    if span:
        h, rem = divmod(int(span), 3600)
        m, s   = divmod(rem, 60)
        console.print(f"  Attack time span    : [bold]{h:02d}h {m:02d}m {s:02d}s[/bold]")

    console.print(f"  Unique attacker IPs : [bold red]{len(summary['unique_ips'])}[/bold red]  {summary['unique_ips']}")
    console.print(f"  Users seen          : [bold yellow]{summary['users_seen']}[/bold yellow]")
    console.print(f"  Sessions tracked    : [bold]{len(summary.get('sessions', []))}[/bold]")

    stages = summary.get("attack_stages", [])
    if stages:
        console.print(f"  Attack stages       : [bold magenta]{' → '.join(sorted(stages))}[/bold magenta]")

    # Brute force
    for ip, count in summary["brute_force_ips"].items():
        if count >= 3:
            console.print(f"\n  [bold red][!] Brute force detected:[/bold red] {ip} → {count} failed attempts")

    # Detection rule alerts
    detections = summary.get("detections", [])
    if detections:
        console.print(f"\n[bold red]── Detections Fired ────────────────────────[/bold red]")
        for det in detections:
            icon = {"brute_force":"🔨","impossible_travel":"✈ ","privesc_chain":"⬆ ","persistence_combo":"🔒","brute_then_success":"💥"}.get(det["rule"], "⚠ ")
            console.print(f"  {icon} [bold red]{det['rule'].upper()}[/bold red] — {det['description']}")
            console.print(f"     [dim]MITRE: {det['mitre']}[/dim]")

    # Critical events table
    if summary["critical_events"]:
        console.print(f"\n[bold red]── Critical Events ─────────────────────────[/bold red]")
        table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold magenta")
        table.add_column("Time",    style="dim", width=20)
        table.add_column("Stage",   width=22)
        table.add_column("Type",    width=14)
        table.add_column("User",    width=12)
        table.add_column("IP",      width=16)
        table.add_column("MITRE",   width=30)
        table.add_column("Command", width=36)

        for e in summary["critical_events"]:
            table.add_row(
                e.timestamp,
                f"[magenta]{e.attack_stage or '—'}[/magenta]",
                f"[red]{e.event_type}[/red]",
                e.user or "-",
                e.src_ip or "-",
                e.mitre or "-",
                (e.command[:33] + "...") if e.command and len(e.command) > 36 else (e.command or "-"),
            )
        console.print(table)


def main():
    parser = argparse.ArgumentParser(
        description="AttackPath — Reconstruct attacker movement from Linux logs"
    )
    parser.add_argument("--log",       required=True,                 help="Path to auth.log or syslog")
    parser.add_argument("--output",    default="output/graph.html",   help="Output HTML graph path")
    parser.add_argument("--timeline",  default=None,                  help="Also export a JSON timeline (e.g. output/timeline.json)")
    parser.add_argument("--no-graph",  action="store_true",           help="Skip graph generation, CLI only")
    args = parser.parse_args()

    print_banner()

    # Parse
    console.print(f"[*] Parsing log: [bold]{args.log}[/bold]")
    try:
        events = parse_auth_log(args.log)
    except FileNotFoundError:
        console.print(f"[bold red][!] File not found:[/bold red] {args.log}")
        sys.exit(1)

    if not events:
        console.print("[yellow][!] No matching events found. Check log format.[/yellow]")
        sys.exit(0)

    summary = summarize(events)
    print_summary(events, summary)

    # JSON timeline export
    timeline_path = args.timeline or (
        os.path.join(os.path.dirname(args.output), "timeline.json")
        if not args.no_graph else None
    )
    if timeline_path:
        export_timeline_json(events, timeline_path, detections=summary.get("detections", []))

    # Graph
    if not args.no_graph:
        console.print(f"\n[*] Building attack graph...")
        G, graph_data = build_graph(events)
        console.print(f"    Nodes: {len(graph_data['nodes'])}  |  Edges: {len(graph_data['edges'])}")
        export_html(graph_data, args.output, summary={
            "total":        summary["total_events"],
            "ips":          list(summary["unique_ips"]),
            "users":        list(summary["users_seen"]),
            "brute_force":  dict(summary["brute_force_ips"]),
            "detections":   summary.get("detections", []),
            "span_seconds": summary.get("span_seconds", 0),
            "sessions":     summary.get("sessions", []),
            "attack_stages":summary.get("attack_stages", []),
        })
        console.print(f"\n[bold green][+] Open in browser:[/bold green] {args.output}")
        if timeline_path:
            console.print(f"[bold green][+] JSON timeline  :[/bold green] {timeline_path}")


if __name__ == "__main__":
    main()
