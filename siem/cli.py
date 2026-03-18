#!/usr/bin/env python3
"""
SIEM Analyzer — Command Line Interface
Colorful, rich terminal output using only the stdlib.
"""

import argparse
import sys
import os
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine        import SIEMEngine
from core.models        import Severity


# ── ANSI helpers ────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
MAGENTA= "\033[95m"
WHITE  = "\033[97m"
BG_RED = "\033[41m"

def c(text, *codes): return "".join(codes) + str(text) + RESET
def sev_color(sev: str) -> str:
    return {
        "CRITICAL": c(sev, BOLD, MAGENTA),
        "HIGH":     c(sev, BOLD, RED),
        "MEDIUM":   c(sev, BOLD, YELLOW),
        "LOW":      c(sev, BOLD, BLUE),
    }.get(sev, sev)


def banner():
    print(f"""
{c('╔══════════════════════════════════════════════════════════════╗', CYAN)}
{c('║', CYAN)}  {c('SIEM LOG ANALYZER', BOLD + WHITE)}  {c('v1.0', DIM)}  ·  Security Information & Event Manager  {c('║', CYAN)}
{c('╚══════════════════════════════════════════════════════════════╝', CYAN)}
""")


def print_section(title: str):
    w = 64
    print(f"\n{c('─' * w, DIM)}")
    print(f"  {c(title.upper(), BOLD + CYAN)}")
    print(f"{c('─' * w, DIM)}")


def print_summary(summary: dict, sources: list[str], event_count: int, elapsed: float):
    print_section("Analysis Summary")
    print(f"  {c('Files analyzed :', DIM)} {len(sources)}")
    for s in sources:
        print(f"    {c('→', DIM)} {s}")
    print(f"  {c('Events parsed  :', DIM)} {c(event_count, BOLD)}")
    print(f"  {c('Alerts raised  :', DIM)} {c(summary['total'], BOLD)}")
    print(f"  {c('Unique IPs     :', DIM)} {summary['unique_ips']}")
    print(f"  {c('Unique users   :', DIM)} {summary['unique_users']}")
    print(f"  {c('Analysis time  :', DIM)} {elapsed:.2f}s")
    print()

    # Severity breakdown bar
    total = summary["total"] or 1
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = summary.get(sev.lower(), 0)
        bar_len = int((count / total) * 30)
        bar = "█" * bar_len + "░" * (30 - bar_len)
        color = {"CRITICAL": MAGENTA, "HIGH": RED, "MEDIUM": YELLOW, "LOW": BLUE}[sev]
        print(f"  {sev_color(sev):<22}  {c(bar, color)}  {c(count, BOLD)}")


def print_alerts(alerts, max_show: int = 50):
    print_section(f"Alerts ({len(alerts)} total, showing top {min(len(alerts), max_show)})")

    shown = sorted(alerts, key=lambda a: -a.severity.score)[:max_show]

    for i, a in enumerate(shown, 1):
        sev_str = sev_color(a.severity.label)
        ts_str  = a.timestamp.strftime("%Y-%m-%d %H:%M:%S")

        print(f"\n  {c(f'[{i:02d}]', DIM)} {sev_str:<22}  {c(a.detector, CYAN)}  {c(a.alert_id, DIM)}")
        print(f"       {c(a.title, BOLD)}")
        print(f"       {c(a.description, DIM)}")
        print(f"       {c('Time:', DIM)} {ts_str}  ", end="")
        if a.source_ip:
            print(f"{c('IP:', DIM)} {a.source_ip}  ", end="")
        if a.user:
            print(f"{c('User:', DIM)} {a.user}  ", end="")
        if a.mitre_id:
            print(f"{c('MITRE:', DIM)} {a.mitre_id} ({a.mitre_tactic})  ", end="")
        print()

        if a.evidence:
            print(f"       {c('Evidence:', DIM)}", end=" ")
            for ev in a.evidence[:2]:
                snippet = str(ev)[:80].replace("\n", " ")
                print(f"\n         {c('»', DIM)} {snippet}", end="")
            print()


def print_top_attackers(top: list[dict]):
    if not top:
        return
    print_section("Top Threat Sources")
    for i, t in enumerate(top[:10], 1):
        score = t["score"]
        bar   = "█" * min(score, 20)
        sev_counts = {}
        for s in t["alerts"]:
            sev_counts[s] = sev_counts.get(s, 0) + 1
        detail = "  ".join(f"{sev_color(k)}: {v}" for k, v in sev_counts.items())
        ip_str  = c(t['ip'], BOLD)
        bar_str = c(bar, RED)
        sc_str  = c(score, BOLD)
        print(f"  {i:2d}.  {ip_str:<30}  {bar_str:<30}  score={sc_str}  {detail}")


def print_mitre(mitre: dict):
    if not mitre:
        return
    print_section("MITRE ATT&CK Coverage")
    for tactic, count in mitre.items():
        bar = "▪" * min(count, 30)
        print(f"  {c(tactic, CYAN):<30}  {bar}  ({count})")


def print_exports(json_path, csv_path):
    print_section("Exported Reports")
    print(f"  {c('JSON :', GREEN)} {json_path}")
    print(f"  {c('CSV  :', GREEN)} {csv_path}")


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="SIEM Log Analyzer — detect threats in log files",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "files", nargs="*",
        help="Log files to analyze (auto-detects type)",
    )
    parser.add_argument(
        "--parser", choices=["auth", "web", "windows", "json"],
        help="Force parser type for all files",
    )
    parser.add_argument(
        "--output-dir", default="reports",
        help="Directory for exported reports (default: reports/)",
    )
    parser.add_argument(
        "--no-export", action="store_true",
        help="Skip JSON/CSV export",
    )
    parser.add_argument(
        "--top", type=int, default=50,
        help="Max alerts to display (default: 50)",
    )
    parser.add_argument(
        "--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW", help="Minimum severity to display",
    )
    parser.add_argument(
        "--slack-webhook", default=None,
        help="Slack webhook URL for notifications",
    )
    parser.add_argument(
        "--web", action="store_true",
        help="Launch web dashboard after analysis",
    )
    parser.add_argument(
        "--port", type=int, default=5000,
        help="Port for web dashboard (default: 5000)",
    )

    args = parser.parse_args()

    if not args.files:
        # Check for sample logs
        sample_dir = Path(__file__).parent / "sample_logs"
        sample_files = list(sample_dir.glob("*"))
        if sample_files:
            print(f"  {c('No files specified. Using sample logs from', YELLOW)} {sample_dir}\n")
            args.files = [str(f) for f in sample_files]
        else:
            print(f"  {c('Usage:', BOLD)} python cli.py <log_file> [log_file2 ...] [options]")
            print(f"  {c('Example:', DIM)} python cli.py auth.log access.log events.json")
            print(f"  {c('Run', DIM)} python generate_samples.py {c('to create sample logs', DIM)}\n")
            sys.exit(0)

    engine = SIEMEngine(output_dir=args.output_dir)

    # Load files
    print(f"  {c('Loading log files...', DIM)}\n")
    for f in args.files:
        try:
            n = engine.load_file(f, parser=args.parser)
            print(f"  {c('✓', GREEN)} {f}  →  {c(n, BOLD)} events")
        except Exception as e:
            print(f"  {c('✗', RED)} {f}  →  {c(str(e), DIM)}")

    if engine.event_count == 0:
        print(f"\n  {c('No events parsed. Check file paths and formats.', YELLOW)}\n")
        sys.exit(1)

    print(f"\n  {c('Running detectors...', DIM)}")
    t0 = time.time()
    manager = engine.analyze()
    elapsed = time.time() - t0

    # Filter by min severity
    sev_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    min_score = sev_order[args.min_severity]
    alerts = [a for a in manager.alerts if a.severity.score >= min_score]

    summary = manager.summary()

    print_summary(summary, engine.sources, engine.event_count, elapsed)
    print_top_attackers(manager.top_attackers())
    print_mitre(manager.mitre_coverage())
    print_alerts(alerts, max_show=args.top)

    if not args.no_export:
        json_path = manager.export_json()
        csv_path  = manager.export_csv()
        print_exports(json_path, csv_path)

    if args.slack_webhook:
        ok = manager.notify_slack(args.slack_webhook)
        status = c("Sent", GREEN) if ok else c("Failed", RED)
        print(f"\n  {c('Slack notification:', DIM)} {status}")

    if args.web:
        print(f"\n  {c('Launching web dashboard...', CYAN)}")
        os.environ["SIEM_PREFILLED"] = "1"
        import subprocess
        subprocess.run([sys.executable, "app.py", "--port", str(args.port)])

    print(f"\n{c('Analysis complete.', GREEN + BOLD)}\n")


if __name__ == "__main__":
    main()
