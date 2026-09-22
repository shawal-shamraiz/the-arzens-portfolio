"""
metrics_calculator.py
----------------------
Simple security metrics calculator for Week 08-09 assignment (Task 5).

Reads a CSV of security events and prints/saves summary metrics.

Expected CSV columns:
    event_id, timestamp, severity, event_type, source_ip

Usage:
    python metrics_calculator.py sample_events.csv
"""

import sys
import csv
import json
from collections import Counter
from datetime import datetime


def load_events(csv_path):
    """Read the events CSV into a list of dicts."""
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def calculate_metrics(events):
    """Compute total events, counts by severity, peak hour, and top source IPs."""
    total_events = len(events)

    severity_counts = Counter(e["severity"] for e in events)
    # Keep a consistent, expected order for display
    severity_order = ["Critical", "High", "Medium", "Low"]
    by_severity = {sev: severity_counts.get(sev, 0) for sev in severity_order}

    # Events by hour (from the timestamp column, format: YYYY-MM-DD HH:MM:SS)
    hour_counts = Counter()
    for e in events:
        try:
            ts = datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S")
            hour_counts[ts.hour] += 1
        except (ValueError, KeyError):
            continue

    peak_hour, peak_count = (None, 0)
    if hour_counts:
        peak_hour, peak_count = hour_counts.most_common(1)[0]

    # Top 3 source IPs
    ip_counts = Counter(e["source_ip"] for e in events if e.get("source_ip"))
    top_ips = ip_counts.most_common(3)

    return {
        "total_events": total_events,
        "by_severity": by_severity,
        "peak_hour": f"{peak_hour:02d}:00" if peak_hour is not None else None,
        "peak_hour_count": peak_count,
        "top_source_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
        "events_by_hour": {f"{h:02d}:00": c for h, c in sorted(hour_counts.items())},
    }


def print_report(metrics):
    """Print the metrics as a simple console report."""
    print("Security Metrics Report")
    print("=" * 24)
    print(f"Total Events: {metrics['total_events']:,}")
    print()
    print("By Severity:")
    for sev, count in metrics["by_severity"].items():
        print(f"  {sev}: {count}")
    print()
    if metrics["peak_hour"]:
        print(f"Peak Hour: {metrics['peak_hour']} ({metrics['peak_hour_count']} events)")
    if metrics["top_source_ips"]:
        top = metrics["top_source_ips"][0]
        print(f"Top Source: {top['ip']} ({top['count']} events)")
        if len(metrics["top_source_ips"]) > 1:
            print("Other top sources:")
            for entry in metrics["top_source_ips"][1:]:
                print(f"  {entry['ip']} ({entry['count']} events)")


def save_json(metrics, out_path="metrics_summary.json"):
    with open(out_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "sample_events.csv"

    try:
        events = load_events(csv_path)
    except FileNotFoundError:
        print(f"CSV file not found: {csv_path}")
        sys.exit(1)

    if not events:
        print("No events found in CSV.")
        sys.exit(1)

    metrics = calculate_metrics(events)
    print_report(metrics)
    save_json(metrics)
