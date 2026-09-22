#!/usr/bin/env python3
"""
bulk_analyzer.py

Workflow 2: Bulk Indicator Analysis

Reads a CSV file full of indicators, enriches every one of them using the
functions from threat_intel_tool.py, and produces:
- a detailed CSV of results
- an HTML report with summary statistics

If one indicator fails, the script prints a warning and keeps going
instead of crashing the whole batch.

Author: Shawal
"""

import argparse
import csv
from collections import Counter
from datetime import datetime, timezone

from colorama import Fore, Style, init as colorama_init

import threat_intel_tool as tit  # reuse the functions we already built

colorama_init(autoreset=True)


# ---------------------------------------------------------------------------
# STEP 1: READ THE INPUT CSV
# ---------------------------------------------------------------------------

def read_bulk_csv(path):
    """Read indicators from a CSV file with columns: indicator, type, source."""
    rows = []
    with open(path, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            indicator = row.get("indicator", "").strip()
            indicator_type = row.get("type", "").strip().lower()
            source = row.get("source", "").strip()
            if indicator:
                rows.append({"indicator": indicator, "type": indicator_type, "source": source})
    return rows


# ---------------------------------------------------------------------------
# STEP 2: PROCESS EVERY INDICATOR (skip failures, don't crash)
# ---------------------------------------------------------------------------

def process_all_indicators(rows, config, cache):
    """
    Enrich every indicator in the list, one at a time.
    Rate limiting already happens inside enrich_indicator (it sleeps
    between API calls), so we don't need to add extra sleep() here.
    """
    results = []

    for i, row in enumerate(rows, start=1):
        indicator = row["indicator"]
        indicator_type = row["type"] or tit.guess_indicator_type(indicator)

        print(f"[{i}/{len(rows)}] Processing {indicator} ({indicator_type})...")

        if not indicator_type or not tit.validate_indicator(indicator, indicator_type):
            print(Fore.YELLOW + f"  Skipping invalid indicator: {indicator}")
            continue

        try:
            enrichment = tit.enrich_indicator(indicator, indicator_type, config, cache)
            results.append(enrichment)
        except Exception as e:
            # something went wrong with this one indicator, log it and move on
            print(Fore.RED + f"  Failed to process {indicator}: {e}")
            continue

    return results


# ---------------------------------------------------------------------------
# STEP 3: BUILD SUMMARY STATISTICS
# ---------------------------------------------------------------------------

def build_summary_stats(results):
    """Work out totals, top tags, and most reported indicators."""
    total = len(results)
    clean = sum(1 for r in results if r["overall_verdict"] == "CLEAN")
    suspicious = sum(1 for r in results if r["overall_verdict"] == "SUSPICIOUS")
    malicious = sum(1 for r in results if r["overall_verdict"] == "MALICIOUS")

    # "top threat categories" - we use OTX tags for this, since that is
    # the only source in threat_intel_tool.py that returns tag/category data
    tag_counter = Counter()
    for r in results:
        otx_result = r["sources"].get("otx", {})
        for tag in otx_result.get("tags", []):
            tag_counter[tag] += 1
    top_categories = tag_counter.most_common(5)

    # "most reported indicators" - based on AbuseIPDB's total_reports number
    reported = []
    for r in results:
        abuse_result = r["sources"].get("abuseipdb", {})
        reports = abuse_result.get("total_reports")
        if reports is not None:
            reported.append((r["indicator"], reports))
    reported.sort(key=lambda pair: pair[1], reverse=True)
    top_reported = reported[:5]

    return {
        "total": total,
        "clean": clean,
        "suspicious": suspicious,
        "malicious": malicious,
        "top_categories": top_categories,
        "top_reported": top_reported,
    }


# ---------------------------------------------------------------------------
# STEP 4: SAVE OUTPUTS (detailed CSV + HTML report)
# ---------------------------------------------------------------------------

def save_detailed_csv(results, filename):
    """Save one row per indicator, with the verdict from each source."""
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "indicator", "type", "query_time",
            "virustotal_verdict", "abuseipdb_verdict", "otx_verdict",
            "overall_verdict",
        ])
        for r in results:
            sources = r["sources"]
            vt = sources.get("virustotal", {}).get("verdict", "N/A")
            abuse = sources.get("abuseipdb", {}).get("verdict", "N/A")
            otx = sources.get("otx", {}).get("verdict", "N/A")
            writer.writerow([
                r["indicator"], r["indicator_type"], r["query_time"],
                vt, abuse, otx, r["overall_verdict"],
            ])
    print(f"Saved detailed CSV to {filename}")


def build_html_report(stats, filename):
    """Write a simple HTML report showing the summary statistics."""
    category_rows = "".join(
        f"<tr><td>{tag}</td><td>{count}</td></tr>" for tag, count in stats["top_categories"]
    ) or "<tr><td colspan='2'>No tag data available</td></tr>"

    reported_rows = "".join(
        f"<tr><td>{indicator}</td><td>{count}</td></tr>" for indicator, count in stats["top_reported"]
    ) or "<tr><td colspan='2'>No report data available</td></tr>"

    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Bulk Threat Intelligence Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 30px; color: #222; }}
    h1 {{ color: #2c3e50; }}
    table {{ border-collapse: collapse; width: 60%; margin-bottom: 25px; }}
    th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
    th {{ background-color: #2c3e50; color: white; }}
    .clean {{ color: green; font-weight: bold; }}
    .suspicious {{ color: #b58900; font-weight: bold; }}
    .malicious {{ color: red; font-weight: bold; }}
  </style>
</head>
<body>
  <h1>Bulk Indicator Analysis Report</h1>
  <p>Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

  <h2>Summary</h2>
  <table>
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Total Indicators Processed</td><td>{stats['total']}</td></tr>
    <tr><td class="clean">Clean</td><td>{stats['clean']}</td></tr>
    <tr><td class="suspicious">Suspicious</td><td>{stats['suspicious']}</td></tr>
    <tr><td class="malicious">Malicious</td><td>{stats['malicious']}</td></tr>
  </table>

  <h2>Top Threat Categories (from OTX tags)</h2>
  <table>
    <tr><th>Tag</th><th>Count</th></tr>
    {category_rows}
  </table>

  <h2>Most Reported Indicators (from AbuseIPDB)</h2>
  <table>
    <tr><th>Indicator</th><th>Total Reports</th></tr>
    {reported_rows}
  </table>

</body>
</html>
"""
    with open(filename, "w") as f:
        f.write(html)
    print(f"Saved HTML report to {filename}")


# ---------------------------------------------------------------------------
# STEP 5: CONSOLE SUMMARY
# ---------------------------------------------------------------------------

def print_console_summary(stats):
    print("\n" + "=" * 50)
    print("BULK ANALYSIS SUMMARY")
    print("=" * 50)
    print(f"Total processed : {stats['total']}")
    print(Fore.GREEN + f"Clean           : {stats['clean']}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"Suspicious      : {stats['suspicious']}" + Style.RESET_ALL)
    print(Fore.RED + f"Malicious       : {stats['malicious']}" + Style.RESET_ALL)
    print("=" * 50 + "\n")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Bulk-enrich indicators from a CSV file")
    parser.add_argument("--input", default="sample_indicators_bulk.csv", help="CSV file of indicators")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--output", default="bulk_results", help="Base name for output files")
    args = parser.parse_args()

    config = tit.load_config(args.config)
    cache_file = config["settings"].get("cache_file", "cache.json")
    cache = tit.load_cache(cache_file)

    rows = read_bulk_csv(args.input)
    print(f"Loaded {len(rows)} indicators from {args.input}")

    results = process_all_indicators(rows, config, cache)

    tit.save_cache(cache_file, cache)  # save cache so next run reuses these results

    stats = build_summary_stats(results)
    print_console_summary(stats)

    save_detailed_csv(results, f"{args.output}.csv")
    build_html_report(stats, f"{args.output}.html")


if __name__ == "__main__":
    main()
