#!/usr/bin/env python3
"""
alert_enricher.py

Workflow 1: Alert Enrichment Pipeline

Reads one SOC alert (a JSON file), enriches the indicator in that alert
using the functions from threat_intel_tool.py, works out a simple risk
score, and saves an incident report in the incidents/ folder.

Author: Shawal
"""

import argparse
import json
import os
from datetime import datetime, timezone

from colorama import Fore, Style, init as colorama_init

import threat_intel_tool as tit  # reuse the functions we already built

colorama_init(autoreset=True)


# ---------------------------------------------------------------------------
# STEP 1: LOAD THE ALERT
# ---------------------------------------------------------------------------

def load_alert(path):
    """Read the alert JSON file and return it as a dictionary."""
    with open(path, "r") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# STEP 2: RISK SCORING (our own simple algorithm)
# ---------------------------------------------------------------------------

def calculate_risk_score(enrichment, severity):
    """
    Work out a risk score from 0 to 100.

    The idea:
    - start with points based on the overall verdict
    - add points based on how severe the original alert was
    - add a few bonus points based on the raw numbers from each API
    - never go above 100
    """
    verdict = enrichment["overall_verdict"]

    if verdict == "MALICIOUS":
        score = 60
    elif verdict == "SUSPICIOUS":
        score = 30
    else:
        score = 5

    severity_points = {"low": 5, "medium": 10, "high": 20, "critical": 25}
    score += severity_points.get(severity.lower(), 10)

    sources = enrichment["sources"]

    vt = sources.get("virustotal", {})
    if "malicious_count" in vt:
        score += min(vt["malicious_count"], 15)  # cap the bonus at 15

    abuse = sources.get("abuseipdb", {})
    if "confidence_score" in abuse:
        score += abuse["confidence_score"] // 10  # 0-10 bonus points

    otx = sources.get("otx", {})
    if "pulse_count" in otx:
        score += min(otx["pulse_count"], 10)

    return min(score, 100)


def risk_level(score):
    """Turn the numeric score into a simple label."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    return "LOW"


def recommended_actions(score):
    """Return a short list of next steps based on the risk score."""
    if score >= 80:
        return [
            "IMMEDIATE: Block the indicator at the firewall",
            "INVESTIGATE: Check internal hosts that contacted this indicator",
            "HUNT: Search logs for similar indicators",
            "ESCALATE: Notify a Tier 2 analyst",
        ]
    elif score >= 50:
        return [
            "INVESTIGATE: Review related logs and connections",
            "MONITOR: Watch this indicator closely for the next 24-48 hours",
        ]
    elif score >= 25:
        return ["MONITOR: Add this indicator to a watchlist"]
    else:
        return ["IGNORE: No action needed, indicator looks clean"]


# ---------------------------------------------------------------------------
# STEP 3: BUILD AND SAVE THE INCIDENT REPORT
# ---------------------------------------------------------------------------

def make_incident_id():
    """Build an incident ID like INC-20260801-143005."""
    now = datetime.now(timezone.utc)
    return f"INC-{now.strftime('%Y%m%d-%H%M%S')}"


def format_source_line(source_name, result):
    """Turn one API's result into a single readable line."""
    if "error" in result:
        return f"  [{source_name}] Error: {result['error']}"

    verdict = result.get("verdict", "UNKNOWN")

    if source_name == "virustotal":
        return f"  [VirusTotal] {result.get('detection_ratio', 'N/A')} detections - {verdict}"
    elif source_name == "abuseipdb":
        return (
            f"  [AbuseIPDB] Confidence: {result.get('confidence_score', 'N/A')}/100, "
            f"{result.get('total_reports', 'N/A')} reports - {verdict}"
        )
    elif source_name == "otx":
        return f"  [AlienVault OTX] {result.get('pulse_count', 'N/A')} pulses, tags: {result.get('tags', [])} - {verdict}"
    return f"  [{source_name}] {result}"


def build_report_text(alert, enrichment, score, level, actions, incident_id):
    """Put together the full text of the incident report."""
    lines = []
    lines.append("=" * 55)
    lines.append(f"INCIDENT REPORT: {incident_id}")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append("=" * 55)
    lines.append("")
    lines.append("ALERT DETAILS:")
    lines.append(f"  Type: {alert.get('alert_type', 'Unknown')}")
    lines.append(f"  Indicator: {alert.get('indicator')}")
    lines.append(f"  Severity: {alert.get('severity', 'unknown')}")
    lines.append(f"  Source: {alert.get('source', 'unknown')}")
    lines.append("")
    lines.append("ENRICHMENT RESULTS:")
    for source_name, result in enrichment["sources"].items():
        lines.append(format_source_line(source_name, result))
    lines.append("")
    lines.append(f"OVERALL VERDICT: {enrichment['overall_verdict']}")
    lines.append(f"RISK SCORE: {score}/100 ({level})")
    lines.append("")
    lines.append("RECOMMENDED ACTIONS:")
    for i, action in enumerate(actions, start=1):
        lines.append(f"  {i}. {action}")
    lines.append("=" * 55)
    return "\n".join(lines)


def save_incident_report(report_text, incident_id, folder="incidents"):
    """Save the report text into the incidents folder. Returns the file path."""
    os.makedirs(folder, exist_ok=True)
    filename = os.path.join(folder, f"{incident_id}.txt")
    with open(filename, "w") as f:
        f.write(report_text)
    return filename


# ---------------------------------------------------------------------------
# STEP 4: CONSOLE SUMMARY
# ---------------------------------------------------------------------------

def print_console_summary(alert, enrichment, score, level, saved_path):
    """Print a short colored summary of what happened."""
    verdict = enrichment["overall_verdict"]
    color = tit.verdict_color(verdict)

    print("\n" + "-" * 50)
    print(f"Alert type : {alert.get('alert_type')}")
    print(f"Indicator  : {alert.get('indicator')}")
    print(color + f"Verdict    : {verdict}" + Style.RESET_ALL)
    print(color + f"Risk Score : {score}/100 ({level})" + Style.RESET_ALL)
    print(f"Report     : {saved_path}")
    print("-" * 50 + "\n")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Enrich one SOC alert and create an incident report")
    parser.add_argument("--alert", default="sample_alert.json", help="Path to the alert JSON file")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    args = parser.parse_args()

    config = tit.load_config(args.config)
    cache_file = config["settings"].get("cache_file", "cache.json")
    cache = tit.load_cache(cache_file)

    alert = load_alert(args.alert)

    indicator = alert["indicator"]
    indicator_type = alert.get("indicator_type") or tit.guess_indicator_type(indicator)

    if not indicator_type or not tit.validate_indicator(indicator, indicator_type):
        print(Fore.RED + f"Alert indicator looks invalid: {indicator}")
        return

    print(f"Enriching alert indicator: {indicator} ({indicator_type})")
    enrichment = tit.enrich_indicator(indicator, indicator_type, config, cache)

    tit.save_cache(cache_file, cache)  # save cache so next run reuses this result

    severity = alert.get("severity", "medium")
    score = calculate_risk_score(enrichment, severity)
    level = risk_level(score)
    actions = recommended_actions(score)
    incident_id = make_incident_id()

    report_text = build_report_text(alert, enrichment, score, level, actions, incident_id)
    saved_path = save_incident_report(report_text, incident_id)

    print_console_summary(alert, enrichment, score, level, saved_path)


if __name__ == "__main__":
    main()
