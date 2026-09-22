#!/usr/bin/env python3
"""
threat_intel_tool.py

THE ARZENS - Threat Intelligence Enrichment Tool (v1.0)

This is a beginner project for the AI, Automation & Security Engineering
internship track. It takes an indicator (IP, domain, file hash, or URL)
and checks it against VirusTotal and AbuseIPDB (AlienVault OTX is optional).

Author: Shawal
"""

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

import requests
import yaml
from colorama import Fore, Style, init as colorama_init

# turn on colorama so colors work on Windows too
colorama_init(autoreset=True)


# ---------------------------------------------------------------------------
# CONFIG LOADING
# ---------------------------------------------------------------------------

def load_config(config_path="config.yaml"):
    """Read the config.yaml file and return it as a dictionary."""
    if not os.path.exists(config_path):
        print(Fore.RED + f"Config file not found: {config_path}")
        sys.exit(1)

    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    return config


# ---------------------------------------------------------------------------
# CACHE (so we don't call the same API twice for the same indicator)
# ---------------------------------------------------------------------------

def load_cache(cache_file):
    """Load the JSON cache file if it exists, otherwise return an empty dict."""
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            # cache file got corrupted somehow, just start fresh
            return {}
    return {}


def save_cache(cache_file, cache_data):
    """Save the cache dictionary back to disk."""
    with open(cache_file, "w") as f:
        json.dump(cache_data, f, indent=2)


def make_cache_key(source, indicator):
    """Build a simple key like 'virustotal:1.2.3.4' for the cache dict."""
    return f"{source}:{indicator}"


# ---------------------------------------------------------------------------
# INPUT VALIDATION
# ---------------------------------------------------------------------------

def is_valid_ip(value):
    """Very simple IPv4 check (good enough for this project)."""
    pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    match = re.match(pattern, value)
    if not match:
        return False
    # each number part must be 0-255
    return all(0 <= int(part) <= 255 for part in match.groups())


def is_valid_domain(value):
    """Simple domain check, e.g. example.com"""
    pattern = r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, value) is not None


def is_valid_hash(value):
    """Accept MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars) hex strings."""
    if not re.match(r"^[a-fA-F0-9]+$", value):
        return False
    return len(value) in (32, 40, 64)


def is_valid_url(value):
    """Very basic URL check."""
    return value.startswith("http://") or value.startswith("https://")


def validate_indicator(indicator, indicator_type):
    """Return True/False depending on whether the indicator looks valid."""
    if indicator_type == "ip":
        return is_valid_ip(indicator)
    elif indicator_type == "domain":
        return is_valid_domain(indicator)
    elif indicator_type == "hash":
        return is_valid_hash(indicator)
    elif indicator_type == "url":
        return is_valid_url(indicator)
    return False


# ---------------------------------------------------------------------------
# RETRY LOGIC (exponential backoff)
# ---------------------------------------------------------------------------

def request_with_retry(method, url, headers=None, params=None, max_retries=3):
    """
    Make an HTTP request and retry with exponential backoff if it fails.
    Wait times: 2s, 4s, 8s (doubles each time).
    Returns the response object, or None if all retries fail.
    """
    wait_time = 2

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url, headers=headers, params=params, timeout=15)

            if response.status_code == 200:
                return response

            elif response.status_code == 401:
                print(Fore.RED + "  -> Unauthorized (401). Check your API key in config.yaml.")
                return None

            elif response.status_code == 429:
                print(Fore.YELLOW + f"  -> Rate limited (429). Waiting {wait_time}s before retry...")
                time.sleep(wait_time)
                wait_time *= 2

            elif response.status_code >= 500:
                print(Fore.YELLOW + f"  -> Server error ({response.status_code}). Retrying in {wait_time}s...")
                time.sleep(wait_time)
                wait_time *= 2

            else:
                print(Fore.YELLOW + f"  -> Unexpected status code {response.status_code}.")
                return response

        except requests.exceptions.RequestException as e:
            print(Fore.YELLOW + f"  -> Request failed ({e}). Retry {attempt}/{max_retries}...")
            time.sleep(wait_time)
            wait_time *= 2

    print(Fore.RED + "  -> Giving up after max retries.")
    return None


# ---------------------------------------------------------------------------
# API FUNCTIONS
# ---------------------------------------------------------------------------

def query_virustotal(indicator, indicator_type, api_key, max_retries):
    """
    Query VirusTotal for an IP, domain, or file hash.
    Returns a small dictionary with the results we care about.
    """
    headers = {"x-apikey": api_key}

    if indicator_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    elif indicator_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
    elif indicator_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{indicator}"
    else:
        return {"error": "VirusTotal does not support this indicator type in this tool"}

    response = request_with_retry("GET", url, headers=headers, max_retries=max_retries)

    if response is None:
        return {"error": "No response from VirusTotal"}

    if response.status_code == 404:
        return {"error": "Not found in VirusTotal"}

    if response.status_code != 200:
        return {"error": f"VirusTotal returned status {response.status_code}"}

    data = response.json()
    stats = data["data"]["attributes"].get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total_engines = sum(stats.values()) if stats else 0

    result = {
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "total_engines": total_engines,
        "detection_ratio": f"{malicious}/{total_engines}" if total_engines else "0/0",
    }

    # verdict based on how many engines flagged it
    if malicious >= 5:
        result["verdict"] = "MALICIOUS"
    elif malicious >= 1 or suspicious >= 1:
        result["verdict"] = "SUSPICIOUS"
    else:
        result["verdict"] = "CLEAN"

    return result


def query_abuseipdb(indicator, indicator_type, api_key, max_retries):
    """Query AbuseIPDB. Only works for IP addresses."""
    if indicator_type != "ip":
        return {"error": "AbuseIPDB only supports IP addresses"}

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": indicator, "maxAgeInDays": "90"}
    url = "https://api.abuseipdb.com/api/v2/check"

    response = request_with_retry("GET", url, headers=headers, params=params, max_retries=max_retries)

    if response is None:
        return {"error": "No response from AbuseIPDB"}

    if response.status_code != 200:
        return {"error": f"AbuseIPDB returned status {response.status_code}"}

    data = response.json()["data"]
    score = data.get("abuseConfidenceScore", 0)
    reports = data.get("totalReports", 0)

    result = {
        "confidence_score": score,
        "total_reports": reports,
        "last_reported": data.get("lastReportedAt"),
    }

    if score >= 75:
        result["verdict"] = "MALICIOUS"
    elif score >= 25:
        result["verdict"] = "SUSPICIOUS"
    else:
        result["verdict"] = "CLEAN"

    return result


def query_otx(indicator, indicator_type, api_key, max_retries):
    """Query AlienVault OTX for pulse (threat report) information."""
    headers = {"X-OTX-API-KEY": api_key}

    if indicator_type == "ip":
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general"
    elif indicator_type == "domain":
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general"
    elif indicator_type == "hash":
        url = f"https://otx.alienvault.com/api/v1/indicators/file/{indicator}/general"
    else:
        return {"error": "OTX does not support this indicator type in this tool"}

    response = request_with_retry("GET", url, headers=headers, max_retries=max_retries)

    if response is None:
        return {"error": "No response from OTX"}

    if response.status_code != 200:
        return {"error": f"OTX returned status {response.status_code}"}

    data = response.json()
    pulse_info = data.get("pulse_info", {})
    pulse_count = pulse_info.get("count", 0)

    # collect a few tags from the pulses, if there are any
    tags = []
    for pulse in pulse_info.get("pulses", [])[:5]:
        tags.extend(pulse.get("tags", []))
    tags = list(set(tags))[:5]  # keep it short, no duplicates

    result = {
        "pulse_count": pulse_count,
        "tags": tags,
    }

    if pulse_count >= 5:
        result["verdict"] = "MALICIOUS"
    elif pulse_count >= 1:
        result["verdict"] = "SUSPICIOUS"
    else:
        result["verdict"] = "CLEAN"

    return result


# ---------------------------------------------------------------------------
# MAIN ENRICHMENT LOGIC
# ---------------------------------------------------------------------------

def guess_indicator_type(indicator):
    """Try to figure out what kind of indicator this is, used for input files."""
    if is_valid_ip(indicator):
        return "ip"
    elif is_valid_url(indicator):
        return "url"
    elif is_valid_hash(indicator):
        return "hash"
    elif is_valid_domain(indicator):
        return "domain"
    return None


def combine_verdicts(source_results):
    """
    Look at the verdicts from each API and decide one overall verdict.
    Simple rule: if any source says MALICIOUS, overall is MALICIOUS.
    Otherwise if any source says SUSPICIOUS, overall is SUSPICIOUS.
    Otherwise CLEAN.
    """
    verdicts = [r.get("verdict") for r in source_results.values() if "verdict" in r]

    if "MALICIOUS" in verdicts:
        return "MALICIOUS"
    elif "SUSPICIOUS" in verdicts:
        return "SUSPICIOUS"
    elif verdicts:
        return "CLEAN"
    return "UNKNOWN"


def enrich_indicator(indicator, indicator_type, config, cache):
    """
    Run one indicator through all enabled APIs and return one combined
    result dictionary. Uses the cache to avoid duplicate API calls.
    """
    settings = config["settings"]
    keys = config["api_keys"]
    max_retries = settings.get("max_retries", 3)

    source_results = {}

    # --- VirusTotal ---
    if settings.get("use_virustotal", True) and indicator_type in ("ip", "domain", "hash"):
        cache_key = make_cache_key("virustotal", indicator)
        if cache_key in cache:
            print("  (using cached VirusTotal result)")
            source_results["virustotal"] = cache[cache_key]
        else:
            print("Checking VirusTotal...")
            result = query_virustotal(indicator, indicator_type, keys["virustotal"], max_retries)
            source_results["virustotal"] = result
            cache[cache_key] = result
            time.sleep(settings.get("rate_limit_seconds", 15))  # basic rate limiting

    # --- AbuseIPDB ---
    if settings.get("use_abuseipdb", True) and indicator_type == "ip":
        cache_key = make_cache_key("abuseipdb", indicator)
        if cache_key in cache:
            print("  (using cached AbuseIPDB result)")
            source_results["abuseipdb"] = cache[cache_key]
        else:
            print("Checking AbuseIPDB...")
            result = query_abuseipdb(indicator, indicator_type, keys["abuseipdb"], max_retries)
            source_results["abuseipdb"] = result
            cache[cache_key] = result
            time.sleep(settings.get("rate_limit_seconds", 15))

    # --- OTX (optional) ---
    if settings.get("use_otx", False) and indicator_type in ("ip", "domain", "hash"):
        cache_key = make_cache_key("otx", indicator)
        if cache_key in cache:
            print("  (using cached OTX result)")
            source_results["otx"] = cache[cache_key]
        else:
            print("Checking AlienVault OTX...")
            result = query_otx(indicator, indicator_type, keys["otx"], max_retries)
            source_results["otx"] = result
            cache[cache_key] = result
            time.sleep(settings.get("rate_limit_seconds", 15))

    overall_verdict = combine_verdicts(source_results)

    enrichment = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "query_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": source_results,
        "overall_verdict": overall_verdict,
    }

    return enrichment


# ---------------------------------------------------------------------------
# OUTPUT FUNCTIONS
# ---------------------------------------------------------------------------

def verdict_color(verdict):
    """Return the right colorama color for a verdict string."""
    if verdict == "MALICIOUS":
        return Fore.RED
    elif verdict == "SUSPICIOUS":
        return Fore.YELLOW
    elif verdict == "CLEAN":
        return Fore.GREEN
    return Fore.WHITE


def print_console_report(enrichment):
    """Print a human-readable report to the console, with colors."""
    print("\n" + "=" * 60)
    print("| THE ARZENS THREAT INTELLIGENCE ENRICHER v1.0")
    print("=" * 60)
    print(f"Indicator: {enrichment['indicator']} ({enrichment['indicator_type']})")
    print(f"Query Time: {enrichment['query_time']}")
    print("-" * 60)

    for source_name, result in enrichment["sources"].items():
        print(f"\n{source_name.upper()}:")
        if "error" in result:
            print(f"  Error: {result['error']}")
            continue
        for key, value in result.items():
            if key == "verdict":
                continue
            print(f"  {key}: {value}")
        v = result.get("verdict", "UNKNOWN")
        print(verdict_color(v) + f"  Verdict: {v}" + Style.RESET_ALL)

    overall = enrichment["overall_verdict"]
    print("\n" + "=" * 60)
    print(verdict_color(overall) + f"| OVERALL VERDICT: {overall}" + Style.RESET_ALL)

    if overall == "MALICIOUS":
        print("| Recommendation: Block immediately, investigate logs")
    elif overall == "SUSPICIOUS":
        print("| Recommendation: Monitor closely, investigate further")
    else:
        print("| Recommendation: No action needed at this time")
    print("=" * 60 + "\n")


def save_json_output(all_results, filename):
    """Save all enrichment results to a JSON file."""
    with open(filename, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"Saved JSON output to {filename}")


def save_csv_output(all_results, filename):
    """Save a simple CSV summary of all enrichment results."""
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["indicator", "type", "query_time", "overall_verdict", "sources_checked"])
        for item in all_results:
            sources_checked = ", ".join(item["sources"].keys())
            writer.writerow([
                item["indicator"],
                item["indicator_type"],
                item["query_time"],
                item["overall_verdict"],
                sources_checked,
            ])
    print(f"Saved CSV output to {filename}")


def save_text_report(all_results, filename):
    """Save a plain text report, similar to the console output."""
    with open(filename, "w") as f:
        for enrichment in all_results:
            f.write("=" * 60 + "\n")
            f.write(f"Indicator: {enrichment['indicator']} ({enrichment['indicator_type']})\n")
            f.write(f"Query Time: {enrichment['query_time']}\n\n")

            for source_name, result in enrichment["sources"].items():
                f.write(f"{source_name.upper()}:\n")
                if "error" in result:
                    f.write(f"  Error: {result['error']}\n\n")
                    continue
                for key, value in result.items():
                    if key == "verdict":
                        continue
                    f.write(f"  {key}: {value}\n")
                f.write(f"  Verdict: {result.get('verdict', 'UNKNOWN')}\n\n")

            f.write(f"OVERALL VERDICT: {enrichment['overall_verdict']}\n")
            f.write("=" * 60 + "\n\n")
    print(f"Saved text report to {filename}")


# ---------------------------------------------------------------------------
# CLI / ARGUMENT PARSING
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="THE ARZENS Threat Intelligence Enrichment Tool"
    )
    parser.add_argument("--ip", help="IP address to check")
    parser.add_argument("--domain", help="Domain to check")
    parser.add_argument("--hash", help="File hash to check (MD5/SHA1/SHA256)")
    parser.add_argument("--url", help="URL to check")
    parser.add_argument("--input-file", help="Text file with one indicator per line")
    parser.add_argument("--interactive", action="store_true", help="Enter indicators one by one")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--output", default="sample_output", help="Base name for output files")
    return parser.parse_args()


def gather_indicators_from_args(args):
    """Turn the CLI flags into a list of (indicator, type) tuples."""
    indicators = []
    if args.ip:
        indicators.append((args.ip, "ip"))
    if args.domain:
        indicators.append((args.domain, "domain"))
    if args.hash:
        indicators.append((args.hash, "hash"))
    if args.url:
        indicators.append((args.url, "url"))
    return indicators


def gather_indicators_from_file(path):
    """Read indicators from a text file, one per line, and guess their type."""
    indicators = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            indicator_type = guess_indicator_type(line)
            if indicator_type:
                indicators.append((line, indicator_type))
            else:
                print(Fore.YELLOW + f"Skipping unrecognized indicator: {line}")
    return indicators


def gather_indicators_interactively():
    """Ask the user to type indicators one at a time until they hit enter on empty."""
    indicators = []
    print("Interactive mode. Enter one indicator per line. Press Enter on an empty line to stop.")
    while True:
        value = input("Indicator (or blank to finish): ").strip()
        if not value:
            break
        indicator_type = guess_indicator_type(value)
        if indicator_type:
            indicators.append((value, indicator_type))
        else:
            print(Fore.YELLOW + "Could not tell what type of indicator that is, skipping.")
    return indicators


def main():
    args = parse_args()
    config = load_config(args.config)
    cache = load_cache(config["settings"].get("cache_file", "cache.json"))

    indicators = []
    indicators += gather_indicators_from_args(args)

    if args.input_file:
        indicators += gather_indicators_from_file(args.input_file)

    if args.interactive:
        indicators += gather_indicators_interactively()

    if not indicators:
        print(Fore.RED + "No indicators given. Use --ip, --domain, --hash, --url, --input-file, or --interactive.")
        sys.exit(1)

    all_results = []

    for indicator, indicator_type in indicators:
        if not validate_indicator(indicator, indicator_type):
            print(Fore.RED + f"Invalid {indicator_type}: {indicator} (skipping)")
            continue

        print(f"\nEnriching {indicator} ({indicator_type})...")
        enrichment = enrich_indicator(indicator, indicator_type, config, cache)
        all_results.append(enrichment)
        print_console_report(enrichment)

    # save the cache so next run can reuse these results
    save_cache(config["settings"].get("cache_file", "cache.json"), cache)

    if all_results:
        save_json_output(all_results, f"{args.output}.json")
        save_csv_output(all_results, f"{args.output}.csv")
        save_text_report(all_results, f"{args.output.replace('_output', '_report')}.txt")
    else:
        print(Fore.YELLOW + "No valid indicators were processed, no output files written.")


if __name__ == "__main__":
    main()
