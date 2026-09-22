#!/usr/bin/env python3
"""
normalizer.py

Reads a text file full of messy security logs (firewall, auth, dns, json
style events all mixed together) and turns them into clean, consistent
CSV and JSON files.

Author: Shawal Shamraiz
THE ARZENS - Beginner Track, Assignment 3, Task 2

Usage:
    python normalizer.py --input logs.txt --output-csv clean.csv --output-json clean.json
    python normalizer.py --input logs.txt --output-csv clean.csv --output-json clean.json --deduplicate
    python normalizer.py --input logs.txt --output-csv clean.csv --output-json clean.json --format firewall
"""

import argparse
import csv
import json
import re
import sys
from datetime import datetime

# these are the actions we know about. if something else shows up we just
# uppercase it and use it as-is instead of throwing it away
KNOWN_ACTIONS = {"ALLOW", "DENY", "SUCCESS", "FAILURE", "QUERY", "RESPONSE", "READ", "WRITE"}

# maps whatever raw "event" word shows up in the log to one of our 4
# categories. LOGIN/LOGOUT come from the auth logs, FILE_ACCESS from json etc
EVENT_TYPE_MAP = {
    "FIREWALL": "FIREWALL",
    "LOGIN": "AUTH",
    "LOGOUT": "AUTH",
    "AUTH": "AUTH",
    "DNS": "DNS",
    "QUERY": "DNS",
    "FILE_ACCESS": "FILE",
    "FILE": "FILE",
}

CSV_FIELDS = ["timestamp", "source_ip", "event_type", "user", "action", "target", "bytes", "status"]

# syslog-style logs (the DNS format in this project) don't include a year.
# we assume this year instead of reading the system clock, so the same
# input always produces the same output no matter when you run the script.
SYSLOG_YEAR_ASSUMPTION = 2026


# ---------------------------------------------------------------------
# small helper functions
# ---------------------------------------------------------------------

def is_valid_ipv4(ip):
    """Pretty basic check - just makes sure it's 4 numbers 0-255 separated by dots."""
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if int(part) > 255:
            return False
    return True


def is_private_ip(ip):
    """Checks the standard private ranges: 10.x, 172.16-31.x, 192.168.x"""
    parts = ip.split(".")
    first = int(parts[0])
    second = int(parts[1])
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    return False


def normalize_timestamp(raw_ts):
    """
    Tries a few known timestamp formats and converts to ISO 8601 UTC
    (YYYY-MM-DDTHH:MM:SSZ). Returns (normalized_string, True) if it
    worked, or (None, False) if nothing matched.
    """
    raw_ts = raw_ts.strip()

    # format 1: "2026-07-20 14:23:45"
    try:
        dt = datetime.strptime(raw_ts, "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ"), True
    except ValueError:
        pass

    # format 2: ISO 8601 like "2026-07-20T14:23:45Z"
    try:
        cleaned = raw_ts.rstrip("Z")
        dt = datetime.strptime(cleaned, "%Y-%m-%dT%H:%M:%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ"), True
    except ValueError:
        pass

    # format 3: syslog style "Jul 20 14:23:45" - no year in the log itself.
    # NOTE: we used to fill this in with datetime.now().year, but that
    # meant re-running the script on the exact same input file could give
    # a different (wrong) result depending on what year it happens to be
    # when you run it - which breaks reproducibility. Since all the sample
    # logs in this project are from 2026, we just assume that year instead
    # of asking the system clock. Not a perfect real-world solution, but
    # it makes results consistent every time this script runs.
    try:
        dt = datetime.strptime(f"{SYSLOG_YEAR_ASSUMPTION} {raw_ts}", "%Y %b %d %H:%M:%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ"), True
    except ValueError:
        pass

    return None, False


def normalize_action(raw_action):
    if not raw_action:
        return "UNKNOWN"
    upper = raw_action.strip().upper()
    return upper  # we don't reject unknown actions, just uppercase them


def normalize_event_type(raw_type):
    if not raw_type:
        return "UNKNOWN"
    upper = raw_type.strip().upper()
    return EVENT_TYPE_MAP.get(upper, upper)


# ---------------------------------------------------------------------
# format detection (for --format auto)
# ---------------------------------------------------------------------

def detect_format(line):
    stripped = line.strip()

    if stripped.startswith("{"):
        return "json"

    if stripped.startswith("[") and "FIREWALL" in stripped:
        return "firewall"

    # syslog style lines start with something like "Jul 20 14:23:45 "
    if re.match(r"^[A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2} ", stripped):
        return "dns"

    # auth logs start with an ISO timestamp followed by a comma
    if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z,", stripped):
        return "auth"

    return None


# ---------------------------------------------------------------------
# one parser function per log format
# each one either returns a dict of raw fields, or raises ValueError
# with a short explanation if the line doesn't match what we expect
# ---------------------------------------------------------------------

FIREWALL_PATTERN = re.compile(
    r"^\[(?P<timestamp>[\d\-: ]+)\]\s+FIREWALL\s+"
    r"src=(?P<src>[\d.]+)\s+dst=(?P<dst>[\d.]+)\s+"
    r"action=(?P<action>\w+)\s+port=(?P<port>\d+)\s+bytes=(?P<bytes>\d+)"
)


def parse_firewall(line):
    match = FIREWALL_PATTERN.match(line.strip())
    if not match:
        raise ValueError("line doesn't match the expected firewall log format")

    g = match.groupdict()
    return {
        "timestamp_raw": g["timestamp"],
        "source_ip": g["src"],
        "target": g["dst"],
        "action_raw": g["action"],
        "event_type_raw": "FIREWALL",
        "user": None,
        "port": int(g["port"]),
        "bytes_val": int(g["bytes"]),
    }


def parse_auth(line):
    parts = line.strip().split(",")
    if len(parts) != 6:
        raise ValueError(f"expected 6 comma-separated fields for an auth log, got {len(parts)}")

    raw_ts, host, event_name, user, ip, status = [p.strip() for p in parts]
    return {
        "timestamp_raw": raw_ts,
        "source_ip": ip,
        "target": host,
        "action_raw": status,
        "event_type_raw": event_name,
        "user": user,
        "port": None,
        "bytes_val": 0,
    }


DNS_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+named\[\d+\]:\s+query:\s+(?P<domain>\S+)\s+IN\s+\w+\s+from\s+(?P<ip>[\d.]+)"
)


def parse_dns(line):
    match = DNS_PATTERN.match(line.strip())
    if not match:
        raise ValueError("line doesn't match the expected dns log format")

    g = match.groupdict()
    return {
        "timestamp_raw": g["timestamp"],
        "source_ip": g["ip"],
        "target": g["domain"],
        "action_raw": "QUERY",
        "event_type_raw": "DNS",
        "user": None,
        "port": None,
        "bytes_val": 0,
    }


def parse_json_log(line):
    try:
        data = json.loads(line.strip())
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid json ({e})")

    return {
        "timestamp_raw": data.get("timestamp", ""),
        "source_ip": data.get("source_ip"),
        "target": data.get("target") or data.get("file"),
        "action_raw": data.get("action", ""),
        "event_type_raw": data.get("event", ""),
        "user": data.get("user"),
        "port": data.get("port"),
        "bytes_val": data.get("bytes", 0),
    }


PARSERS = {
    "firewall": parse_firewall,
    "auth": parse_auth,
    "dns": parse_dns,
    "json": parse_json_log,
}


# ---------------------------------------------------------------------
# turns the raw parsed fields into the final normalized record,
# doing all the validation along the way
# ---------------------------------------------------------------------

def build_record(raw, original_log):
    issues = []

    normalized_ts, ok = normalize_timestamp(raw["timestamp_raw"])
    if not ok:
        issues.append("unparseable timestamp")
        normalized_ts = "UNKNOWN"

    source_ip = raw.get("source_ip")
    if source_ip:
        if not is_valid_ipv4(source_ip):
            issues.append("invalid ip format")
            source_ip = "UNKNOWN"
        elif is_private_ip(source_ip):
            issues.append("private ip range")
    else:
        source_ip = "UNKNOWN"

    event_type = normalize_event_type(raw.get("event_type_raw", ""))
    action = normalize_action(raw.get("action_raw", ""))

    user = raw.get("user")
    user = user.strip() if user else "SYSTEM"

    target = raw.get("target")
    target = target.strip() if target else "UNKNOWN"

    bytes_val = raw.get("bytes_val")
    if bytes_val is None:
        bytes_val = 0
    if bytes_val < 0:
        issues.append("negative bytes value")
        bytes_val = 0

    port = raw.get("port")
    if port is not None and not (1 <= port <= 65535):
        issues.append("port out of valid range (1-65535)")

    status = "FLAGGED" if issues else "VALID"

    record = {
        "timestamp": normalized_ts,
        "source_ip": source_ip,
        "event_type": event_type,
        "user": user,
        "action": action,
        "target": target,
        "bytes": bytes_val,
        "status": status,
        "original_log": original_log,
    }
    return record, issues


# ---------------------------------------------------------------------
# output writers
# ---------------------------------------------------------------------

def write_csv(records, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for r in records:
            writer.writerow({key: r[key] for key in CSV_FIELDS})


def write_json(records, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)


def write_error_log(error_lines, path):
    with open(path, "w", encoding="utf-8") as f:
        if not error_lines:
            f.write("No parsing errors for this run.\n")
        else:
            for line in error_lines:
                f.write(line + "\n")


# ---------------------------------------------------------------------
# main
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Normalize messy security logs into clean CSV and JSON files."
    )
    parser.add_argument("--input", required=True, help="Path to the mixed/messy log file")
    parser.add_argument("--output-csv", required=True, help="Where to write the normalized CSV")
    parser.add_argument("--output-json", required=True, help="Where to write the normalized JSON")
    parser.add_argument(
        "--format",
        choices=["auto", "firewall", "auth", "dns", "json"],
        default="auto",
        help="Force a specific parser instead of auto-detecting (default: auto)"
    )
    parser.add_argument(
        "--deduplicate",
        action="store_true",
        help="Remove duplicate events (same timestamp, source_ip, and action)"
    )
    args = parser.parse_args()

    try:
        input_lines = open(args.input, "r", encoding="utf-8").readlines()
    except FileNotFoundError:
        print(f"Error: input file '{args.input}' was not found.")
        sys.exit(1)
    except PermissionError:
        print(f"Error: permission denied while reading '{args.input}'.")
        sys.exit(1)

    total_lines = 0
    parsed_count = 0
    skipped = 0
    duplicates_removed = 0
    error_lines = []
    seen_keys = set()
    final_records = []

    for line_number, raw_line in enumerate(input_lines, start=1):
        line = raw_line.rstrip("\n")

        if not line.strip():
            continue  # blank lines don't count toward anything

        total_lines += 1

        fmt = args.format if args.format != "auto" else detect_format(line)

        if fmt is None:
            skipped += 1
            msg = f"line {line_number}: could not detect a matching log format, skipping"
            print("WARNING:", msg)
            error_lines.append(msg)
            continue

        parse_func = PARSERS[fmt]
        try:
            raw_fields = parse_func(line)
        except ValueError as e:
            skipped += 1
            msg = f"line {line_number} ({fmt}): {e}"
            print("WARNING:", msg)
            error_lines.append(msg)
            continue

        record, issues = build_record(raw_fields, line)
        parsed_count += 1

        if args.deduplicate:
            dedup_key = (record["timestamp"], record["source_ip"], record["action"])
            if dedup_key in seen_keys:
                duplicates_removed += 1
                continue
            seen_keys.add(dedup_key)

        final_records.append(record)

    # sort by timestamp then source_ip so re-running the script on the
    # same input always produces the exact same file (this matters for
    # the reproducibility task later)
    final_records.sort(key=lambda r: (r["timestamp"], r["source_ip"]))

    write_csv(final_records, args.output_csv)
    write_json(final_records, args.output_json)
    write_error_log(error_lines, "parse_errors.log")

    print("--- Normalization Summary ---")
    print(f"Total lines read:      {total_lines}")
    print(f"Successfully parsed:   {parsed_count}")
    print(f"Skipped (malformed):   {skipped}")
    print(f"Duplicates removed:    {duplicates_removed}")
    print(f"CSV output:            {args.output_csv}")
    print(f"JSON output:           {args.output_json}")
    print(f"Error log:             parse_errors.log")


if __name__ == "__main__":
    main()
