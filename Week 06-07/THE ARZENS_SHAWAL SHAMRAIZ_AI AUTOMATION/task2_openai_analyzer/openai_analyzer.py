#!/usr/bin/env python3
"""
openai_analyzer.py — AI-assisted security log analyzer using OpenAI's GPT-4.

THE ARZENS Internship — Week 06, Task 2

Reads security log entries (from a file, stdin, or interactive input), sends
each entry (or batch of entries) to GPT-4 with a structured prompt, and
extracts: an event summary, a severity rating, and a recommended action.

Safety features:
  * --dry-run          : never calls the OpenAI API; uses a deterministic
                          mock analyzer instead, so the tool can be
                          demonstrated / graded without an API key or cost.
  * Cost tracking       : every real API call's estimated cost is appended
                          to cost_tracker.csv, with a running total.
  * Rate limiting       : a configurable minimum delay between API calls
                          (--rate-limit, default 1.0s) prevents accidental
                          bursts against the API.
  * Human oversight     : the tool only ever *recommends* an action. It never
                          performs blocking/containment itself.

Usage:
    python openai_analyzer.py --log-file sample_logs.txt --dry-run
    python openai_analyzer.py --log-file sample_logs.txt --format json
    python openai_analyzer.py                       # interactive mode
    python openai_analyzer.py --log-file logs.txt --model gpt-4 --rate-limit 2

Requires (for live mode only): OPENAI_API_KEY set in the environment or a
.env file (see .env.example). Install deps: pip install openai python-dotenv
"""

import argparse
import csv
import json
import os
import sys
import time
import re
import hashlib
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Optional dependency loading (kept optional so --dry-run works with zero
# third-party packages installed, which matters for grading/demo purposes).
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # .env loading is a convenience, not a hard requirement

OPENAI_AVAILABLE = True
try:
    from openai import OpenAI
except ImportError:
    OPENAI_AVAILABLE = False

# ---------------------------------------------------------------------------
# Cost model (approximate, USD per 1K tokens). Update if OpenAI pricing
# changes. Kept centralized so cost tracking has one source of truth.
# ---------------------------------------------------------------------------
MODEL_PRICING = {
    # model_name: (input $ / 1K tokens, output $ / 1K tokens)
    "gpt-4":         (0.030, 0.060),
    "gpt-4-turbo":   (0.010, 0.030),
    "gpt-4o":        (0.005, 0.015),
    "gpt-4o-mini":   (0.00015, 0.0006),
}
DEFAULT_MODEL = "gpt-4o-mini"  # cheap default; override with --model

SEVERITY_LEVELS = ["Informational", "Low", "Medium", "High", "Critical"]

PROMPT_TEMPLATE = """You are a security operations assistant helping a SOC analyst triage a raw
log entry. You do not take any action yourself — you only advise a human analyst.

Analyze the following log entry and respond with STRICT JSON only, no prose, no markdown
fences, matching exactly this schema:

{{
  "event_summary": "one or two sentence plain-English summary of what happened",
  "severity": "one of Informational, Low, Medium, High, Critical",
  "recommended_action": "one concrete next step a human analyst should take",
  "indicators": ["list", "of", "any", "IPs/domains/hashes/usernames found, empty if none"]
}}

Log entry:
---
{log_entry}
---
"""


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, min_interval_seconds: float):
        self.min_interval = min_interval_seconds
        self._last_call = 0.0

    def wait(self):
        elapsed = time.time() - self._last_call
        remaining = self.min_interval - elapsed
        if remaining > 0:
            time.sleep(remaining)
        self._last_call = time.time()


# ---------------------------------------------------------------------------
# Cost tracker
# ---------------------------------------------------------------------------
class CostTracker:
    FIELDS = ["timestamp", "model", "input_tokens", "output_tokens",
              "estimated_cost_usd", "running_total_usd"]

    def __init__(self, path: str):
        self.path = Path(path)
        self.running_total = 0.0
        if self.path.exists():
            with open(self.path, newline="") as f:
                rows = list(csv.DictReader(f))
                if rows:
                    self.running_total = float(rows[-1]["running_total_usd"])
        else:
            with open(self.path, "w", newline="") as f:
                csv.writer(f).writerow(self.FIELDS)

    def record(self, model: str, input_tokens: int, output_tokens: int) -> float:
        in_price, out_price = MODEL_PRICING.get(model, MODEL_PRICING[DEFAULT_MODEL])
        cost = (input_tokens / 1000.0) * in_price + (output_tokens / 1000.0) * out_price
        self.running_total += cost
        with open(self.path, "a", newline="") as f:
            csv.writer(f).writerow([
                datetime.now(timezone.utc).isoformat(),
                model, input_tokens, output_tokens,
                f"{cost:.6f}", f"{self.running_total:.6f}",
            ])
        return cost


# ---------------------------------------------------------------------------
# Analysis backends
# ---------------------------------------------------------------------------
def mock_analyze(log_entry: str) -> dict:
    """Deterministic, offline stand-in for the GPT-4 call. Used in --dry-run
    mode so the tool can be exercised without an API key or cost. Uses
    simple keyword heuristics rather than any real model."""
    lower = log_entry.lower()

    indicators = []
    indicators += re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_entry)          # IPv4
    indicators += re.findall(r"\b[a-f0-9]{32,64}\b", lower)                     # hashes
    indicators += re.findall(r"\buser=([\w\-.]+)", log_entry, re.IGNORECASE)     # usernames

    if any(k in lower for k in ["failed password", "authentication failure", "invalid user"]):
        severity = "Medium"
        summary = "Repeated or suspicious authentication failure detected."
        action = "Review source IP against recent login history; consider temporary lockout if repeated."
    elif any(k in lower for k in ["malware", "ransomware", "trojan", "exploit", "shellcode"]):
        severity = "Critical"
        summary = "Indicators of malware or active exploitation detected in log entry."
        action = "Isolate affected host immediately and escalate to incident response."
    elif any(k in lower for k in ["port scan", "nmap", "reconnaissance"]):
        severity = "Low"
        summary = "Network reconnaissance / scanning activity observed."
        action = "Log and monitor source IP; block if scanning continues or intensifies."
    elif any(k in lower for k in ["denied", "blocked", "dropped"]):
        severity = "Informational"
        summary = "Traffic was denied by an existing control; no immediate action indicated."
        action = "No action required; retain for trend analysis."
    else:
        severity = "Low"
        summary = "Log entry does not match a known high-risk pattern; manual review suggested."
        action = "Analyst should review the raw entry for context not captured by automated rules."

    return {
        "event_summary": summary,
        "severity": severity,
        "recommended_action": action,
        "indicators": sorted(set(indicators)),
    }


def openai_analyze(client, model: str, log_entry: str, cost_tracker: CostTracker) -> dict:
    prompt = PROMPT_TEMPLATE.format(log_entry=log_entry)
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=300,
    )
    usage = response.usage
    cost_tracker.record(model, usage.prompt_tokens, usage.completion_tokens)

    raw = response.choices[0].message.content.strip()
    raw = re.sub(r"^```(?:json)?|```$", "", raw, flags=re.MULTILINE).strip()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {
            "event_summary": "Model response could not be parsed as JSON.",
            "severity": "Low",
            "recommended_action": "Review raw model output manually.",
            "indicators": [],
        }
        parsed["_raw_model_output"] = raw
    return parsed


# ---------------------------------------------------------------------------
# Log reading
# ---------------------------------------------------------------------------
def read_log_entries(log_file: str | None) -> list[str]:
    if log_file:
        path = Path(log_file)
        if not path.exists():
            print(f"[!] Log file not found: {log_file}", file=sys.stderr)
            sys.exit(1)
        with open(path, "r", errors="replace") as f:
            lines = [line.rstrip("\n") for line in f if line.strip()]
        return lines

    # Interactive mode
    print("Interactive mode — paste one log entry per line. Enter an empty line to finish.")
    entries = []
    while True:
        try:
            line = input("> ")
        except EOFError:
            break
        if not line.strip():
            break
        entries.append(line)
    return entries


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------
def entry_id(log_entry: str) -> str:
    return hashlib.sha1(log_entry.encode()).hexdigest()[:10]


def print_console(results: list[dict]):
    for r in results:
        print("-" * 70)
        print(f"Entry ID     : {r['entry_id']}")
        print(f"Log          : {r['log_entry'][:100]}")
        print(f"Severity     : {r['severity']}")
        print(f"Summary      : {r['event_summary']}")
        print(f"Action       : {r['recommended_action']}")
        print(f"Indicators   : {', '.join(r['indicators']) if r['indicators'] else 'none'}")
    print("-" * 70)


def write_json(results: list[dict], out_path: str):
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] JSON written to {out_path}")


def write_csv(results: list[dict], out_path: str):
    fields = ["entry_id", "log_entry", "severity", "event_summary",
              "recommended_action", "indicators"]
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            row = dict(r)
            row["indicators"] = "; ".join(r["indicators"])
            writer.writerow({k: row[k] for k in fields})
    print(f"[+] CSV written to {out_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="AI-assisted security log analyzer (GPT-4).")
    parser.add_argument("--log-file", help="Path to a plaintext log file (one entry per line).")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                         help=f"OpenAI model to use (default: {DEFAULT_MODEL}).")
    parser.add_argument("--dry-run", action="store_true",
                         help="Do not call the OpenAI API; use offline heuristic analysis.")
    parser.add_argument("--rate-limit", type=float, default=1.0,
                         help="Minimum seconds between API calls (default: 1.0).")
    parser.add_argument("--format", choices=["console", "json", "csv", "all"], default="all",
                         help="Output format (default: all — console + json + csv).")
    parser.add_argument("--output-prefix", default="analysis_results",
                         help="Filename prefix for json/csv output.")
    parser.add_argument("--cost-log", default="cost_tracker.csv",
                         help="Path to the running cost tracker CSV.")
    parser.add_argument("--max-entries", type=int, default=None,
                         help="Optional cap on number of log entries processed (safety limit).")
    args = parser.parse_args()

    entries = read_log_entries(args.log_file)
    if not entries:
        print("[!] No log entries to analyze.", file=sys.stderr)
        sys.exit(1)
    if args.max_entries:
        entries = entries[: args.max_entries]

    cost_tracker = CostTracker(args.cost_log)
    limiter = RateLimiter(args.rate_limit)

    client = None
    if not args.dry_run:
        if not OPENAI_AVAILABLE:
            print("[!] openai package not installed. Install with `pip install openai`, "
                  "or run with --dry-run.", file=sys.stderr)
            sys.exit(1)
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            print("[!] OPENAI_API_KEY not set. Copy .env.example to .env and add your key, "
                  "or run with --dry-run.", file=sys.stderr)
            sys.exit(1)
        client = OpenAI(api_key=api_key)

    results = []
    for entry in entries:
        if args.dry_run:
            analysis = mock_analyze(entry)
        else:
            limiter.wait()
            analysis = openai_analyze(client, args.model, entry, cost_tracker)

        results.append({
            "entry_id": entry_id(entry),
            "log_entry": entry,
            **analysis,
        })

    if args.format in ("console", "all"):
        print_console(results)
    if args.format in ("json", "all"):
        write_json(results, f"{args.output_prefix}.json")
    if args.format in ("csv", "all"):
        write_csv(results, f"{args.output_prefix}.csv")

    print(f"\n[+] Analyzed {len(results)} entries. "
          f"Mode: {'DRY-RUN (offline heuristic)' if args.dry_run else args.model}")
    if not args.dry_run:
        print(f"[+] Running estimated API cost: ${cost_tracker.running_total:.4f} "
              f"(see {args.cost_log})")


if __name__ == "__main__":
    main()
