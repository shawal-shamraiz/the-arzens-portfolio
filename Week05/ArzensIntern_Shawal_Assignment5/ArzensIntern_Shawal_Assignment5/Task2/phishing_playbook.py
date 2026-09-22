#!/usr/bin/env python3
"""
Phishing Response Playbook
Reads a reported email, extracts indicators, checks local threat intel,
scores risk, decides an action, writes a report, and logs everything.

Usage:
    python phishing_playbook.py --input-file sample_email.json
    python phishing_playbook.py --sender a@b.com --subject "..." --body "..." --attachment-hash <md5>
    python phishing_playbook.py --input-file sample_email.json --dry-run
    python phishing_playbook.py --rollback
"""

import argparse
import json
import logging
import os
import re
import sys
import uuid
from datetime import datetime, timezone

import yaml

CONFIG_PATH = "config.yaml"
QUARANTINE_STATE_FILE = "quarantine_state.json"

SUSPICIOUS_SUBJECT_KEYWORDS = [
    "urgent", "verify", "suspended", "password", "click here",
    "confirm", "account", "security alert", "act now", "limited time",
]

URL_REGEX = re.compile(r"https?://[^\s\"'<>]+")


# ---------- Setup ----------

def load_config(path):
    """Load YAML config. Falls back to safe defaults if the file is missing/broken."""
    defaults = {
        "thresholds": {"high": 70, "medium": 40},
        "notify": {"security_team": "security@company.com", "user_cc": True},
        "blacklist_path": "blacklist_domains.txt",
        "malware_hash_path": "malware_hashes.txt",
        "log_path": "playbook.log",
        "suspicious_keywords": SUSPICIOUS_SUBJECT_KEYWORDS,
        "api": {"virustotal_enabled": False, "virustotal_api_key_env": "VT_API_KEY"},
    }
    if not os.path.exists(path):
        print(f"[WARN] config.yaml not found at '{path}', using built-in defaults.")
        return defaults
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        # merge shallow so a partial config.yaml still works
        for key, val in defaults.items():
            data.setdefault(key, val)
        return data
    except yaml.YAMLError as e:
        print(f"[WARN] config.yaml could not be parsed ({e}); using built-in defaults.")
        return defaults


def setup_logging(log_path):
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    # also echo to console
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.WARNING)
    logging.getLogger().addHandler(console)


def load_lines(path):
    """Load a plain-text list file (one entry per line). Returns [] and warns if missing."""
    if not os.path.exists(path):
        logging.warning(f"Threat-intel file not found: {path}")
        print(f"[WARN] Missing threat-intel file: {path} (treating as empty list)")
        return []
    with open(path, "r") as f:
        return [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]


# ---------- Step 1: Input Reception ----------

def get_input(args):
    """Build the email dict from --input-file or individual CLI flags."""
    if args.input_file:
        if not os.path.exists(args.input_file):
            raise FileNotFoundError(f"Input file not found: {args.input_file}")
        with open(args.input_file, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Malformed JSON in {args.input_file}: {e}")
    else:
        data = {
            "sender": args.sender,
            "subject": args.subject,
            "body": args.body,
            "attachment_hash": args.attachment_hash,
            "reported_by": args.reported_by or "unknown",
        }

    validate_input(data)
    return data


def validate_input(data):
    required = ["sender", "subject", "body"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        raise ValueError(f"Missing required field(s): {', '.join(missing)}")
    if "@" not in data["sender"]:
        raise ValueError(f"Invalid sender email address: {data['sender']}")
    data.setdefault("attachment_hash", "")
    data.setdefault("reported_by", "unknown")


# ---------- Step 2: Indicator Extraction ----------

def extract_indicators(email, config):
    domain = email["sender"].split("@")[-1].lower()
    urls = URL_REGEX.findall(email.get("body", ""))
    subject_lower = email.get("subject", "").lower()
    keywords_found = [
        kw for kw in config["suspicious_keywords"] if kw.lower() in subject_lower
    ]
    return {
        "domain": domain,
        "urls": urls,
        "attachment_hash": email.get("attachment_hash", ""),
        "keywords_found": keywords_found,
    }


# ---------- Step 3: Reputation Checking ----------

def check_reputation(indicators, config):
    """Check domain/URLs/hash against local threat intel. Each check is isolated
    so a single failure doesn't stop the rest of the workflow."""
    result = {
        "domain_bad": False,
        "malicious_urls": [],
        "hash_known_malware": False,
        "errors": [],
    }

    try:
        blacklist = load_lines(config["blacklist_path"])
        result["domain_bad"] = indicators["domain"] in blacklist
    except Exception as e:
        result["errors"].append(f"domain check failed: {e}")
        logging.error(f"Domain reputation check failed: {e}")

    try:
        # Local heuristic + local blacklist for URLs (no external API required).
        for url in indicators["urls"]:
            url_domain = re.sub(r"^https?://", "", url).split("/")[0].lower()
            if url_domain in load_lines(config["blacklist_path"]) or "evil" in url_domain:
                result["malicious_urls"].append(url)
    except Exception as e:
        result["errors"].append(f"url check failed: {e}")
        logging.error(f"URL reputation check failed: {e}")

    try:
        if indicators["attachment_hash"]:
            hashes = load_lines(config["malware_hash_path"])
            result["hash_known_malware"] = indicators["attachment_hash"].lower() in hashes
    except Exception as e:
        result["errors"].append(f"hash check failed: {e}")
        logging.error(f"Hash reputation check failed: {e}")

    return result


# ---------- Step 4: Risk Scoring ----------

def calculate_risk(indicators, reputation):
    score = 0
    reasons = []

    if reputation["domain_bad"]:
        score += 40
        reasons.append("Known bad sender domain (+40)")

    if reputation["malicious_urls"]:
        score += 30
        reasons.append(f"Suspicious/malicious URL detected (+30): {reputation['malicious_urls']}")

    if reputation["hash_known_malware"]:
        score += 50
        reasons.append("Known malware attachment hash (+50)")

    if indicators["keywords_found"]:
        kw_points = 10 * len(indicators["keywords_found"])
        score += kw_points
        reasons.append(f"Suspicious subject keyword(s) {indicators['keywords_found']} (+{kw_points})")

    score = min(score, 100)
    return score, reasons


# ---------- Step 5: Decision & Action ----------

def decide(score, config):
    thresholds = config["thresholds"]
    if score >= thresholds["high"]:
        return "HIGH"
    if score >= thresholds["medium"]:
        return "MEDIUM"
    return "LOW"


def take_action(decision, email, run_id, dry_run, config):
    """Simulated actions only. Writes quarantine state so --rollback can undo it."""
    actions = []

    if decision == "HIGH":
        actions = ["quarantine_email", "block_sender", "notify_security_team"]
    elif decision == "MEDIUM":
        actions = ["hold_for_analyst_review", "notify_user"]
    else:
        actions = ["log_only", "deliver_with_warning"]

    if dry_run:
        print("  [DRY-RUN MODE - No actions taken]")
        print(f"  Would perform: {', '.join(actions)}")
        logging.info(f"Run {run_id}: DRY-RUN, would perform {actions}")
        return actions

    # Simulate performing the actions locally.
    for action in actions:
        logging.info(f"Run {run_id}: performed simulated action '{action}'")

    if "quarantine_email" in actions or "block_sender" in actions:
        save_quarantine_state(run_id, email, actions)

    return actions


def save_quarantine_state(run_id, email, actions):
    state = {
        "run_id": run_id,
        "sender": email["sender"],
        "actions": actions,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "restored": False,
    }
    with open(QUARANTINE_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def rollback(config):
    if not os.path.exists(QUARANTINE_STATE_FILE):
        print("[ROLLBACK] No quarantine state found — nothing to roll back.")
        return
    with open(QUARANTINE_STATE_FILE, "r") as f:
        state = json.load(f)
    if state.get("restored"):
        print(f"[ROLLBACK] Run {state['run_id']} was already rolled back.")
        return
    print(f"[ROLLBACK] Restoring sender '{state['sender']}' from run {state['run_id']}")
    print(f"  Reversing actions: {', '.join(state['actions'])}")
    state["restored"] = True
    with open(QUARANTINE_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)
    logging.info(f"Rollback executed for run {state['run_id']} (sender: {state['sender']})")
    print("[ROLLBACK] Complete.")


# ---------- Step 6: Notification ----------

def generate_report(run_id, email, indicators, score, reasons, decision, actions, dry_run, config):
    report_lines = [
        "=" * 60,
        "PHISHING RESPONSE - SECURITY REPORT",
        "=" * 60,
        f"Run ID: {run_id}",
        f"Timestamp: {datetime.now(timezone.utc).isoformat()}",
        f"Reported by: {email.get('reported_by', 'unknown')}",
        "",
        "-- Original Email --",
        f"Sender: {email['sender']}",
        f"Subject: {email['subject']}",
        f"Body: {email['body']}",
        f"Attachment hash: {email.get('attachment_hash') or 'N/A'}",
        "",
        "-- Extracted Indicators --",
        f"Domain: {indicators['domain']}",
        f"URLs: {indicators['urls']}",
        f"Keywords found: {indicators['keywords_found']}",
        "",
        f"Risk Score: {score}/100",
        "Reasons:",
    ] + [f"  - {r}" for r in reasons] + [
        "",
        f"Decision: {decision}",
        f"Actions {'(dry-run, not executed)' if dry_run else 'taken'}: {', '.join(actions)}",
    ]

    if decision == "MEDIUM":
        report_lines.append(f"Analyst review required: run_id={run_id}")

    report_text = "\n".join(report_lines)

    notify_to = config["notify"]["security_team"]
    print(f"  Security report generated for: {notify_to}")
    logging.info(f"Run {run_id}: local security report generated for {notify_to}")
    return report_text


# ---------- Main workflow ----------

def run_playbook(args):
    config = load_config(CONFIG_PATH)
    setup_logging(config["log_path"])
    run_id = f"playbook_run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"

    print("+" + "=" * 58 + "+")
    print("| PHISHING RESPONSE PLAYBOOK v1.0" + " " * 25 + "|")
    print("+" + "=" * 58 + "+")

    logging.info(f"=== Run {run_id} started ===")

    try:
        email = get_input(args)
    except (ValueError, FileNotFoundError) as e:
        print(f"[ERROR] Input validation failed: {e}")
        logging.error(f"Run {run_id}: input validation failed: {e}")
        sys.exit(1)

    print(f'Input: {email["sender"]} - "{email["subject"]}"')
    logging.info(f"Run {run_id}: input received from {email.get('reported_by')}")

    print("\nSTEP 1: Extracting indicators...")
    indicators = extract_indicators(email, config)
    print(f"  Domain: {indicators['domain']}")
    print(f"  URLs: {indicators['urls']}")
    print(f"  Hash: {indicators['attachment_hash'] or 'N/A'}")
    logging.info(f"Run {run_id}: indicators={indicators}")

    print("\nSTEP 2: Checking reputation...")
    reputation = check_reputation(indicators, config)
    print(f"  Domain bad: {reputation['domain_bad']}")
    print(f"  Malicious URLs: {reputation['malicious_urls']}")
    print(f"  Hash known malware: {reputation['hash_known_malware']}")
    if reputation["errors"]:
        print(f"  [WARN] Some checks failed but workflow continued: {reputation['errors']}")
    logging.info(f"Run {run_id}: reputation={reputation}")

    print("\nSTEP 3: Calculating risk score...")
    score, reasons = calculate_risk(indicators, reputation)
    for r in reasons:
        print(f"  {r}")
    decision = decide(score, config)
    print(f"  Total Risk Score: {score}/100 - {decision}")
    logging.info(f"Run {run_id}: score={score} decision={decision}")

    print("\nSTEP 4: Taking action...")
    actions = take_action(decision, email, run_id, args.dry_run, config)
    if not args.dry_run:
        print(f"  Performed: {', '.join(actions)}")

    print("\nSTEP 5: Generating report...")
    report_text = generate_report(
        run_id, email, indicators, score, reasons, decision, actions, args.dry_run, config
    )
    report_path = f"report_{run_id}.txt"
    with open(report_path, "w") as f:
        f.write(report_text)

    print(f"\nAUDIT LOG: {config['log_path']}")
    print(f"REPORT FILE: {report_path}")
    logging.info(f"=== Run {run_id} finished: decision={decision}, actions={actions} ===")


def main():
    parser = argparse.ArgumentParser(description="Phishing Response Playbook")
    parser.add_argument("--sender")
    parser.add_argument("--subject")
    parser.add_argument("--body")
    parser.add_argument("--attachment-hash", dest="attachment_hash", default="")
    parser.add_argument("--reported-by", dest="reported_by", default="")
    parser.add_argument("--input-file")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--rollback", action="store_true")
    args = parser.parse_args()

    if args.rollback:
        config = load_config(CONFIG_PATH)
        setup_logging(config["log_path"])
        rollback(config)
        return

    if not args.input_file and not (args.sender and args.subject and args.body):
        parser.error("Provide --input-file OR --sender/--subject/--body")

    run_playbook(args)


if __name__ == "__main__":
    main()
