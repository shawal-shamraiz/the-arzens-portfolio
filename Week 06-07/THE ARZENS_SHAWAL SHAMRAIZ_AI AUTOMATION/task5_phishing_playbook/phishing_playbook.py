#!/usr/bin/env python3
"""
phishing_playbook.py — Automated phishing response SOAR playbook.

THE ARZENS Internship — Week 07, Task 5

Pipeline: input email -> indicator extraction -> reputation check
(local blacklist + optional VirusTotal) -> risk scoring (0-100) ->
tiered decision (High=auto-block, Medium=analyst review, Low=log only)
-> notification -> audit log (playbook.log).

Safety features:
  * --dry-run     : runs the full pipeline but never performs a real block
                     or sends a real email; the would-be action is logged
                     instead. This is the DEFAULT — you must pass --live to
                     perform a real containment action.
  * --rollback    : reverses a previous auto-block by case ID, restoring the
                     blacklist and recording the reversal (who/why) in the
                     audit log.
  * Input validation: sender/URL/hash formats are checked before use; a
                     malformed email record is rejected, not guessed at.

Usage:
    python phishing_playbook.py --email-file sample_email.json --dry-run
    python phishing_playbook.py --email-file sample_email.json --live
    python phishing_playbook.py --rollback CASE-2026-0001
    python phishing_playbook.py --email-file sample_email.json --config config.yaml
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

try:
    import requests
except ImportError:
    requests = None

DEFAULT_CONFIG = {
    "blacklist_file": "blacklist_domains.txt",
    "active_blocks_file": "active_blocks.json",
    "playbook_log": "playbook.log",
    "log_retention_days": 180,
    "risk_thresholds": {"high": 70, "medium": 30},
    "virustotal": {
        "enabled": False,
        "api_key_env": "VIRUSTOTAL_API_KEY",
        "max_requests_per_minute": 4,
    },
    "notification": {
        "security_team_email": "secops@example.com",
        "send_real_email": False,
    },
}

URL_RE = re.compile(r"https?://[^\s\"'<>]+[^\s\"'<>.,;:!?)\]]", re.IGNORECASE)
HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def load_config(path: str) -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    p = Path(path)
    if p.exists() and yaml is not None:
        with open(p) as f:
            user_cfg = yaml.safe_load(f) or {}

        def deep_merge(base, override):
            for k, v in override.items():
                if isinstance(v, dict) and isinstance(base.get(k), dict):
                    deep_merge(base[k], v)
                else:
                    base[k] = v
        deep_merge(cfg, user_cfg)
    elif p.exists() and yaml is None:
        print("[!] PyYAML not installed; using default config. `pip install pyyaml`.",
              file=sys.stderr)
    return cfg


# ---------------------------------------------------------------------------
# Audit logging (append-only, one JSON object per line)
# ---------------------------------------------------------------------------
def audit_log(log_path: str, event: dict):
    event = {"timestamp": datetime.now(timezone.utc).isoformat(), **event}
    with open(log_path, "a") as f:
        f.write(json.dumps(event) + "\n")


# ---------------------------------------------------------------------------
# Input validation + indicator extraction
# ---------------------------------------------------------------------------
def validate_email(record: dict) -> list[str]:
    errors = []
    sender = record.get("sender", "")
    if not sender or not EMAIL_RE.match(sender):
        errors.append(f"Invalid or missing sender address: {sender!r}")
    if not any(record.get(f) for f in ("body", "urls", "attachment_hash")):
        errors.append("Email record has no body, urls, or attachment_hash to analyze.")
    ah = record.get("attachment_hash")
    if ah and not HASH_RE.match(ah):
        errors.append(f"attachment_hash does not look like a valid MD5/SHA1/SHA256 hash: {ah!r}")
    return errors


def extract_indicators(record: dict) -> dict:
    sender = record.get("sender", "")
    sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""

    body = record.get("body", "") or ""
    urls_in_body = URL_RE.findall(body)
    urls_field = record.get("urls", []) or []
    all_urls = sorted(set(urls_in_body + urls_field))

    url_domains = []
    for u in all_urls:
        m = re.match(r"https?://([^/]+)", u, re.IGNORECASE)
        if m:
            url_domains.append(m.group(1).lower())

    attachment_hash = record.get("attachment_hash", "") or ""

    return {
        "sender": sender,
        "sender_domain": sender_domain,
        "urls": all_urls,
        "url_domains": sorted(set(url_domains)),
        "attachment_hash": attachment_hash,
    }


# ---------------------------------------------------------------------------
# Reputation checking
# ---------------------------------------------------------------------------
def load_blacklist(path: str) -> set:
    p = Path(path)
    if not p.exists():
        return set()
    with open(p) as f:
        return {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}


class VTRateLimiter:
    """Enforces VirusTotal's free-tier request/minute cap."""
    def __init__(self, max_per_minute: int):
        self.max_per_minute = max_per_minute
        self.calls = []

    def wait_if_needed(self):
        now = time.time()
        self.calls = [t for t in self.calls if now - t < 60]
        if len(self.calls) >= self.max_per_minute:
            sleep_for = 60 - (now - self.calls[0])
            if sleep_for > 0:
                time.sleep(sleep_for)
        self.calls.append(time.time())


def check_virustotal(domain: str, api_key: str, limiter: VTRateLimiter) -> dict | None:
    """Best-effort VirusTotal domain lookup. Returns None on any failure so a
    network problem never crashes the playbook — it just falls back to
    local-blacklist-only reputation."""
    if requests is None:
        return None
    try:
        limiter.wait_if_needed()
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": api_key},
            timeout=8,
        )
        if resp.status_code != 200:
            return None
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
    except Exception:
        return None


def check_reputation(indicators: dict, blacklist: set, cfg: dict, dry_run: bool) -> dict:
    findings = {"blacklist_hits": [], "virustotal_hits": [], "vt_checked": False}

    candidates = [indicators["sender_domain"]] + indicators["url_domains"]
    for domain in filter(None, candidates):
        if domain in blacklist:
            findings["blacklist_hits"].append(domain)

    vt_cfg = cfg.get("virustotal", {})
    if vt_cfg.get("enabled") and not dry_run:
        api_key = os.environ.get(vt_cfg.get("api_key_env", "VIRUSTOTAL_API_KEY"))
        if api_key:
            findings["vt_checked"] = True
            limiter = VTRateLimiter(vt_cfg.get("max_requests_per_minute", 4))
            for domain in filter(None, set(candidates)):
                result = check_virustotal(domain, api_key, limiter)
                if result and (result["malicious"] > 0 or result["suspicious"] > 0):
                    findings["virustotal_hits"].append({"domain": domain, **result})
        else:
            findings["vt_checked"] = False  # no key -> silently skip, don't fail the run
    return findings


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------
def score_risk(indicators: dict, reputation: dict) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    if reputation["blacklist_hits"]:
        score += 50
        reasons.append(f"Domain(s) on local blacklist: {', '.join(reputation['blacklist_hits'])}")

    if reputation["virustotal_hits"]:
        score += 40
        vt_domains = ", ".join(h["domain"] for h in reputation["virustotal_hits"])
        reasons.append(f"VirusTotal flagged domain(s) as malicious/suspicious: {vt_domains}")

    if indicators["attachment_hash"]:
        score += 15
        reasons.append("Email includes an attachment hash for a suspicious/unsolicited file.")

    if len(indicators["urls"]) >= 3:
        score += 10
        reasons.append(f"Email contains {len(indicators['urls'])} embedded URLs (link-heavy).")

    lookalike_domains = [d for d in ([indicators["sender_domain"]] + indicators["url_domains"])
                         if d and any(kw in d for kw in ["-secure", "-verify", "-support", "login-"])]
    if lookalike_domains:
        score += 15
        reasons.append(f"Domain(s) use a common phishing lookalike pattern: {', '.join(lookalike_domains)}")

    score = min(score, 100)
    if not reasons:
        reasons.append("No indicators matched known bad patterns; treat as low risk.")
    return score, reasons


def decide(score: int, thresholds: dict) -> str:
    if score >= thresholds["high"]:
        return "High"
    elif score >= thresholds["medium"]:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
def generate_case_id() -> str:
    return f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{os.urandom(2).hex()}"


def apply_high_action(indicators: dict, cfg: dict, case_id: str, dry_run: bool) -> dict:
    action = {
        "type": "auto_block",
        "targets": {
            "domains": [d for d in ([indicators["sender_domain"]] + indicators["url_domains"]) if d],
            "hash": indicators["attachment_hash"] or None,
        },
        "executed": False,
    }
    if dry_run:
        action["note"] = "DRY-RUN: block was NOT applied. Re-run with --live to enforce."
        return action

    active_blocks_path = Path(cfg["active_blocks_file"])
    blocks = []
    if active_blocks_path.exists():
        blocks = json.loads(active_blocks_path.read_text())
    blocks.append({
        "case_id": case_id,
        "targets": action["targets"],
        "blocked_at": datetime.now(timezone.utc).isoformat(),
    })
    active_blocks_path.write_text(json.dumps(blocks, indent=2))
    action["executed"] = True
    action["note"] = "Domains/hash added to active_blocks.json (simulated enforcement point)."
    return action


def rollback_case(case_id: str, cfg: dict) -> bool:
    active_blocks_path = Path(cfg["active_blocks_file"])
    if not active_blocks_path.exists():
        print(f"[!] No active blocks file found at {active_blocks_path}.")
        return False
    blocks = json.loads(active_blocks_path.read_text())
    remaining = [b for b in blocks if b["case_id"] != case_id]
    if len(remaining) == len(blocks):
        print(f"[!] Case {case_id} not found in active blocks.")
        return False
    active_blocks_path.write_text(json.dumps(remaining, indent=2))
    audit_log(cfg["playbook_log"], {
        "event": "rollback",
        "case_id": case_id,
        "actor": os.environ.get("USER", "unknown_analyst"),
        "note": "High-severity auto-block reversed via --rollback.",
    })
    print(f"[+] Case {case_id} rolled back. Block removed from {active_blocks_path}.")
    return True


def send_notification(record: dict, severity: str, score: int, reasons: list, cfg: dict,
                       dry_run: bool) -> dict:
    notif_cfg = cfg.get("notification", {})
    subject = f"[Phishing Playbook] {severity} severity case — sender {record.get('sender')}"
    body_lines = [
        f"Severity: {severity} (score {score}/100)",
        f"Sender: {record.get('sender')}",
        f"Subject: {record.get('subject')}",
        "Reasons:",
    ] + [f"  - {r}" for r in reasons]
    body = "\n".join(body_lines)

    if dry_run or not notif_cfg.get("send_real_email", False):
        print("\n--- NOTIFICATION (not sent, dry-run/simulated) ---")
        print(f"To: {notif_cfg.get('security_team_email')}")
        print(f"Subject: {subject}")
        print(body)
        print("--- end notification ---\n")
        return {"sent": False, "to": notif_cfg.get("security_team_email"), "subject": subject}

    # Real SMTP sending intentionally not implemented here — left as an
    # integration point so this reference tool doesn't need live mail
    # credentials to be graded/demoed.
    print("[!] send_real_email is True but SMTP integration is not configured in this "
          "reference implementation; notification was only printed above.")
    return {"sent": False, "to": notif_cfg.get("security_team_email"), "subject": subject}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Automated phishing response playbook.")
    parser.add_argument("--email-file", help="Path to a JSON file with the reported email.")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml.")
    parser.add_argument("--dry-run", action="store_true", default=True,
                         help="(default) Do not perform real blocks or send real email.")
    parser.add_argument("--live", action="store_true",
                         help="Disable dry-run: perform real containment actions.")
    parser.add_argument("--rollback", metavar="CASE_ID",
                         help="Roll back a previous auto-block by case ID.")
    args = parser.parse_args()

    cfg = load_config(args.config)
    dry_run = not args.live

    if args.rollback:
        success = rollback_case(args.rollback, cfg)
        sys.exit(0 if success else 1)

    if not args.email_file:
        print("[!] --email-file is required (or use --rollback CASE_ID).", file=sys.stderr)
        sys.exit(1)

    email_path = Path(args.email_file)
    if not email_path.exists():
        print(f"[!] Email file not found: {args.email_file}", file=sys.stderr)
        sys.exit(1)
    record = json.loads(email_path.read_text())

    errors = validate_email(record)
    if errors:
        for e in errors:
            print(f"[!] Validation error: {e}", file=sys.stderr)
        audit_log(cfg["playbook_log"], {
            "event": "validation_failed", "errors": errors, "raw_input": record,
        })
        sys.exit(1)

    case_id = generate_case_id()
    indicators = extract_indicators(record)
    blacklist = load_blacklist(cfg["blacklist_file"])
    reputation = check_reputation(indicators, blacklist, cfg, dry_run)
    score, reasons = score_risk(indicators, reputation)
    severity = decide(score, cfg["risk_thresholds"])

    action_result = {"type": "log_only", "executed": False}
    if severity == "High":
        action_result = apply_high_action(indicators, cfg, case_id, dry_run)
    elif severity == "Medium":
        action_result = {"type": "analyst_review_queue", "executed": False,
                          "note": "Case queued for manual analyst disposition."}

    notif_result = send_notification(record, severity, score, reasons, cfg, dry_run)

    audit_log(cfg["playbook_log"], {
        "event": "playbook_run",
        "case_id": case_id,
        "mode": "dry-run" if dry_run else "live",
        "sender": record.get("sender"),
        "indicators": indicators,
        "reputation": reputation,
        "risk_score": score,
        "reasons": reasons,
        "severity": severity,
        "action": action_result,
        "notification": notif_result,
    })

    print(f"\n[+] Case {case_id}: severity={severity} score={score}/100 "
          f"mode={'DRY-RUN' if dry_run else 'LIVE'}")
    print(f"[+] Action: {action_result}")
    print(f"[+] Full audit entry written to {cfg['playbook_log']}")


if __name__ == "__main__":
    main()
