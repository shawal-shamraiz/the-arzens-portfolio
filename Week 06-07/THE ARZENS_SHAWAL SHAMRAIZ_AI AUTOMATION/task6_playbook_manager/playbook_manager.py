#!/usr/bin/env python3
"""
playbook_manager.py — Manage, run, schedule, and health-check the security
playbooks/tools built in Tasks 2, 3, and 5.

THE ARZENS Internship — Week 07, Task 6

Commands:
    --list                              Show all registered playbooks
    --run <playbook>                    Execute a specific playbook now
    --run <playbook> -- <extra args>    Execute with custom CLI args
    --schedule <playbook> --interval hourly|daily
                                         Register a recurring schedule
    --run-scheduler                     Foreground loop that executes any
                                         due scheduled playbooks (polls once
                                         a minute; Ctrl+C to stop)
    --health-check                      Validate registry, config files,
                                         and required environment variables
    --history [--last N]                Show recent execution history
    --daily-summary                     Print a summary of the last 24h

Design notes:
  * Playbooks are executed as subprocesses (python <script> <args>), each
    with its own working directory, so relative paths inside each tool
    (config.yaml, sample files) resolve correctly regardless of where
    playbook_manager.py itself is invoked from.
  * Every run — success or failure — is appended to execution_history.json
    with start time, duration, exit code, and truncated stdout/stderr, so
    the manager has its own audit trail independent of each playbook's own
    internal logging (e.g. phishing_playbook.py's playbook.log).
  * Health checks never execute a playbook; they only inspect the registry,
    required files, and required environment variables, so --health-check
    is always safe to run.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()
REGISTRY_PATH = BASE_DIR / "playbook_registry.json"
SCHEDULE_PATH = BASE_DIR / "schedule_config.yaml"
HISTORY_PATH = BASE_DIR / "execution_history.json"

VALID_INTERVALS = {"hourly": timedelta(hours=1), "daily": timedelta(days=1)}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
def load_registry() -> list[dict]:
    if not REGISTRY_PATH.exists():
        print(f"[!] Registry not found at {REGISTRY_PATH}", file=sys.stderr)
        sys.exit(1)
    return json.loads(REGISTRY_PATH.read_text())


def get_playbook(name: str, registry: list[dict]) -> dict | None:
    for pb in registry:
        if pb["name"] == name:
            return pb
    return None


def cmd_list(registry: list[dict]):
    print(f"{'NAME':<22} {'ENABLED':<9} {'DESCRIPTION'}")
    print("-" * 90)
    for pb in registry:
        print(f"{pb['name']:<22} {str(pb.get('enabled', True)):<9} {pb['description'][:60]}")


# ---------------------------------------------------------------------------
# Execution history
# ---------------------------------------------------------------------------
def load_history() -> list[dict]:
    if HISTORY_PATH.exists():
        return json.loads(HISTORY_PATH.read_text())
    return []


def save_history(history: list[dict]):
    HISTORY_PATH.write_text(json.dumps(history, indent=2))


def record_run(name: str, started_at: str, duration_s: float, exit_code: int,
                stdout: str, stderr: str):
    history = load_history()
    history.append({
        "playbook": name,
        "started_at": started_at,
        "duration_seconds": round(duration_s, 3),
        "exit_code": exit_code,
        "success": exit_code == 0,
        "stdout_tail": stdout[-1000:],
        "stderr_tail": stderr[-1000:],
    })
    save_history(history)
    return history[-1]


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------
def run_playbook(pb: dict, extra_args: list[str] | None = None) -> dict:
    if not pb.get("enabled", True):
        print(f"[!] Playbook '{pb['name']}' is disabled in the registry; skipping.")
        return {"success": False, "skipped": True}

    script_path = (BASE_DIR / pb["script_path"]).resolve()
    working_dir = (BASE_DIR / pb["working_dir"]).resolve()
    args = extra_args if extra_args else pb.get("default_args", [])

    if not script_path.exists():
        print(f"[!] Script not found for '{pb['name']}': {script_path}", file=sys.stderr)
        rec = record_run(pb["name"], datetime.now(timezone.utc).isoformat(), 0.0, -1,
                          "", f"Script not found: {script_path}")
        alert_on_failure(pb["name"], rec)
        return {"success": False}

    cmd = [sys.executable, str(script_path)] + args
    started_at = datetime.now(timezone.utc).isoformat()
    t0 = time.monotonic()
    print(f"[*] Running '{pb['name']}': {' '.join(cmd)}  (cwd={working_dir})")
    try:
        result = subprocess.run(cmd, cwd=working_dir, capture_output=True, text=True, timeout=300)
        duration = time.monotonic() - t0
        rec = record_run(pb["name"], started_at, duration, result.returncode,
                          result.stdout, result.stderr)
        if result.returncode == 0:
            print(f"[+] '{pb['name']}' completed successfully in {duration:.2f}s.")
        else:
            print(f"[!] '{pb['name']}' FAILED (exit code {result.returncode}) after {duration:.2f}s.")
            alert_on_failure(pb["name"], rec)
        return {"success": result.returncode == 0, "record": rec}
    except subprocess.TimeoutExpired:
        duration = time.monotonic() - t0
        rec = record_run(pb["name"], started_at, duration, -1, "", "Execution timed out (300s).")
        print(f"[!] '{pb['name']}' TIMED OUT after {duration:.2f}s.")
        alert_on_failure(pb["name"], rec)
        return {"success": False, "record": rec}


def alert_on_failure(name: str, record: dict):
    """Simulated notification hook. A real deployment would send this to
    Slack/email/PagerDuty; here we print a clearly-marked alert so failures
    are never silent."""
    print("=" * 60)
    print(f"[ALERT] Playbook '{name}' failed at {record['started_at']}")
    print(f"        exit_code={record['exit_code']}  duration={record['duration_seconds']}s")
    if record.get("stderr_tail"):
        print(f"        stderr (tail): {record['stderr_tail'][-300:]}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Scheduling
# ---------------------------------------------------------------------------
def load_schedule() -> dict:
    if not SCHEDULE_PATH.exists():
        return {"schedules": []}
    try:
        import yaml
        return yaml.safe_load(SCHEDULE_PATH.read_text()) or {"schedules": []}
    except ImportError:
        print("[!] PyYAML not installed; treating schedule as empty. `pip install pyyaml`.",
              file=sys.stderr)
        return {"schedules": []}


def save_schedule(schedule: dict):
    import yaml
    SCHEDULE_PATH.write_text(yaml.dump(schedule, sort_keys=False))


def cmd_schedule(name: str, interval: str, registry: list[dict]):
    if interval not in VALID_INTERVALS:
        print(f"[!] Invalid interval '{interval}'. Choose from: {list(VALID_INTERVALS)}",
              file=sys.stderr)
        sys.exit(1)
    if get_playbook(name, registry) is None:
        print(f"[!] Unknown playbook '{name}'. Use --list to see registered playbooks.",
              file=sys.stderr)
        sys.exit(1)

    schedule = load_schedule()
    schedule.setdefault("schedules", [])
    schedule["schedules"] = [s for s in schedule["schedules"] if s["playbook"] != name]
    schedule["schedules"].append({
        "playbook": name,
        "interval": interval,
        "next_run": datetime.now(timezone.utc).isoformat(),
        "added_at": datetime.now(timezone.utc).isoformat(),
    })
    save_schedule(schedule)
    print(f"[+] Scheduled '{name}' to run {interval}. See {SCHEDULE_PATH.name}.")


def run_due_schedules(registry: list[dict]):
    schedule = load_schedule()
    now = datetime.now(timezone.utc)
    changed = False
    for entry in schedule.get("schedules", []):
        next_run = datetime.fromisoformat(entry["next_run"])
        if now >= next_run:
            pb = get_playbook(entry["playbook"], registry)
            if pb:
                run_playbook(pb)
            entry["next_run"] = (now + VALID_INTERVALS[entry["interval"]]).isoformat()
            entry["last_run"] = now.isoformat()
            changed = True
    if changed:
        save_schedule(schedule)


def cmd_run_scheduler(registry: list[dict]):
    print("[*] Scheduler running in foreground. Checking for due playbooks every 60s. "
          "Press Ctrl+C to stop.")
    try:
        while True:
            run_due_schedules(registry)
            time.sleep(60)
    except KeyboardInterrupt:
        print("\n[*] Scheduler stopped.")


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
def cmd_health_check(registry: list[dict]) -> bool:
    print("Playbook Manager — Health Check")
    print("=" * 60)
    all_ok = True

    for pb in registry:
        print(f"\n[{pb['name']}]")
        script_path = (BASE_DIR / pb["script_path"]).resolve()
        working_dir = (BASE_DIR / pb["working_dir"]).resolve()

        if script_path.exists():
            print(f"  [OK]   script found: {script_path}")
        else:
            print(f"  [FAIL] script missing: {script_path}")
            all_ok = False

        if working_dir.is_dir():
            print(f"  [OK]   working dir exists: {working_dir}")
        else:
            print(f"  [FAIL] working dir missing: {working_dir}")
            all_ok = False

        for rel_file in pb.get("required_files", []):
            fpath = working_dir / rel_file
            if fpath.exists():
                print(f"  [OK]   required file present: {rel_file}")
            else:
                print(f"  [FAIL] required file missing: {rel_file}")
                all_ok = False

        for env_var in pb.get("required_env", []):
            if os.environ.get(env_var):
                print(f"  [OK]   env var set: {env_var}")
            else:
                print(f"  [WARN] env var not set: {env_var} "
                      f"(playbook will need --dry-run/--mock without it)")

    print("\n" + "=" * 60)
    print("Overall status:", "HEALTHY" if all_ok else "ISSUES FOUND (see FAIL lines above)")
    return all_ok


# ---------------------------------------------------------------------------
# History reporting
# ---------------------------------------------------------------------------
def cmd_history(last_n: int):
    history = load_history()
    for rec in history[-last_n:]:
        status = "OK" if rec["success"] else "FAILED"
        print(f"{rec['started_at']}  {rec['playbook']:<22} {status:<7} "
              f"{rec['duration_seconds']}s  exit={rec['exit_code']}")


def cmd_daily_summary():
    history = load_history()
    cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    recent = [r for r in history if datetime.fromisoformat(r["started_at"]) >= cutoff]

    print("Daily Summary — last 24 hours")
    print("=" * 60)
    if not recent:
        print("No playbook runs in the last 24 hours.")
        return

    by_playbook = {}
    for r in recent:
        by_playbook.setdefault(r["playbook"], {"total": 0, "success": 0, "failed": 0})
        by_playbook[r["playbook"]]["total"] += 1
        if r["success"]:
            by_playbook[r["playbook"]]["success"] += 1
        else:
            by_playbook[r["playbook"]]["failed"] += 1

    for name, stats in by_playbook.items():
        print(f"  {name:<22} total={stats['total']:<4} "
              f"success={stats['success']:<4} failed={stats['failed']}")

    total_failed = sum(s["failed"] for s in by_playbook.values())
    if total_failed:
        print(f"\n[ALERT] {total_failed} run(s) failed in the last 24 hours. Review with "
              f"`--history`.")
    else:
        print("\nAll runs succeeded in the last 24 hours.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Manage and schedule security playbooks.")
    parser.add_argument("--list", action="store_true", help="Show all registered playbooks.")
    parser.add_argument("--run", metavar="PLAYBOOK", help="Run a specific playbook now.")
    parser.add_argument("--schedule", metavar="PLAYBOOK", help="Schedule a playbook to run.")
    parser.add_argument("--interval", choices=list(VALID_INTERVALS), default="hourly",
                         help="Interval to use with --schedule (default: hourly).")
    parser.add_argument("--run-scheduler", action="store_true",
                         help="Foreground loop executing due scheduled playbooks.")
    parser.add_argument("--health-check", action="store_true",
                         help="Validate registry, files, and environment variables.")
    parser.add_argument("--history", action="store_true", help="Show recent execution history.")
    parser.add_argument("--last", type=int, default=10, help="Number of history entries to show.")
    parser.add_argument("--daily-summary", action="store_true",
                         help="Print a summary of runs in the last 24 hours.")
    parser.add_argument("extra_args", nargs=argparse.REMAINDER,
                         help="Extra args to pass through to --run (after a literal '--').")
    args = parser.parse_args()

    registry = load_registry()

    if args.list:
        cmd_list(registry)
    elif args.run:
        pb = get_playbook(args.run, registry)
        if pb is None:
            print(f"[!] Unknown playbook '{args.run}'. Use --list to see options.", file=sys.stderr)
            sys.exit(1)
        extra = args.extra_args[1:] if args.extra_args and args.extra_args[0] == "--" else None
        result = run_playbook(pb, extra)
        sys.exit(0 if result.get("success") else 1)
    elif args.schedule:
        cmd_schedule(args.schedule, args.interval, registry)
    elif args.run_scheduler:
        cmd_run_scheduler(registry)
    elif args.health_check:
        ok = cmd_health_check(registry)
        sys.exit(0 if ok else 1)
    elif args.history:
        cmd_history(args.last)
    elif args.daily_summary:
        cmd_daily_summary()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
