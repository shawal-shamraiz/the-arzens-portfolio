#!/usr/bin/env python3
"""
Playbook Manager
Registers, runs, schedules, monitors, and health-checks security playbooks.

Usage:
    python playbook_manager.py --list
    python playbook_manager.py --run phishing_playbook --input email.json
    python playbook_manager.py --run phishing_playbook --input email.json --dry-run
    python playbook_manager.py --health-check
    python playbook_manager.py --history --last 10
    python playbook_manager.py --schedule phishing_playbook --interval hourly
    python playbook_manager.py --watch incoming_reports --playbook phishing_playbook
    python playbook_manager.py --daily-summary
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

REGISTRY_PATH = "playbook_registry.json"
EXECUTIONS_PATH = "executions.json"
TEMPLATES_DIR = "notification_templates"
REQUIRED_PACKAGES = ["yaml"]  # import name for pyyaml


# ---------- Registry ----------

def load_registry():
    if not os.path.exists(REGISTRY_PATH):
        print(f"[ERROR] Registry file not found: {REGISTRY_PATH}")
        sys.exit(1)
    with open(REGISTRY_PATH, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Registry file is malformed: {e}")
            sys.exit(1)
    return data.get("playbooks", [])


def find_playbook(name):
    for pb in load_registry():
        if pb["name"] == name:
            return pb
    return None


def list_playbooks():
    playbooks = load_registry()
    print("+==========================================================+")
    print("| PLAYBOOK MANAGER v1.0                                    |")
    print("+==========================================================+")
    print("Available Playbooks:")
    for i, pb in enumerate(playbooks, start=1):
        status = "ENABLED " if pb.get("enabled") else "DISABLED"
        print(f"  [{i}] {pb['name']:<20} {status} - {pb['description']}")


# ---------- Execution history ----------

def load_executions():
    if not os.path.exists(EXECUTIONS_PATH):
        return []
    with open(EXECUTIONS_PATH, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def save_execution(record):
    history = load_executions()
    history.append(record)
    with open(EXECUTIONS_PATH, "w") as f:
        json.dump(history, f, indent=2)


def show_history(last_n):
    history = load_executions()
    recent = history[-last_n:] if last_n else history
    print(f"Execution History (Last {len(recent)}):")
    for run in reversed(recent):
        status = run["status"]
        extra = run.get("summary", "")
        print(f"  [{run['start_time']}] {run['playbook']:<20} {status:<8} {extra}")
    if not recent:
        print("  (no executions recorded yet)")


# ---------- Notifications (local/template based) ----------

def render_template(template_name, **kwargs):
    path = os.path.join(TEMPLATES_DIR, template_name)
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        template = f.read()
    try:
        return template.format(**kwargs)
    except KeyError as e:
        return template + f"\n[WARN] missing template field: {e}"


def send_notification(template_name, **kwargs):
    """Writes the rendered notification to a local outbox file instead of
    faking real email/Slack delivery (no credentials configured)."""
    rendered = render_template(template_name, **kwargs)
    if rendered is None:
        print(f"[WARN] Notification template not found: {template_name}")
        return
    os.makedirs("notifications_sent", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = os.path.join("notifications_sent", f"{ts}_{template_name}")
    with open(outfile, "w") as f:
        f.write(rendered)
    print(f"[NOTIFY] {template_name} -> {outfile} (local outbox; no real email/Slack credentials configured)")


# ---------- On-demand execution ----------

def run_playbook(name, input_file, dry_run):
    pb = find_playbook(name)
    if pb is None:
        print(f"[ERROR] Playbook '{name}' not found in registry.")
        sys.exit(1)
    if not pb.get("enabled"):
        print(f"[ERROR] Playbook '{name}' is disabled in the registry.")
        sys.exit(1)
    if not os.path.exists(pb["script"]):
        print(f"[ERROR] Playbook script not found: {pb['script']}")
        sys.exit(1)

    script_dir = os.path.dirname(pb["script"]) or "."
    script_name = os.path.basename(pb["script"])
    cmd = [sys.executable, script_name]
    if input_file:
        cmd += ["--input-file", input_file]
    if dry_run:
        cmd += ["--dry-run"]

    start = datetime.now(timezone.utc)
    print(f"Running '{name}'...")
    try:
        result = subprocess.run(
            cmd, cwd=script_dir,
            capture_output=True, text=True, timeout=60
        )
        success = result.returncode == 0
        output = result.stdout.strip()
        error = result.stderr.strip() if not success else ""
    except subprocess.TimeoutExpired:
        success = False
        output = ""
        error = "Execution timed out after 60s"
    except Exception as e:
        success = False
        output = ""
        error = str(e)

    end = datetime.now(timezone.utc)
    duration = (end - start).total_seconds()

    # pull a one-line summary out of the playbook's own output, if possible
    summary = "n/a"
    for line in output.splitlines():
        if "Risk Score" in line or "Decision" in line:
            summary = line.strip()
            break

    record = {
        "playbook": name,
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
        "duration_seconds": round(duration, 3),
        "status": "SUCCESS" if success else "FAILED",
        "summary": summary,
        "error": error,
    }
    save_execution(record)

    print(output if output else "(no output)")
    if error:
        print(f"[STDERR] {error}")

    if not success:
        send_notification(
            "failure.txt",
            playbook_name=name,
            start_time=start.isoformat(),
            error_message=error or "unknown error",
        )
    elif "HIGH" in summary:
        send_notification(
            "high_risk_alert.txt",
            playbook_name=name,
            run_id="n/a",
            risk_score="n/a",
            decision="HIGH",
            actions="see playbook report",
        )

    print(f"\nStatus: {record['status']} | Duration: {duration:.2f}s")
    return record


# ---------- Health checks ----------

def check_dependencies():
    missing = []
    for pkg in REQUIRED_PACKAGES:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    return missing


def check_api_health(config_path):
    """Reads a playbook's api: section and reports whether it's configured
    correctly. Returns (ok: bool, message: str), or None if the config
    can't be read (already flagged elsewhere as 'config invalid')."""
    try:
        import yaml
        with open(config_path) as f:
            cfg = yaml.safe_load(f) or {}
    except Exception:
        return None

    api_cfg = cfg.get("api", {})
    if not api_cfg.get("virustotal_enabled", False):
        return (True, "Optional API integration disabled")

    key_env = api_cfg.get("virustotal_api_key_env", "VT_API_KEY")
    if not os.environ.get(key_env):
        return (False, "API key missing")
    return (True, f"API key configured via {key_env}")


def health_check():
    playbooks = load_registry()
    print("Health Status:")
    all_ok = True
    missing_deps = check_dependencies()

    for pb in playbooks:
        issues = []
        if not os.path.exists(pb["script"]):
            issues.append("script missing")

        config_path = pb.get("config")
        api_status = None
        if config_path and not os.path.exists(config_path):
            issues.append("Config missing")
        elif config_path:
            try:
                import yaml
                with open(config_path) as f:
                    yaml.safe_load(f)
                api_status = check_api_health(config_path)
                if api_status and not api_status[0]:
                    issues.append("API key missing")
            except Exception:
                issues.append("config invalid")

        if missing_deps:
            issues.append(f"missing deps: {missing_deps}")

        if issues:
            all_ok = False
            print(f"  [!] {pb['name']:<20} {'; '.join(issues)}")
        else:
            print(f"  [OK] {pb['name']:<20} Healthy")

        if api_status:
            tag = "OK" if api_status[0] else "!"
            print(f"        API: [{tag}] {api_status[1]}")

    return all_ok


# ---------- Daily summary ----------

def generate_daily_summary():
    """Reads today's execution history, builds a short summary, renders
    daily_summary.txt, and writes it to the local notification outbox."""
    history = load_executions()
    today = datetime.now().date().isoformat()
    todays_runs = [r for r in history if r["start_time"].startswith(today)]

    total = len(todays_runs)
    success_count = sum(1 for r in todays_runs if r["status"] == "SUCCESS")
    failure_count = total - success_count

    if todays_runs:
        run_list = "\n".join(
            f"  [{r['start_time']}] {r['playbook']} {r['status']} {r.get('summary', '')}"
            for r in todays_runs
        )
    else:
        run_list = "  (no runs recorded today)"

    send_notification(
        "daily_summary.txt",
        date=today,
        total_runs=total,
        success_count=success_count,
        failure_count=failure_count,
        run_list=run_list,
    )
    print(f"Daily summary: {total} run(s) today, {success_count} success, {failure_count} failed.")


# ---------- Event-driven execution (folder watch) ----------

def watch_folder(folder, playbook_name, dry_run):
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        print("[ERROR] 'watchdog' library not installed. Run: pip install watchdog")
        sys.exit(1)

    pb = find_playbook(playbook_name)
    if pb is None:
        print(f"[ERROR] Playbook '{playbook_name}' not found in registry.")
        sys.exit(1)
    if not pb.get("enabled"):
        print(f"[ERROR] Playbook '{playbook_name}' is disabled in the registry.")
        sys.exit(1)
    if not os.path.isdir(folder):
        print(f"[ERROR] Watched folder not found: {folder}")
        sys.exit(1)

    class ReportHandler(FileSystemEventHandler):
        def on_created(self, event):
            if event.is_directory:
                return
            if not event.src_path.lower().endswith(".json"):
                return
            print(f"[WATCH] New report detected: {event.src_path}")
            try:
                run_playbook(playbook_name, os.path.abspath(event.src_path), dry_run)
            except Exception as e:
                # A bad/unreadable file should not crash the watcher.
                print(f"[ERROR] Failed to process {event.src_path}: {e}")

    observer = Observer()
    observer.schedule(ReportHandler(), path=folder, recursive=False)
    observer.start()
    print(f"Watching '{folder}' for new .json reports -> playbook '{playbook_name}'.")
    print("[NOTE] Only simulated/local actions are ever taken - no destructive real-world actions.")
    print("Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nWatcher stopped.")
    observer.join()


# ---------- Scheduling ----------

def schedule_playbook(name, interval, time_str):
    try:
        import schedule
    except ImportError:
        print("[ERROR] 'schedule' library not installed. Run: pip install schedule")
        sys.exit(1)

    # Special pseudo-playbook name: schedule the daily summary instead of
    # a registered playbook. Simple way to hook the daily-summary
    # requirement into the same scheduling mechanism.
    if name == "daily_summary":
        if interval != "daily":
            print("[ERROR] daily_summary can only be scheduled with --interval daily")
            sys.exit(1)
        schedule.every().day.at(time_str or "18:00").do(generate_daily_summary)
        print(f"Scheduled daily summary generation at {time_str or '18:00'}. Press Ctrl+C to stop.")
        try:
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nScheduler stopped.")
        return

    pb = find_playbook(name)
    if pb is None:
        print(f"[ERROR] Playbook '{name}' not found in registry.")
        sys.exit(1)

    def job():
        print(f"[SCHEDULED] Triggering '{name}' at {datetime.now().isoformat()}")
        run_playbook(name, input_file=None, dry_run=True)

    if interval == "hourly":
        schedule.every().hour.do(job)
    elif interval == "daily":
        schedule.every().day.at(time_str or "02:00").do(job)
    else:
        print(f"[ERROR] Unsupported interval: {interval} (use 'hourly' or 'daily')")
        sys.exit(1)

    print(f"Scheduled '{name}' to run {interval}. Press Ctrl+C to stop.")
    print("[NOTE] Foreground loop for demo purposes - run in background/cron for production.")
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nScheduler stopped.")


# ---------- Main ----------

def main():
    parser = argparse.ArgumentParser(description="Playbook Manager")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--run", metavar="PLAYBOOK_NAME")
    parser.add_argument("--input", metavar="INPUT_FILE")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--health-check", action="store_true")
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--last", type=int, default=10)
    parser.add_argument("--schedule", metavar="PLAYBOOK_NAME")
    parser.add_argument("--interval", choices=["hourly", "daily"], default="hourly")
    parser.add_argument("--time", default="02:00", help="HH:MM, used with --interval daily")
    parser.add_argument("--watch", metavar="FOLDER", help="Watch a folder for new .json reports")
    parser.add_argument("--playbook", metavar="PLAYBOOK_NAME", help="Playbook to run for --watch")
    parser.add_argument("--daily-summary", action="store_true", help="Generate today's summary now")
    args = parser.parse_args()

    if args.list:
        list_playbooks()
    elif args.run:
        run_playbook(args.run, args.input, args.dry_run)
    elif args.health_check:
        print("+==========================================================+")
        print("| PLAYBOOK MANAGER v1.0                                    |")
        print("+==========================================================+")
        ok = health_check()
        sys.exit(0 if ok else 1)
    elif args.history:
        show_history(args.last)
    elif args.schedule:
        schedule_playbook(args.schedule, args.interval, args.time)
    elif args.watch:
        if not args.playbook:
            parser.error("--watch requires --playbook <name>")
        watch_folder(args.watch, args.playbook, args.dry_run)
    elif args.daily_summary:
        generate_daily_summary()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
