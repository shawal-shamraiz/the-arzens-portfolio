# Playbook Manager & Scheduler

**THE ARZENS Internship — Week 07, Task 6**

`playbook_manager.py` is a lightweight orchestrator that registers, runs,
schedules, and health-checks the security tools built in Tasks 2, 3, and 5
(`openai_analyzer.py`, `hf_classifier.py`, `phishing_playbook.py`). It does
not reimplement those tools — it wraps them as subprocesses, so each keeps
its own internal logic, config, and safety features (e.g. `phishing_playbook.py`
still defaults to `--dry-run`; the manager doesn't override that).

## Files

| File                        | Purpose                                                            |
|------------------------------|---------------------------------------------------------------------|
| `playbook_manager.py`         | The manager/scheduler CLI itself.                                  |
| `playbook_registry.json`      | Metadata for each registered playbook (script path, working dir, default args, required files/env vars). |
| `schedule_config.yaml`        | Recurring schedules; created/updated by `--schedule`, editable by hand. |
| `execution_history.json`      | Auto-generated log of every run: timestamp, duration, exit code, truncated stdout/stderr. |
| `MANAGER_README.md`           | This file.                                                          |

## How playbooks are registered

Each entry in `playbook_registry.json` looks like:

```json
{
  "name": "phishing_response",
  "description": "...",
  "script_path": "../task5_phishing_playbook/phishing_playbook.py",
  "working_dir": "../task5_phishing_playbook",
  "default_args": ["--email-file", "sample_email.json", "--dry-run"],
  "required_env": [],
  "required_files": ["config.yaml", "blacklist_domains.txt", "sample_email.json"],
  "enabled": true
}
```

`working_dir` matters: the manager runs each playbook with that directory as
its current working directory, so relative paths inside the playbook (its
own `config.yaml`, sample files, log files) resolve exactly as if you had
run the script by hand from that folder.

To add a new playbook, add an entry here — no changes to
`playbook_manager.py` are needed.

## Commands

```bash
# Show all registered playbooks
python playbook_manager.py --list

# Run a playbook now, using its default_args from the registry
python playbook_manager.py --run phishing_response

# Run a playbook with your own arguments instead of the registry defaults
python playbook_manager.py --run phishing_response -- --email-file other.json --live

# Register a recurring schedule (hourly or daily)
python playbook_manager.py --schedule phishing_response --interval hourly
python playbook_manager.py --schedule hf_alert_classifier --interval daily

# Start the foreground scheduler loop (checks every 60s for due playbooks)
python playbook_manager.py --run-scheduler

# Validate the whole setup without running anything
python playbook_manager.py --health-check

# Review recent runs
python playbook_manager.py --history --last 20

# Summarize the last 24 hours (and flag if anything failed)
python playbook_manager.py --daily-summary
```

## Health checks

`--health-check` verifies, for every registered playbook:
- the script file exists at the configured path,
- the working directory exists,
- every file listed in `required_files` is present in that working directory,
- every environment variable listed in `required_env` is set (a missing one
  is a **warning**, not a failure — the underlying playbook is expected to
  fall back to a `--dry-run`/`--mock` mode without it).

It never executes a playbook, so it's always safe to run, including in CI.

## Execution history & notifications

Every `--run` (whether triggered manually or by the scheduler) appends one
record to `execution_history.json`:

```json
{
  "playbook": "phishing_response",
  "started_at": "2026-09-12T07:54:08.544065+00:00",
  "duration_seconds": 0.164,
  "exit_code": 0,
  "success": true,
  "stdout_tail": "...",
  "stderr_tail": ""
}
```

If a run exits non-zero or times out (300s cap), the manager prints a
clearly-marked `[ALERT]` block immediately — this is the "alert on failure"
notification required by the assignment. In a production deployment this
`alert_on_failure()` hook is where you'd wire up Slack/email/PagerDuty
instead of stdout.

`--daily-summary` aggregates `execution_history.json` for the last 24 hours
per playbook (total / success / failed) and prints a top-level `[ALERT]`
line if anything failed in that window — this is the "daily summary"
notification required by the assignment.

## Scheduling model

`--schedule <playbook> --interval hourly|daily` writes (or updates) an entry
in `schedule_config.yaml` with a `next_run` timestamp. `--run-scheduler` is a
simple foreground polling loop: every 60 seconds it checks whether any
schedule's `next_run` has passed, runs that playbook if so, and pushes
`next_run` forward by the configured interval. This is intentionally simple
(no external scheduler dependency) so it's easy to read and grade; a
production deployment would more likely use cron, systemd timers, or a task
queue to invoke `--run <playbook>` on a schedule instead of the built-in
loop.

## Safety notes

- The manager does not change any playbook's own safety defaults. If a
  playbook defaults to `--dry-run` (as `phishing_playbook.py` does), running
  it via the manager with `default_args` from the registry stays in
  `--dry-run` unless you explicitly override the args with `--live`.
- `execution_history.json` stores only the **tail** (last 1000 characters)
  of stdout/stderr per run, to keep the history file bounded and avoid
  accidentally persisting large amounts of sensitive log data.
