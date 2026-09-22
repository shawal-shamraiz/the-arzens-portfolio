# Playbook Manager

## Purpose
Registers multiple security playbooks, runs them on demand or on a
schedule, tracks execution history, checks their health, and sends
local notifications on failure or high-risk results.

## Setup
```bash
pip install pyyaml schedule watchdog
```
(`watchdog` is only needed for the `--watch` folder-watch feature.)

## Files
| File | Purpose |
|---|---|
| `playbook_manager.py` | main management script |
| `playbook_registry.json` | registered playbook metadata |
| `executions.json` | created at runtime — execution history |
| `sample_playbooks/` | the phishing playbook + two stub demo playbooks |
| `schedule_config.yaml` | example scheduling settings (disabled by default) |
| `notification_templates/` | failure / high-risk / daily-summary templates |
| `notifications_sent/` | created at runtime — local notification outbox |

## Registry Format (`playbook_registry.json`)
```json
{
  "playbooks": [
    {
      "name": "phishing_playbook",
      "description": "Phishing email response",
      "trigger_type": "manual",
      "enabled": true,
      "script": "sample_playbooks/phishing_playbook.py",
      "config": "sample_playbooks/config.yaml"
    }
  ]
}
```
`script` and `config` paths are relative to `Task3/`. The manager runs
the script with the script's own folder as the working directory, so
each playbook can keep its own `config.yaml` / data files alongside it.

## Commands

List playbooks:
```bash
python playbook_manager.py --list
```

Run a playbook:
```bash
python playbook_manager.py --run phishing_playbook --input sample_email.json
python playbook_manager.py --run phishing_playbook --input sample_email.json --dry-run
```
(`--input` is passed relative to the playbook's own folder, e.g. a file
inside `sample_playbooks/`.)

Health check:
```bash
python playbook_manager.py --health-check
```

Execution history:
```bash
python playbook_manager.py --history --last 10
```

Scheduling:
```bash
python playbook_manager.py --schedule phishing_playbook --interval hourly
python playbook_manager.py --schedule malware_response --interval daily --time 02:00
```
Runs in the foreground using the `schedule` library and triggers a
dry-run of the playbook at each interval; stop with Ctrl+C.
`schedule_config.yaml` documents the intended schedule but is not
auto-loaded — it's a reference for what to configure via the CLI (or
extend the script to read it directly).

## Health Checks
For each registered playbook, the manager verifies:
- the script file exists
- the config file exists and parses as valid YAML
- required Python packages (`pyyaml`) are importable
- whether an optional API integration is configured correctly (see below)

Disabled/broken entries are shown with `[!]` and a reason; healthy ones
with `[OK]`. The `failed_login` entry is intentionally disabled with no
config file in this submission, to demonstrate a `[!] ... Config
missing` result.

### API/dependency status
Each playbook's `config.yaml` has an `api:` section (see Task 2's
`config.yaml`). The health check reads it and reports one of:
- `[OK] Optional API integration disabled` — `virustotal_enabled: false` (the base/local implementation; no key required)
- `[OK] API key configured via <ENV_VAR>` — enabled and the environment variable is set
- `[!] API key missing` — enabled but the environment variable is not set

No real API key is required to pass health checks in the default
(disabled) configuration.

## History
Each run appends a record to `executions.json`: playbook name, start
time, end time, duration, status, a one-line summary pulled from the
playbook's own output, and an error message if it failed.

## Notifications
Notifications are template-based and written to `notifications_sent/`
as local files (not sent over real email/Slack, since no credentials
are configured). Triggers:
- **Failure** — any non-zero exit from a playbook run
- **High-risk alert** — a successful run whose output summary contains "HIGH"
- **Daily summary** — generated on demand with `--daily-summary`, or on a
  schedule (see below)

## Event-Driven Execution (folder watch)
Watches a folder for newly created `.json` report files and runs the
matching registered, enabled playbook automatically.
```bash
python playbook_manager.py --watch incoming_reports --playbook phishing_playbook
```
- New `.json` files dropped into `incoming_reports/` are picked up and
  passed to the playbook as `--input-file`.
- Each run is recorded in `executions.json`, same as `--run`.
- A file that fails to process is logged and skipped; the watcher keeps
  running rather than crashing.
- Only simulated/local actions are ever taken — never real quarantine,
  blocking, or delivery.
- Add `--dry-run` to only show what each incoming report would trigger.
- Stop with Ctrl+C.

## Daily Summary
Generate it on demand:
```bash
python playbook_manager.py --daily-summary
```
Reads today's entries from `executions.json`, counts successes/failures,
renders `daily_summary.txt`, and writes it to `notifications_sent/`.

To run it automatically once a day, schedule the special
`daily_summary` name (same scheduling mechanism as playbooks):
```bash
python playbook_manager.py --schedule daily_summary --interval daily --time 18:00
```

## Examples
```bash
python playbook_manager.py --list
python playbook_manager.py --run phishing_playbook --input sample_email.json
python playbook_manager.py --health-check
python playbook_manager.py --history --last 5
python playbook_manager.py --watch incoming_reports --playbook phishing_playbook
python playbook_manager.py --daily-summary
```

## Limitations
- Scheduling runs in the foreground (no daemonization) and the
  playbook schedule job only triggers dry-runs, for safety in a demo
  environment.
- The folder watcher only checks for `.json` files created in the
  watched folder (not subfolders), and only supports one playbook per
  `--watch` invocation.
- Notifications are local files, not real email/Slack delivery.
