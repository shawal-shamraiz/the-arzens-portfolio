# Assignment 5 — Playbook Automation & SOAR Concepts

## Structure
```text
ArzensIntern_Shawal_Assignment5/
│
├── Task1/
│   └── ArzensIntern_Shawal_PlaybookDesign.docx
│
├── Task2/
│   ├── phishing_playbook.py
│   ├── config.yaml
│   ├── blacklist_domains.txt
│   ├── malware_hashes.txt
│   ├── sample_email.json
│   ├── sample_output.txt
│   └── README.md
│
├── Task3/
│   ├── playbook_manager.py
│   ├── playbook_registry.json
│   ├── schedule_config.yaml
│   ├── sample_playbooks/
│   │   ├── phishing_playbook.py
│   │   ├── config.yaml
│   │   ├── blacklist_domains.txt
│   │   ├── malware_hashes.txt
│   │   ├── malware_response.py
│   │   ├── failed_login.py
│   │   └── sample_email.json
│   ├── notification_templates/
│   │   ├── failure.txt
│   │   ├── high_risk_alert.txt
│   │   └── daily_summary.txt
│   └── MANAGER_README.md
│
└── README.md   (this file)
```
`executions.json`, `playbook.log`, `report_*.txt`, `quarantine_state.json`,
and `notifications_sent/` are created at runtime — not shipped, so the
submission stays clean.

## Dependencies
```bash
pip install pyyaml schedule watchdog
```
Everything else (`re`, `json`, `argparse`, `logging`, `uuid`, `datetime`,
`subprocess`) is Python standard library. `watchdog` is only needed for
Task 3's `--watch` (event-driven) feature.

---

## Testing Guide

### Task 2 — `phishing_playbook.py` (run from inside `Task2/`)

| # | Scenario | Command | Expected |
|---|---|---|---|
| 1 | Low risk | `python phishing_playbook.py --sender colleague@trusted.com --subject "Meeting notes" --body "See attached."` | Score 0, decision LOW, actions `log_only, deliver_with_warning` |
| 2 | Medium risk | `python phishing_playbook.py --sender user@unknown-domain.com --subject "Urgent: Please Confirm and Verify Your Account" --body "no links"` | Score 40, decision MEDIUM, actions `hold_for_analyst_review, notify_user` |
| 3 | High risk | `python phishing_playbook.py --input-file sample_email.json` | Score 100, decision HIGH, actions `quarantine_email, block_sender, notify_security_team` |
| 4 | Dry-run | `python phishing_playbook.py --input-file sample_email.json --dry-run` | Same scoring, "[DRY-RUN MODE - No actions taken]", no `quarantine_state.json` written |
| 5 | Rollback | `python phishing_playbook.py --rollback` (after a non-dry-run HIGH/MEDIUM run) | Prints restored sender + reversed actions; second call says "already rolled back" |
| 6 | Malformed input | `python phishing_playbook.py --input-file sample_email.json` with a hand-edited invalid JSON file | `[ERROR] Input validation failed: Malformed JSON in ...` |
| 7 | Missing config | temporarily rename `config.yaml` | `[WARN] config.yaml not found ... using built-in defaults`, run still completes |
| 8 | Missing threat-intel file | temporarily rename `blacklist_domains.txt` | `[WARN] Missing threat-intel file ...`, domain check treated as empty, run continues |
| 9 | Failed reputation check | corrupt one threat-intel file's permissions or path | That check is caught individually and logged; other checks and the final decision still complete |

`[RUN LOCALLY]` — actually run these commands yourself; `sample_output.txt`
in `Task2/` is a real captured run of scenario 3 with `--dry-run`.

### Task 3 — `playbook_manager.py` (run from inside `Task3/`)

| # | Scenario | Command | Expected |
|---|---|---|---|
| 10 | List | `python playbook_manager.py --list` | 3 playbooks shown, 2 ENABLED / 1 DISABLED |
| 11 | Run | `python playbook_manager.py --run phishing_playbook --input sample_email.json` | Runs the real Task 2 playbook via subprocess; appends to `executions.json` |
| 12 | Health check | `python playbook_manager.py --health-check` | `phishing_playbook` and `malware_response` OK; `failed_login` shows `[!] Config missing` (intentional demo) |
| 13 | History | `python playbook_manager.py --history --last 10` | Lists recorded runs, most recent first |
| 14 | Scheduling config | `python playbook_manager.py --schedule phishing_playbook --interval hourly` | Starts a foreground loop (Ctrl+C to stop); `schedule_config.yaml` documents the intended interval/time settings |
| 15 | Folder-watch / event-driven | `python playbook_manager.py --watch incoming_reports --playbook phishing_playbook`, then drop a `.json` report into `incoming_reports/` in another terminal | Watcher detects the new file, runs the playbook automatically, and appends a record to `executions.json`; Ctrl+C to stop |
| 16 | Daily summary | `python playbook_manager.py --daily-summary` | Prints a one-line count of today's runs and writes a rendered `daily_summary.txt` to `notifications_sent/` |
| 17 | API/dependency health check | `python playbook_manager.py --health-check` (default config has `virustotal_enabled: false`) | Each healthy playbook shows an extra `API: [OK] Optional API integration disabled` line; if you set `virustotal_enabled: true` in a playbook's `config.yaml` without exporting the API key env var, that playbook instead shows `[!] API key missing` |

`[RUN LOCALLY]` — execute these in order (11 before 13, so history has data).

---

## Final Requirement Audit

| Requirement | File/Section | Status |
|---|---|---|
| Task 1: 600–800 words | `Task1/...PlaybookDesign.docx` (716 prose words, 811 incl. diagram) | Done |
| Task 1: Trigger/Conditions/Actions/Outputs/HITL | Task1 docx | Done |
| Task 1: Dry-run/Rollback/Rate limiting | Task1 docx — Safety Controls | Done |
| Task 1: Audit logging/storage/retention | Task1 docx — Audit Requirements | Done |
| Task 1: Workflow diagram | Task1 docx — ASCII diagram | Done |
| Task 2: All 7 workflow steps | `phishing_playbook.py` | Done |
| Task 2: Exact scoring (+40/+30/+50/+10 each) | `calculate_risk()` | Done |
| Task 2: Exact thresholds (70/40) | `config.yaml` + `decide()` | Done |
| Task 2: `--dry-run` | `take_action()` | Done, tested |
| Task 2: `--rollback` | `rollback()` | Done, tested |
| Task 2: Input validation & error handling | `validate_input()`, per-check try/except | Done, tested |
| Task 2: Audit logging to `playbook.log` | `setup_logging()` + `logging.info` calls throughout | Done |
| Task 2: Notification wording doesn't imply real delivery | `generate_report()` — "Security report generated for:" | Done, tested |
| Task 2: All required files | `Task2/` | Done |
| Task 3: Registry + metadata | `playbook_registry.json` | Done |
| Task 3: Enabled/disabled status | `--list` output | Done, tested |
| Task 3: On-demand execution | `--run` | Done, tested |
| Task 3: Scheduling (schedule library) | `--schedule` | Done |
| Task 3: Event-driven execution (watchdog folder watch) | `watch_folder()`, `--watch`/`--playbook` | Done, tested |
| Task 3: Execution monitoring + history | `executions.json`, `--history` | Done, tested |
| Task 3: Health checks (files/config/deps) | `--health-check` | Done, tested |
| Task 3: Health checks — API key status | `check_api_health()` | Done, tested |
| Task 3: Notifications — failure/high-risk | `notification_templates/`, `send_notification()` | Done, tested |
| Task 3: Notifications — daily summary implemented | `generate_daily_summary()`, `--daily-summary` | Done, tested |
| Task 3: All required files | `Task3/` | Done |
| Documentation: README + MANAGER_README, commands match code | `Task2/README.md`, `Task3/MANAGER_README.md` | Done |

---

## Git Workflow (suggested)
```bash
git init
git add Task1/
git commit -m "Initial Assignment 5 structure"
git add Task1/
git commit -m "Add Task 1 SOAR design"
git add Task2/phishing_playbook.py
git commit -m "Add phishing response playbook"
git add Task2/
git commit -m "Add Task 2 configuration and test data"
git add Task3/playbook_manager.py Task3/playbook_registry.json
git commit -m "Add playbook manager"
git add Task2/README.md Task3/MANAGER_README.md README.md
git commit -m "Add documentation"
git add .
git commit -m "Final testing and cleanup"
git remote add origin <YOUR_REPO_URL>
git push -u origin main
```
(Replace `<YOUR_REPO_URL>` with your own — no repository URL is invented here.)

---

## MY ACTIONS
- [ ] Install dependencies: `pip install pyyaml schedule watchdog`
- [ ] Save/copy this folder to your local machine
- [ ] Run the Task 2 and Task 3 test scenarios above and confirm output on your machine
- [ ] Open `Task1/ArzensIntern_Shawal_PlaybookDesign.docx` and check formatting/page count in your Word viewer
- [ ] Fix any environment-specific errors (Python version, missing packages)
- [ ] Create a GitHub repository for this assignment
- [ ] Commit and push files using the suggested workflow above
- [ ] Copy your repository link into your submission
- [ ] Prepare the final ZIP (and/or PDF export of Task 1) for submission
- [ ] Submit to Google Classroom
