# Phishing Response Playbook

## Purpose
Automates the first response to a reported phishing email: extracts
indicators, checks them against local threat intel, scores risk, decides
an action (quarantine / review / log), writes a report, and logs every
step for audit purposes.

## Requirements
- Python 3.8+
- `pyyaml`

## Installation
```bash
pip install pyyaml
```
(`re`, `json`, `argparse`, `logging`, `uuid`, `datetime` are built-in.)

## Files
| File | Purpose |
|---|---|
| `phishing_playbook.py` | main script |
| `config.yaml` | thresholds, paths, notification settings |
| `blacklist_domains.txt` | local list of known bad domains |
| `malware_hashes.txt` | local list of known malware hashes |
| `sample_email.json` | test input matching the assignment example |
| `sample_output.txt` | real console output from a `--dry-run` execution |
| `playbook.log` | created at runtime — audit log |
| `quarantine_state.json` | created at runtime — used by `--rollback` |

## Configuration (`config.yaml`)
Set risk thresholds, the security-team notification address, file paths
for the blacklist/hash lists, and the suspicious-keyword list. VirusTotal
integration is optional and off by default; if you enable it, put the API
key in an environment variable (e.g. `VT_API_KEY`) — never in this file.

## Command Examples

Run with individual flags:
```bash
python phishing_playbook.py --sender security@paypa1.com \
  --subject "Urgent: Verify Your Account" \
  --body "Click here to verify: http://evil-site.com/login" \
  --attachment-hash d41d8cd98f00b204e9800998ecf8427e
```

Run with a JSON file:
```bash
python phishing_playbook.py --input-file sample_email.json
```

### JSON input example
```json
{
  "sender": "security@paypa1.com",
  "subject": "Urgent: Verify Your Account",
  "body": "Click here to verify: http://evil-site.com/login",
  "attachment_hash": "d41d8cd98f00b204e9800998ecf8427e",
  "reported_by": "user@company.com"
}
```

### Dry-run
```bash
python phishing_playbook.py --input-file sample_email.json --dry-run
```
Shows the risk score and which actions *would* be taken, without writing
quarantine state.

### Rollback
```bash
python phishing_playbook.py --rollback
```
Restores the sender from the most recent non-dry-run HIGH/MEDIUM action
by reading `quarantine_state.json` and marking it restored. Running it
twice in a row for the same state is a no-op (it tells you it was already
rolled back).

## Testing
See the project-level testing section in the top-level submission README
for the full list of scenarios (low/medium/high risk, dry-run, rollback,
malformed input, missing config, missing threat-intel file).

Quick check:
```bash
python phishing_playbook.py --input-file sample_email.json
cat playbook.log
```

## Limitations
- Reputation checks use local flat files, not a live threat-intel feed.
- VirusTotal integration is optional/config-driven and disabled by
  default — no external API calls are made in the base implementation.
- "Quarantine" and "block sender" are simulated (logged/local state
  only) — no real mailbox or firewall is touched.
- Single quarantine slot: `--rollback` only restores the most recent
  action, not full history.

## Safety Notes
- Always test with `--dry-run` first on new input.
- Do not commit real API keys or credentials to `config.yaml`.
- A failed reputation check is logged as a warning and does not stop
  the rest of the workflow.
