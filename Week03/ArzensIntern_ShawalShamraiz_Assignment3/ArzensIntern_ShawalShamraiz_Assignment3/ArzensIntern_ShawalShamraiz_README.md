# ArzensIntern_ShawalShamraiz — Security Log Normalizer & Reproducibility Package

**Author:** Shawal Shamraiz
THE ARZENS Beginner Track — Assignment 3, Tasks 2 & 3

## Project Overview

This project reads messy, mixed-format security logs (firewall, auth, DNS,
and JSON file-access logs all in one file) and normalizes them into two
clean, consistent files — a CSV and a JSON — using `normalizer.py`. On top
of that, this package proves the tool is reproducible: `checksum.py`
fingerprints the input/output files so tampering or drift can be caught
later, and `test_reproducibility.py` actually runs the normalizer twice
and checks the two runs produce byte-identical output.

## What it handles

Four log formats, mixed together in the same input file:

- **Firewall** — `[2026-07-20 14:23:45] FIREWALL src=192.168.1.100 dst=10.0.0.50 action=ALLOW port=443 bytes=15234`
- **Auth** (comma-separated) — `2026-07-20T14:25:00Z,auth-server,LOGIN,alice,192.168.1.100,SUCCESS`
- **DNS** (syslog style) — `Jul 20 14:27:30 dns-server named[1234]: query: malicious.example.com IN A from 192.168.1.100`
- **JSON** — `{"timestamp": "2026-07-20 14:29:00", "event": "FILE_ACCESS", "user": "bob", "file": "/etc/passwd", "action": "READ"}`

The script guesses the format of each line automatically, or you can force
one format with `--format` if you know the whole file is one type.

## Installation

**Python version:** 3.9 or newer (developed and tested on Python 3.12.3).
No external packages needed — everything used across `normalizer.py`,
`checksum.py`, and `test_reproducibility.py` (`argparse`, `csv`, `json`,
`re`, `datetime`, `hashlib`, `subprocess`, `filecmp`, `os`, `sys`) is
built into Python already.

**Virtual environment (optional, but good practice):**
```bash
python3 -m venv venv
source venv/bin/activate       # on Windows: venv\Scripts\activate
```

**Installing dependencies:**
```bash
pip install -r ArzensIntern_ShawalShamraiz_requirements.txt
```
This will effectively do nothing, since the file only contains comments
explaining that there's nothing to install — see the file itself for why.

## Usage

Basic run:
```bash
python ArzensIntern_ShawalShamraiz_normalizer.py --input sample_mixed_logs.txt --output-csv clean.csv --output-json clean.json
```

Remove duplicate events (same timestamp, source IP, and action):
```bash
python ArzensIntern_ShawalShamraiz_normalizer.py --input sample_mixed_logs.txt --output-csv clean.csv --output-json clean.json --deduplicate
```

Force a specific parser instead of auto-detecting:
```bash
python ArzensIntern_ShawalShamraiz_normalizer.py --input firewall_only.txt --output-csv clean.csv --output-json clean.json --format firewall
```

### CLI arguments

| Argument | Required | Default | What it does |
|---|---|---|---|
| `--input` | yes | — | Path to the messy input log file |
| `--output-csv` | yes | — | Where to write the normalized CSV |
| `--output-json` | yes | — | Where to write the normalized JSON |
| `--format` | no | `auto` | `auto`, `firewall`, `auth`, `dns`, or `json` |
| `--deduplicate` | no | off | Removes duplicate events if set |

## What gets normalized

- **Timestamps** get converted to ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`), no
  matter which of the 3 input formats they started as. If a timestamp can't
  be parsed at all, the record is kept but marked `UNKNOWN` and flagged,
  instead of getting thrown away.
- **IP addresses** get checked for valid IPv4 format, and flagged if they
  fall in a private range (10.x, 172.16–31.x, 192.168.x).
- **event_type**, **action** get uppercased and normalized (e.g. `LOGIN` →
  `AUTH`, `FILE_ACCESS` → `FILE`).
- **user** defaults to `SYSTEM` when the log entry has no user (firewall
  and DNS logs don't have one).
- **port** and **bytes** get range-checked (port 1–65535, bytes > 0 when
  the log type reports bytes at all).

Every record ends up with a `status` of either `VALID` or `FLAGGED`. See
`data_dictionary.txt` for exactly what triggers a flag.

## Reproducibility

This project is set up so that running `normalizer.py` on the same input
always produces exactly the same output, byte for byte — no timestamps
based on "now", no unsorted data, no hardcoded absolute paths. Two tools
back this up:

### Running checksum.py

Generates MD5 and SHA-256 hashes of the input log file and both output
files, and saves them to `ArzensIntern_ShawalShamraiz_checksums.txt`:
```bash
python ArzensIntern_ShawalShamraiz_checksum.py
```

Later, to check nothing has changed (or that a fresh run matches the
original):
```bash
python ArzensIntern_ShawalShamraiz_checksum.py --verify
```
This prints `PASS`/`FAIL` per file and exits with code 1 if anything
doesn't match, so it can be used in a script or CI pipeline too.

### Running the reproducibility test

Actually runs `normalizer.py` twice back-to-back on the same sample input
and compares both CSV outputs and both JSON outputs directly:
```bash
python ArzensIntern_ShawalShamraiz_test_reproducibility.py
```

Expected output:
```
Running normalizer.py - first run...
Running normalizer.py - second run...

CSV outputs identical:  YES
JSON outputs identical: YES

RESULT: PASS - normalizer produces identical output on repeated runs.
```

If this ever prints `FAIL`, something in `normalizer.py` started
depending on the system clock, an unsorted collection, or something else
non-deterministic — see `ENVIRONMENT.md` for the one bug like this that
was already found and fixed (the DNS/syslog timestamp year).

## Environment documentation

Full details on the exact Python version, OS, and setup this was
developed and tested on are in `ArzensIntern_ShawalShamraiz_ENVIRONMENT.md`.

## Expected output

Running the script prints a short summary:
```
--- Normalization Summary ---
Total lines read:      25
Successfully parsed:   22
Skipped (malformed):   3
Duplicates removed:    1
CSV output:            sample_clean.csv
JSON output:           sample_clean.json
Error log:             parse_errors.log
```

It also writes `parse_errors.log`, listing every skipped or flagged line
by line number and reason, so nothing silently disappears.

## Troubleshooting

- **"input file was not found"** — check the path passed to `--input`.
  Relative paths are relative to wherever you're running the script from.
- **Everything is showing up as FLAGGED** — this usually just means most
  of your source IPs are in a private range, which is expected for
  internal log data. Check `status` isn't being confused with an actual
  error; look at `parse_errors.log` for the real reason.
- **A whole log type is being skipped** — run with `--format` forced to
  that type on a small sample to see the specific parsing error, since
  auto-detect can occasionally misidentify a very irregular line.
- **Output changes between runs** — it shouldn't. Records are sorted by
  timestamp then source IP before writing, so the same input always
  produces the same output. If you see differences, check whether the
  input file itself changed.
- **`checksum.py --verify` says FAIL** — either a file genuinely changed
  since the checksums were generated, or you're running it against a
  different sample file than the one the checksums were made from. Rerun
  `checksum.py` (without `--verify`) to regenerate against the current
  files if the change was intentional.
- **`test_reproducibility.py` says FAIL** — this means two runs on the
  exact same input produced different output, which shouldn't happen.
  Check for anything reading `datetime.now()` or similar inside
  `normalizer.py` (this exact bug existed once already — see
  `ENVIRONMENT.md`).
- **"can't find normalizer" when running the test or checksum script** —
  both scripts locate files relative to their own location, not your
  current directory, so this should only happen if a file was renamed or
  moved out of the project folder.

## Folder structure

```
.
├── ArzensIntern_ShawalShamraiz_normalizer.py
├── ArzensIntern_ShawalShamraiz_checksum.py
├── ArzensIntern_ShawalShamraiz_test_reproducibility.py
├── ArzensIntern_ShawalShamraiz_sample_mixed_logs.txt
├── ArzensIntern_ShawalShamraiz_sample_clean.csv
├── ArzensIntern_ShawalShamraiz_sample_clean.json
├── ArzensIntern_ShawalShamraiz_data_dictionary.txt
├── ArzensIntern_ShawalShamraiz_checksums.txt
├── ArzensIntern_ShawalShamraiz_requirements.txt
├── ArzensIntern_ShawalShamraiz_ENVIRONMENT.md
└── ArzensIntern_ShawalShamraiz_README.md
```

All scripts assume they're sitting together in this same folder — both
`checksum.py` and `test_reproducibility.py` locate the other files
relative to their own script location, not wherever you happen to be
running the command from.

## Files in this submission

| File | Purpose |
|---|---|
| `ArzensIntern_ShawalShamraiz_normalizer.py` | Main normalizer script (Task 2) |
| `ArzensIntern_ShawalShamraiz_sample_mixed_logs.txt` | 25 sample log lines mixing all 4 formats, plus intentional bad data (invalid IP, missing fields, broken JSON, unparseable timestamp, duplicates, garbage line) |
| `ArzensIntern_ShawalShamraiz_sample_clean.csv` | Actual CSV output from running the script on the sample above, with `--deduplicate` |
| `ArzensIntern_ShawalShamraiz_sample_clean.json` | Actual JSON output from the same run |
| `ArzensIntern_ShawalShamraiz_data_dictionary.txt` | Field-by-field documentation of the output schema |
| `ArzensIntern_ShawalShamraiz_requirements.txt` | Dependency list (Task 3) — documents that none are needed |
| `ArzensIntern_ShawalShamraiz_checksum.py` | Generates/verifies MD5 + SHA-256 checksums (Task 3) |
| `ArzensIntern_ShawalShamraiz_checksums.txt` | Saved checksums from the sample run (Task 3) |
| `ArzensIntern_ShawalShamraiz_test_reproducibility.py` | Runs the normalizer twice and diffs the output (Task 3) |
| `ArzensIntern_ShawalShamraiz_ENVIRONMENT.md` | Exact dev environment, OS, and Python version used (Task 3) |
| `ArzensIntern_ShawalShamraiz_README.md` | This file |
