# ENVIRONMENT.md

**Author:** Shawal Shamraiz
THE ARZENS Beginner Track — Assignment 3, Task 3

This documents the environment the project was actually built and tested
in, so anyone re-running it later knows what to expect.

## Python version

Python 3.12.3

The project itself doesn't need anything that new — anything Python 3.9
or newer should work fine, since it only uses standard library modules
(`argparse`, `csv`, `json`, `re`, `datetime`, `hashlib`, `subprocess`,
`filecmp`, `os`, `sys`). I just happened to develop it on 3.12.3.

## Operating system

Linux (Ubuntu-based), x86_64

The code doesn't do anything OS-specific — no hardcoded path separators,
no OS-only libraries — so it should run the same way on Windows or macOS.
I didn't have a Windows machine to test on directly, so if something
breaks there it's most likely a path-separator issue I didn't catch.

## Development environment

Command line + a text editor, no IDE-specific project files. All scripts
are plain `.py` files meant to be run directly with `python3`.

## Virtual environment setup

Not strictly required, since there are no external packages to isolate,
but it's still good practice:

```bash
python3 -m venv venv
source venv/bin/activate       # on Windows: venv\Scripts\activate
```

There's nothing to install into it (`ArzensIntern_ShawalShamraiz_requirements.txt`
explains why), so this step is really just for keeping the project's
Python environment separate from anything else on your machine.

## Installation source

Python itself was already installed on the system (no custom build).
No packages were installed from PyPI, since none were needed.

## Project folder structure

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

All scripts assume they're sitting in this same folder together — they
find each other using paths relative to their own location, not the
folder you happen to be running the command from.

## Date created

22 July 2026

## Last tested

2 August 2026 — reran `test_reproducibility.py` and `checksum.py --verify`
after fixing a bug in the DNS/syslog timestamp parser (it was reading the
year off the system clock instead of using a fixed value, which meant
re-running the script in a different year could have silently produced
different output). Both passed after the fix.

## Important notes

- The DNS/syslog log format in the sample data doesn't include a year
  (e.g. `Jul 20 14:23:45`). The normalizer assumes these logs are from
  2026, since that matches the rest of the sample dataset. This is
  hardcoded on purpose — see the comment above `SYSLOG_YEAR_ASSUMPTION`
  in `normalizer.py` — so that results stay identical no matter when the
  script is actually run.
- `checksum.py` and `test_reproducibility.py` both use `os.path.dirname`
  to locate files relative to their own script location, not the current
  working directory, so they work correctly even if you `cd` somewhere
  else first and call them with a full path.
