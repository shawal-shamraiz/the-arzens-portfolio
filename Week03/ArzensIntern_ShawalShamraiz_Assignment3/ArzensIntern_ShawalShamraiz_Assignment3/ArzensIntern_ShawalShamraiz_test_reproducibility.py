#!/usr/bin/env python3
"""
test_reproducibility.py

Runs normalizer.py twice on the same input file and checks that both
runs produce byte-for-byte identical CSV and JSON output. If they
match, the normalizer is reproducible. If they don't, something in
the code depends on something it shouldn't (like the system clock,
or unsorted output).

Author: Shawal Shamraiz
THE ARZENS - Beginner Track, Assignment 3, Task 3

Usage:
    python test_reproducibility.py
"""

import filecmp
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

NORMALIZER = os.path.join(SCRIPT_DIR, "ArzensIntern_ShawalShamraiz_normalizer.py")
INPUT_FILE = os.path.join(SCRIPT_DIR, "ArzensIntern_ShawalShamraiz_sample_mixed_logs.txt")

RUN1_CSV = os.path.join(SCRIPT_DIR, "_repro_test_run1.csv")
RUN1_JSON = os.path.join(SCRIPT_DIR, "_repro_test_run1.json")
RUN2_CSV = os.path.join(SCRIPT_DIR, "_repro_test_run2.csv")
RUN2_JSON = os.path.join(SCRIPT_DIR, "_repro_test_run2.json")


def run_normalizer(csv_path, json_path):
    """Runs normalizer.py once with the given output paths."""
    result = subprocess.run(
        [
            sys.executable, NORMALIZER,
            "--input", INPUT_FILE,
            "--output-csv", csv_path,
            "--output-json", json_path,
            "--deduplicate",
        ],
        capture_output=True, text=True
    )
    return result


def cleanup_temp_files():
    for path in (RUN1_CSV, RUN1_JSON, RUN2_CSV, RUN2_JSON):
        if os.path.isfile(path):
            os.remove(path)


def main():
    if not os.path.isfile(NORMALIZER):
        print(f"Error: can't find normalizer at {NORMALIZER}")
        sys.exit(1)
    if not os.path.isfile(INPUT_FILE):
        print(f"Error: can't find input file at {INPUT_FILE}")
        sys.exit(1)

    print("Running normalizer.py - first run...")
    result1 = run_normalizer(RUN1_CSV, RUN1_JSON)
    if result1.returncode != 0:
        print("First run failed to complete:")
        print(result1.stdout)
        print(result1.stderr)
        sys.exit(1)

    print("Running normalizer.py - second run...")
    result2 = run_normalizer(RUN2_CSV, RUN2_JSON)
    if result2.returncode != 0:
        print("Second run failed to complete:")
        print(result2.stdout)
        print(result2.stderr)
        sys.exit(1)

    csv_match = filecmp.cmp(RUN1_CSV, RUN2_CSV, shallow=False)
    json_match = filecmp.cmp(RUN1_JSON, RUN2_JSON, shallow=False)

    print("")
    print(f"CSV outputs identical:  {'YES' if csv_match else 'NO'}")
    print(f"JSON outputs identical: {'YES' if json_match else 'NO'}")
    print("")

    cleanup_temp_files()

    if csv_match and json_match:
        print("RESULT: PASS - normalizer produces identical output on repeated runs.")
        sys.exit(0)
    else:
        print("RESULT: FAIL - output changed between runs. Check for anything")
        print("that depends on the system clock, file listing order, or an")
        print("unsorted dictionary/set somewhere in normalizer.py.")
        sys.exit(1)


if __name__ == "__main__":
    main()
