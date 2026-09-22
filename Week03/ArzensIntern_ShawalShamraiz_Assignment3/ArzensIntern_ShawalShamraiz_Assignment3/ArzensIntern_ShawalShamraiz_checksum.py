#!/usr/bin/env python3
"""
checksum.py

Calculates MD5 and SHA-256 hashes of the normalizer's input and output
files, so we can prove later that a re-run produced the exact same
bytes. Can also run in --verify mode to check a previous run's saved
hashes against what's on disk right now.

Author: Shawal Shamraiz
THE ARZENS - Beginner Track, Assignment 3, Task 3

Usage:
    python checksum.py
    python checksum.py --verify
"""

import argparse
import hashlib
import os
import sys
from datetime import datetime, timezone

# default files we're checking - these are relative paths so this works
# no matter where the project folder ends up on someone's machine
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_FILES = {
    "input": "ArzensIntern_ShawalShamraiz_sample_mixed_logs.txt",
    "csv_output": "ArzensIntern_ShawalShamraiz_sample_clean.csv",
    "json_output": "ArzensIntern_ShawalShamraiz_sample_clean.json",
}

CHECKSUM_FILE = "ArzensIntern_ShawalShamraiz_checksums.txt"


def get_md5(file_path):
    """Reads a file in chunks and returns its MD5 hash as a hex string."""
    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def get_sha256(file_path):
    """Same idea as get_md5, just with SHA-256 instead."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def generate_checksums(files_dict, output_path):
    """
    Computes MD5 + SHA-256 for every file in files_dict and writes them
    all to output_path along with a timestamp.
    """
    lines = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for label, file_path in files_dict.items():
        full_path = os.path.join(SCRIPT_DIR, file_path)

        if not os.path.isfile(full_path):
            print(f"Skipping '{label}' - file not found: {file_path}")
            continue

        md5_hash = get_md5(full_path)
        sha_hash = get_sha256(full_path)

        lines.append(f"File: {label} ({file_path})")
        lines.append(f"MD5: {md5_hash}")
        lines.append(f"SHA256: {sha_hash}")
        lines.append(f"Generated: {now}")
        lines.append("")

        print(f"{label}: {file_path}")
        print(f"  MD5:    {md5_hash}")
        print(f"  SHA256: {sha_hash}")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\nChecksums written to {os.path.basename(output_path)}")


def read_saved_checksums(checksum_path):
    """
    Parses our own checksums.txt format back into a dict:
    { label: {"path": ..., "md5": ..., "sha256": ...} }
    """
    saved = {}
    current_label = None
    current_path = None

    with open(checksum_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("File:"):
                # line looks like: File: input (some_file.txt)
                inside = line.split("File:", 1)[1].strip()
                current_label = inside.split("(")[0].strip()
                current_path = inside.split("(")[1].rstrip(")").strip()
                saved[current_label] = {"path": current_path}
            elif line.startswith("MD5:") and current_label:
                saved[current_label]["md5"] = line.split("MD5:", 1)[1].strip()
            elif line.startswith("SHA256:") and current_label:
                saved[current_label]["sha256"] = line.split("SHA256:", 1)[1].strip()

    return saved


def verify_checksums(files_dict, checksum_path):
    """
    Recomputes hashes for the current files on disk and compares them
    against what's stored in checksum_path. Prints PASS/FAIL per file
    and an overall result at the end.
    """
    if not os.path.isfile(checksum_path):
        print(f"Error: no checksum file found at {os.path.basename(checksum_path)}.")
        print("Run 'python checksum.py' first (without --verify) to generate one.")
        sys.exit(1)

    saved = read_saved_checksums(checksum_path)
    all_passed = True

    for label, file_path in files_dict.items():
        full_path = os.path.join(SCRIPT_DIR, file_path)

        if label not in saved:
            print(f"{label}: no saved checksum on record, skipping")
            continue

        if not os.path.isfile(full_path):
            print(f"{label}: FAIL - file '{file_path}' no longer exists")
            all_passed = False
            continue

        current_md5 = get_md5(full_path)
        current_sha = get_sha256(full_path)

        md5_match = current_md5 == saved[label].get("md5")
        sha_match = current_sha == saved[label].get("sha256")

        if md5_match and sha_match:
            print(f"{label}: PASS ({file_path})")
        else:
            print(f"{label}: FAIL ({file_path}) - hash does not match saved checksum")
            all_passed = False

    print("")
    if all_passed:
        print("Overall result: PASS - all files match their saved checksums.")
    else:
        print("Overall result: FAIL - one or more files do not match.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Generate or verify MD5/SHA-256 checksums for the normalizer's input and output files."
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Check current files against previously saved checksums instead of generating new ones"
    )
    args = parser.parse_args()

    checksum_path = os.path.join(SCRIPT_DIR, CHECKSUM_FILE)

    try:
        if args.verify:
            verify_checksums(DEFAULT_FILES, checksum_path)
        else:
            generate_checksums(DEFAULT_FILES, checksum_path)
    except PermissionError as err:
        print(f"Error: permission denied ({err})")
        sys.exit(1)
    except OSError as err:
        print(f"Error: something went wrong reading or writing a file ({err})")
        sys.exit(1)


if __name__ == "__main__":
    main()
