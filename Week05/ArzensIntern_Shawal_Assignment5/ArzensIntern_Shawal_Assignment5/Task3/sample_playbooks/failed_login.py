#!/usr/bin/env python3
"""
Failed Login Anomaly / Brute Force Detection (stub playbook)
Registered but disabled, and its config file is intentionally not
present in this submission. This demonstrates the manager's
--health-check correctly reporting a missing-config playbook.
"""
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description="Failed Login Anomaly (stub)")
    parser.add_argument("--input-file")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    print("+==========================================================+")
    print("| FAILED LOGIN / BRUTE FORCE PLAYBOOK v1.0                  |")
    print("+==========================================================+")
    print("Simulated action: check_geo_location, verify_threat_intel")
    print("Decision: Confirmed brute force -> block IP (simulated)")
    if args.dry_run:
        print("[DRY-RUN MODE - No actions taken]")
    print("Done.")
    sys.exit(0)


if __name__ == "__main__":
    main()
