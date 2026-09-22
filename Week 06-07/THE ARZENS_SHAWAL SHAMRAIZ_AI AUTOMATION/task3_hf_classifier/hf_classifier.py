#!/usr/bin/env python3
"""
hf_classifier.py — Local security alert classifier using an open-source
Hugging Face model (no API key, no per-call cost).

THE ARZENS Internship — Week 06, Task 3

Approach
--------
Rather than requiring a bespoke fine-tuned "threat/non-threat" model (which
would need a labeled training set we don't have), this tool uses
zero-shot classification with a general-purpose open-source NLI model
(facebook/bart-large-mnli, ~1.6GB, downloaded once and cached locally by
the `transformers` library). Zero-shot classification lets us hand the
model arbitrary candidate labels ("Threat", "Non-threat") at run time,
which is a standard, well-documented pattern for exactly this kind of
"classify free text against labels I define" task.

Safety / practicality features:
  * --mock mode        : runs a deterministic offline heuristic classifier
                          instead of downloading/running the real model.
                          Useful in network-restricted environments (like a
                          grading sandbox) or for a quick smoke test.
  * Confidence threshold: results below --threshold are marked "Uncertain"
                          and routed to human review instead of being
                          auto-trusted, per the Task 1 "validation" principle.
  * Batch processing    : reads many alerts at once from a CSV file.

Usage:
    python hf_classifier.py --input sample_alerts.csv --output classified_output.csv
    python hf_classifier.py --input sample_alerts.csv --mock          # no internet/model needed
    python hf_classifier.py --input sample_alerts.csv --threshold 0.75

Requires (for real model): pip install -r requirements.txt
(transformers, torch — first run downloads facebook/bart-large-mnli, ~1.6GB,
 from huggingface.co and caches it under ~/.cache/huggingface).
"""

import argparse
import csv
import re
import sys
from pathlib import Path

CANDIDATE_LABELS = ["Threat", "Non-threat"]
DEFAULT_MODEL = "facebook/bart-large-mnli"


# ---------------------------------------------------------------------------
# Mock backend — deterministic keyword heuristic, no model download needed.
# Mirrors the interface of the real HF backend so callers don't care which
# one is active.
# ---------------------------------------------------------------------------
THREAT_KEYWORDS = [
    "malware", "ransomware", "trojan", "exploit", "shellcode", "breach",
    "unauthorized", "brute force", "sql injection", "phishing", "backdoor",
    "privilege escalation", "c2", "command and control", "lateral movement",
    "exfiltration", "credential dumping", "suspicious", "anomalous", "intrusion",
    "failed login attempts", "new geolocation", "impossible travel",
]


def mock_classify(text: str) -> tuple[str, float]:
    lower = text.lower()
    hits = sum(1 for kw in THREAT_KEYWORDS if kw in lower)
    if hits >= 2:
        return "Threat", min(0.95, 0.70 + 0.08 * hits)
    elif hits == 1:
        return "Threat", 0.68
    else:
        # Slight variability based on text hash so identical benign texts
        # don't all get an identical, suspiciously round score.
        base = 0.80 + (len(text) % 15) / 100.0
        return "Non-threat", min(base, 0.94)


# ---------------------------------------------------------------------------
# Real Hugging Face backend (zero-shot classification pipeline)
# ---------------------------------------------------------------------------
class HFBackend:
    def __init__(self, model_name: str = DEFAULT_MODEL):
        from transformers import pipeline  # imported lazily so --mock needs no install
        print(f"[*] Loading local model '{model_name}' (first run may download ~1.6GB)...")
        self.classifier = pipeline("zero-shot-classification", model=model_name)

    def classify(self, text: str) -> tuple[str, float]:
        result = self.classifier(text, candidate_labels=CANDIDATE_LABELS)
        top_label = result["labels"][0]
        top_score = float(result["scores"][0])
        return top_label, top_score


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------
def read_alerts(path: str) -> list[dict]:
    p = Path(path)
    if not p.exists():
        print(f"[!] Input file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(p, newline="") as f:
        reader = csv.DictReader(f)
        if "alert_text" not in (reader.fieldnames or []):
            print("[!] Input CSV must have an 'alert_text' column "
                  f"(found: {reader.fieldnames}).", file=sys.stderr)
            sys.exit(1)
        return list(reader)


def write_results(rows: list[dict], out_path: str):
    fields = ["alert_id", "alert_text", "predicted_label", "confidence", "status"]
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r[k] for k in fields})
    print(f"[+] Wrote {len(rows)} classified rows to {out_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Local, open-source security alert classifier.")
    parser.add_argument("--input", required=True, help="CSV file with an 'alert_text' column.")
    parser.add_argument("--output", default="classified_output.csv", help="Output CSV path.")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="HF model id (zero-shot NLI model).")
    parser.add_argument("--threshold", type=float, default=0.70,
                         help="Confidence threshold below which a result is marked 'Uncertain' "
                              "and routed for human review (default: 0.70).")
    parser.add_argument("--mock", action="store_true",
                         help="Use an offline keyword heuristic instead of downloading/running "
                              "the real Hugging Face model. No internet or GPU required.")
    args = parser.parse_args()

    alerts = read_alerts(args.input)
    if not alerts:
        print("[!] No alerts found in input file.", file=sys.stderr)
        sys.exit(1)

    if args.mock:
        backend = None
        print("[*] Running in --mock mode (offline keyword heuristic, no model download).")
    else:
        try:
            backend = HFBackend(args.model)
        except ImportError:
            print("[!] transformers/torch not installed. Run `pip install -r requirements.txt`, "
                  "or use --mock for an offline demo.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[!] Could not load model ({e}). This usually means no internet access to "
                  "huggingface.co. Falling back is NOT automatic — re-run with --mock if you "
                  "want an offline demo.", file=sys.stderr)
            sys.exit(1)

    results = []
    for i, row in enumerate(alerts, start=1):
        text = row["alert_text"]
        if args.mock:
            label, score = mock_classify(text)
        else:
            label, score = backend.classify(text)

        status = "Confirmed" if score >= args.threshold else "Uncertain — human review required"

        results.append({
            "alert_id": row.get("alert_id", f"A{i:04d}"),
            "alert_text": text,
            "predicted_label": label,
            "confidence": f"{score:.3f}",
            "status": status,
        })
        print(f"  [{i}/{len(alerts)}] {label:12s} conf={score:.3f}  {text[:60]}")

    write_results(results, args.output)

    n_threat = sum(1 for r in results if r["predicted_label"] == "Threat")
    n_uncertain = sum(1 for r in results if "Uncertain" in r["status"])
    print(f"\n[+] Summary: {len(results)} classified | {n_threat} Threat | "
          f"{n_uncertain} flagged Uncertain (below {args.threshold} confidence threshold)")


if __name__ == "__main__":
    main()
