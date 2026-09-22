# WORKFLOWS.md

This document explains the two automation workflows built on top of
`threat_intel_tool.py`. Both scripts import functions from that file
instead of rewriting them, so make sure `threat_intel_tool.py` and
`config.yaml` are in the same folder before running these.

---

## Workflow 1: Alert Enrichment Pipeline (`alert_enricher.py`)

### Purpose
A SOC alert usually just gives you a raw indicator, like an IP address,
with no context about how dangerous it actually is. This workflow takes
one alert, enriches the indicator automatically, works out a risk score,
and writes a ready-to-read incident report — so an analyst doesn't have
to look the indicator up by hand.

### How it works
1. Reads the alert from a JSON file (see `sample_alert.json`).
2. Figures out the indicator type (uses the type in the alert if given,
   otherwise guesses it, same as `threat_intel_tool.py` does).
3. Calls `enrich_indicator()` from `threat_intel_tool.py` to check the
   indicator against VirusTotal / AbuseIPDB / OTX.
4. Calculates a risk score from 0-100 using a simple formula:
   - starting points based on the overall verdict (Clean/Suspicious/Malicious)
   - extra points based on the alert's severity field
   - a small bonus based on each source's own numbers (detections,
     confidence score, pulse count)
5. Turns the score into a level: LOW, MEDIUM, HIGH, or CRITICAL.
6. Picks a list of recommended actions based on the score.
7. Builds a text incident report and saves it to the `incidents/` folder,
   named with a timestamped ID like `INC-20260801-143005.txt`.
8. Prints a short colored summary to the console.

### Required files
- `threat_intel_tool.py` (must be in the same folder)
- `config.yaml` (holds your API keys and settings)
- an alert JSON file, e.g. `sample_alert.json`

### Example commands
Run with the sample alert:
```bash
python alert_enricher.py --alert sample_alert.json
```

Run with your own alert file:
```bash
python alert_enricher.py --alert my_alert.json --config config.yaml
```

### Sample alert format
```json
{
  "timestamp": "2026-08-01T14:30:00Z",
  "alert_type": "Suspicious Outbound Connection",
  "indicator": "185.220.101.42",
  "indicator_type": "ip",
  "severity": "high",
  "source": "Firewall"
}
```

---

## Workflow 2: Bulk Indicator Analysis (`bulk_analyzer.py`)

### Purpose
Sometimes a threat intel team hands you a whole list of indicators, not
just one. This workflow processes all of them, keeps going even if a
few fail, and produces a detailed CSV plus an easy-to-read HTML summary
report for the team.

### How it works
1. Reads indicators from a CSV file with columns `indicator, type, source`
   (see `sample_indicators_bulk.csv`).
2. Loops through every indicator one at a time and calls
   `enrich_indicator()` from `threat_intel_tool.py`.
   - Rate limiting is already handled inside `enrich_indicator()` (it
     sleeps between API calls), so this script does not add extra delays.
   - If one indicator throws an error, the script prints a warning and
     moves on to the next one instead of stopping the whole batch.
3. Builds summary statistics:
   - Total indicators processed
   - Clean / Suspicious / Malicious counts
   - Top threat categories (based on OTX tags, since that is the only
     source in `threat_intel_tool.py` that returns tag/category data)
   - Most reported indicators (based on AbuseIPDB's report count)
4. Saves a detailed CSV with one row per indicator and its verdict from
   each source.
5. Saves an HTML report with the summary statistics in styled tables.
6. Prints a short colored summary to the console.

### Required files
- `threat_intel_tool.py` (must be in the same folder)
- `config.yaml` (holds your API keys and settings)
- a CSV file of indicators, e.g. `sample_indicators_bulk.csv`

### Example commands
Run with the sample CSV:
```bash
python bulk_analyzer.py --input sample_indicators_bulk.csv
```

Choose a custom name for the output files:
```bash
python bulk_analyzer.py --input sample_indicators_bulk.csv --output my_bulk_run
```
This creates `my_bulk_run.csv` and `my_bulk_run.html`.

### Sample CSV format
```csv
indicator,type,source
185.220.101.42,ip,Firewall
malicious-test-domain.com,domain,Proxy
44d88612fea8a8f36de82e1278abb02f,hash,Email Gateway
```

---

## Folder Structure

```
threat_intel_tool.py          - core functions (both workflows import from this)
config.yaml                   - API keys and settings
alert_enricher.py             - Workflow 1
bulk_analyzer.py              - Workflow 2
sample_alert.json             - test input for Workflow 1
sample_indicators_bulk.csv    - test input for Workflow 2
WORKFLOWS.md                  - this file

incidents/                    - created automatically by alert_enricher.py
  INC-20260801-143005.txt     - one incident report per alert processed

cache.json                    - created automatically, avoids duplicate API calls
bulk_results.csv              - created by bulk_analyzer.py (detailed results)
bulk_results.html             - created by bulk_analyzer.py (summary report)
```

## Notes

- Both workflows share the same `cache.json` file as `threat_intel_tool.py`,
  so if you already checked an indicator recently, it won't be looked up
  again.
- Both workflows use `config.yaml` for API keys, the same as
  `threat_intel_tool.py`. Never hardcode API keys in these scripts.
- If `threat_intel_tool.py` is missing from the folder, both scripts will
  fail to import and won't run — that file is required, not optional.
