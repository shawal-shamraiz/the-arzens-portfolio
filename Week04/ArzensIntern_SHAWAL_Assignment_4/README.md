# THE ARZENS Threat Intelligence Enricher

A beginner-level Python tool that checks IP addresses, domains, file hashes,
and URLs against threat intelligence APIs (VirusTotal and AbuseIPDB, with
optional AlienVault OTX support), and prints out an easy-to-read verdict.

Built for Assignment 4 (Beginner Track) of THE ARZENS internship program.

## Project Structure

```
threat_intel_tool.py     - main script
config.yaml               - API keys and settings (edit this before running)
sample_indicators.txt     - example list of indicators to test with
sample_output.json        - example JSON output
sample_output.csv         - example CSV output
sample_report.txt         - example text report
README.md                 - this file
```

When you run the tool it will also create:
- `cache.json` - stores past results so the same indicator is not checked twice
- your chosen output files (JSON, CSV, and a text report)

## 1. Installation

You need Python 3.8 or newer.

Clone or download this project, then install the required libraries:

```bash
pip install requests pyyaml colorama
```

`argparse`, `json`, and `csv` come built into Python, so you don't need to
install them separately.

## 2. Required Libraries

| Library    | What it's used for                       |
|------------|-------------------------------------------|
| requests   | Making HTTP calls to the APIs             |
| pyyaml     | Reading the config.yaml file              |
| colorama   | Coloring the console output (red/yellow/green) |
| argparse   | Reading command-line arguments (built-in) |
| json       | Reading/writing JSON files (built-in)     |
| csv        | Writing CSV files (built-in)              |

## 3. Getting API Keys

You need at least two of these three keys for the tool to be useful.

**VirusTotal**
1. Go to https://www.virustotal.com/gui/join-us
2. Create a free account.
3. Click your profile icon, then "API Key" to find your key.
4. Free tier limits: 500 requests/day, 4 requests/minute.

**AbuseIPDB**
1. Go to https://www.abuseipdb.com/register
2. Create a free account.
3. Go to the Account page, then "API" tab to find your key.
4. Free tier limits: 1,000 checks/day.

**AlienVault OTX** (optional in this tool)
1. Go to https://otx.alienvault.com
2. Create a free account.
3. Click your profile, then "API Integration" to find your key.

Once you have your keys, open `config.yaml` and paste them in:

```yaml
api_keys:
  virustotal: "PASTE_YOUR_KEY_HERE"
  abuseipdb: "PASTE_YOUR_KEY_HERE"
  otx: "PASTE_YOUR_KEY_HERE"
```

**Never hardcode your API keys inside threat_intel_tool.py.** Always use
config.yaml, and never upload config.yaml with your real keys to GitHub.
Add it to a `.gitignore` file if you plan to push this project publicly.

## 4. Example Commands

Check a single IP address:
```bash
python threat_intel_tool.py --ip 185.220.101.42
```

Check a domain:
```bash
python threat_intel_tool.py --domain example.com
```

Check a file hash:
```bash
python threat_intel_tool.py --hash 44d88612fea8a8f36de82e1278abb02f
```

Check multiple indicator types at once:
```bash
python threat_intel_tool.py --ip 8.8.8.8 --domain example.com
```

Check a whole list of indicators from a file:
```bash
python threat_intel_tool.py --input-file sample_indicators.txt
```

Enter indicators one at a time:
```bash
python threat_intel_tool.py --interactive
```

Choose a custom name for your output files:
```bash
python threat_intel_tool.py --ip 8.8.8.8 --output my_results
```
This creates `my_results.json`, `my_results.csv`, and `my_results_report.txt`.

## 5. How the Tool Works (Short Version)

1. Reads your API keys and settings from `config.yaml`.
2. Collects indicators from the command line, a file, or interactive input.
3. Checks each indicator's format (e.g. does it actually look like an IP?).
4. Checks the local cache first, so the same indicator is not looked up twice.
5. Calls VirusTotal and/or AbuseIPDB (and OTX if enabled), waiting a few
   seconds between calls to respect API rate limits.
6. If a request fails, it retries up to 3 times with exponential backoff
   (waits 2s, then 4s, then 8s).
7. Combines the results into one overall verdict: CLEAN, SUSPICIOUS, or
   MALICIOUS.
8. Prints a colored report to the console and saves JSON, CSV, and text
   report files.

## 6. Notes

- AbuseIPDB only supports IP addresses, so it is skipped automatically for
  domains, hashes, and URLs.
- This tool does not support URL lookups yet on VirusTotal/OTX (that would
  need file/URL submission endpoints, which are a good next step to add).
- The `use_otx` setting in config.yaml is off by default. Turn it to `true`
  once you have an OTX key.
