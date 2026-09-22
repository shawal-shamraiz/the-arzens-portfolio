# Streamlit Security Dashboard — How to Run

## What this is
An interactive web dashboard (`dashboard.py`) built with
[Streamlit](https://streamlit.io) that lets you upload a security events CSV
and instantly see:
- Big KPI numbers (total events, critical count, high count, top source IP)
- A filterable table of all events
- A bar chart of events by severity
- A line chart of events over time (by hour)
- A severity filter (multi-select)

## Setup

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the dashboard**
   ```bash
   streamlit run dashboard.py
   ```
   This opens automatically in your browser at `http://localhost:8501`.

3. **Upload data**
   Click "Upload events CSV" and select `sample_events.csv` (generated in
   Task 5), or any CSV with these columns:
   ```
   event_id, timestamp, severity, event_type, source_ip
   ```

4. **Explore**
   - Use the severity multi-select to filter the dashboard down to just
     `Critical` and `High`, for example.
   - The table, KPIs, and both charts update automatically based on the
     filter.

5. **Take your screenshot**
   With the dashboard running and data uploaded in your browser, take a
   screenshot of the page and save it as `screenshot.png`. This has to be
   done on your machine since it requires actually running the Streamlit
   server and opening a browser — it can't be generated for you ahead of
   time.

## Troubleshooting
- If `streamlit` isn't recognized as a command, make sure your Python
  `Scripts`/`bin` folder is on your PATH, or run it as
  `python -m streamlit run dashboard.py`.
- If the "Events Over Time" chart doesn't appear, check that your CSV's
  `timestamp` column is in a standard format like `2026-09-10 14:32:05`.
