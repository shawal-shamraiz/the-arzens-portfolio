"""
dashboard.py
------------
Simple interactive security dashboard built with Streamlit (Task 6).

Run with:
    streamlit run dashboard.py

Then upload a CSV with columns: event_id, timestamp, severity, event_type, source_ip
(sample_events.csv from Task 5 works directly.)
"""

import streamlit as st
import pandas as pd

st.set_page_config(page_title="Security Dashboard", layout="wide")

st.title("Security Dashboard")
st.caption("Upload a security events CSV to explore it below.")

uploaded_file = st.file_uploader("Upload events CSV", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)

    # Try to parse timestamps if present, for the "events over time" chart
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    # ---- Filter ----
    severities_available = sorted(df["severity"].dropna().unique().tolist()) if "severity" in df.columns else []
    selected_severities = st.multiselect(
        "Filter by severity",
        options=severities_available,
        default=severities_available,
    )

    if selected_severities:
        filtered_df = df[df["severity"].isin(selected_severities)]
    else:
        filtered_df = df

    # ---- Big KPI numbers ----
    col1, col2, col3, col4 = st.columns(4)
    total = len(filtered_df)
    critical = int((filtered_df["severity"] == "Critical").sum()) if "severity" in filtered_df.columns else 0
    high = int((filtered_df["severity"] == "High").sum()) if "severity" in filtered_df.columns else 0
    col1.metric("Total Events", f"{total:,}")
    col2.metric("Critical", critical)
    col3.metric("High", high)
    if "source_ip" in filtered_df.columns and not filtered_df.empty:
        top_ip = filtered_df["source_ip"].value_counts().idxmax()
        col4.metric("Top Source IP", top_ip)

    # ---- Table ----
    st.subheader("Events")
    st.write(filtered_df)

    # ---- Bar chart: events by severity ----
    if "severity" in filtered_df.columns:
        st.subheader("Events by Severity")
        st.bar_chart(filtered_df["severity"].value_counts())

    # ---- Line chart: events over time (by hour) ----
    if "timestamp" in filtered_df.columns and filtered_df["timestamp"].notna().any():
        st.subheader("Events Over Time (by hour)")
        hourly = (
            filtered_df.dropna(subset=["timestamp"])
            .set_index("timestamp")
            .resample("h")
            .size()
        )
        st.line_chart(hourly)
else:
    st.info("Upload a CSV file to see the dashboard. You can use sample_events.csv from Task 5.")
