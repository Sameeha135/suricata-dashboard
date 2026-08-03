import streamlit as st
import pandas as pd
import re


SEVERITY_LABELS = {1: "High (1)", 2: "Medium (2)", 3: "Low (3)"}


def severity_breakdown_chart(df):
    if df.empty or "severity" not in df:
        st.info("No data for severity breakdown.")
        return
    counts = df["severity"].value_counts().sort_index()
    counts.index = counts.index.map(lambda s: SEVERITY_LABELS.get(s, f"Unknown ({s})"))
    st.bar_chart(counts)


def alerts_over_time_chart(df):
    if df.empty or df["timestamp"].isna().all():
        st.info("No timestamped data for the timeline.")
        return
    ts = df.set_index("timestamp").resample("1min").size()
    st.line_chart(ts)



def top_signatures_chart(df, n=10):
    if df.empty:
        st.info("No signatures to rank.")
        return
    
    cleaned_df = df.copy()
    # Regex pattern to remove common emojis and symbols found in signatures
    emoji_pattern = re.compile(r"[\U00010000-\U0010ffff]|[\u2600-\u27BF]|[\U0001f300-\U0001f5ff]|[\U0001f600-\U0001f64f]|[\U0001f680-\U0001f6ff]|[\U0001f700-\U0001f77f]|[\U0001f780-\U0001f7ff]|[\U0001f800-\U0001f8ff]|[\U0001f900-\U0001f9ff]|[\U0001fa00-\U0001fa6f]|[\U0001fa70-\U0001faff]|[\u2700-\u27bf]", flags=re.UNICODE)
    
    cleaned_df["signature"] = cleaned_df["signature"].astype(str).apply(
        lambda x: emoji_pattern.sub(r"", x).strip()
    )
    
    st.bar_chart(cleaned_df["signature"].value_counts().head(n))


def traffic_over_time_chart(df):
    """Mirrors alerts_over_time_chart but for general traffic volume -
    lets you see spikes in background/scan activity, not just alerts."""
    if df.empty or df["timestamp"].isna().all():
        st.info("No timestamped data for the traffic timeline.")
        return
    ts = df.set_index("timestamp").resample("1min").size()
    st.line_chart(ts)


def top_talkers_chart(df, n=10, ip_column="src_ip"):
    # Ranks source IPs by event count 
    if df.empty or ip_column not in df:
        st.info("No IP data for top talkers.")
        return
    counts = df[ip_column].dropna().value_counts().head(n)
    if counts.empty:
        st.info("No IP data for top talkers.")
        return
    st.bar_chart(counts)


def protocol_distribution_chart(df):
    # Breaks down traffic by protocol (TCP/UDP/ICMP/etc)
    if df.empty or "proto" not in df:
        st.info("No protocol data available.")
        return
    counts = df["proto"].dropna().value_counts()
    if counts.empty:
        st.info("No protocol data available.")
        return
    st.bar_chart(counts)


def kpi_row(alerts_df, traffic_df):
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Alerts", len(alerts_df))
    high_sev = len(alerts_df[alerts_df["severity"] == 1]) if not alerts_df.empty else 0
    col2.metric("High Severity", high_sev)
    col3.metric("Unique Signatures", alerts_df["signature"].nunique() if not alerts_df.empty else 0)
    col4.metric("Traffic Events", len(traffic_df))
    unique_talkers = traffic_df["src_ip"].nunique() if not traffic_df.empty and "src_ip" in traffic_df else 0
    col5.metric("Active Source IPs", unique_talkers)