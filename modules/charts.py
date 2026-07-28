import streamlit as st


def severity_breakdown_chart(df):
    if df.empty or "severity" not in df:
        st.info("No data for severity breakdown.")
        return
    st.bar_chart(df["severity"].value_counts().sort_index())


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
    st.bar_chart(df["signature"].value_counts().head(n))


def kpi_row(alerts_df, traffic_df):
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Alerts", len(alerts_df))
    high_sev = len(alerts_df[alerts_df["severity"] == 1]) if not alerts_df.empty else 0
    col2.metric("High Severity", high_sev)
    col3.metric("Unique Signatures", alerts_df["signature"].nunique() if not alerts_df.empty else 0)
    col4.metric("Traffic Events", len(traffic_df))