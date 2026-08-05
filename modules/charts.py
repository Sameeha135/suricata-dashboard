import re
import pandas as pd
import plotly.express as px
import streamlit as st

SEVERITY_LABELS = {1: "High (1)", 2: "Medium (2)", 3: "Low (3)"}

# Fixed Plotly configuration: locked zoom/pan & disabled floating menu
FIXED_CHART_CONFIG = {
    "displayModeBar": False,
    "scrollZoom": False,
    "doubleClick": False,
    "staticPlot": False,
}

# Unified Dark-Theme Blue Color Palette
BLUE_PRIMARY = "#4a90e2"      # Vibrant SIEM primary blue
BLUE_SECONDARY = "#64b5f6"    # Soft light blue for contrast bars
BLUE_CYAN = "#00bcd4"         # Neon cyan for timeline tracking

# Blue-Themed Severity Palette (Deep to Light)
SEVERITY_COLORS = {
    "High (1)": "#1565c0",    # Deep cobalt blue
    "Medium (2)": "#42a5f5",  # Mid slate blue
    "Low (3)": "#90caf9",     # Soft light blue
}


def severity_breakdown_chart(df):
    if df.empty or "severity" not in df.columns:
        st.info("No alert severity data available.")
        return

    # Map numeric severities to labels
    counts = df["severity"].map(SEVERITY_LABELS).value_counts().reset_index()
    counts.columns = ["Severity", "Count"]

    # Ensure all three levels exist for consistent chart rendering
    all_levels = pd.DataFrame({"Severity": ["High (1)", "Medium (2)", "Low (3)"]})
    counts = pd.merge(all_levels, counts, on="Severity", how="left").fillna(0)
    counts["Count"] = counts["Count"].astype(int)

    # Dynamic headroom: Add 18% space above the highest bar so text labels don't clip
    max_count = counts["Count"].max()
    y_max = max(10, int(max_count * 1.18))

    fig = px.bar(
        counts,
        x="Severity",
        y="Count",
        color="Severity",
        color_discrete_map=SEVERITY_COLORS,
        text="Count",
    )

    fig.update_traces(
        textposition="outside",
        cliponaxis=False,  # Prevents Plotly from clipping text outside the plot area
        hovertemplate="<b>%{x}</b><br>Count: %{y}<extra></extra>",
    )

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#ffffff"),
        xaxis=dict(title="", showgrid=False),
        yaxis=dict(
            title="Alert Count",
            showgrid=True,
            gridcolor="rgba(255,255,255,0.1)",
            range=[0, y_max],  # Forces axis scale to draw the gridline above the highest bar
        ),
        margin=dict(l=10, r=10, t=30, b=10),
        showlegend=False,
    )

    st.plotly_chart(fig, width="stretch", config=FIXED_CHART_CONFIG)


def alerts_over_time_chart(df):
    if df.empty or df["timestamp"].isna().all():
        st.info("No timestamped data for the timeline.")
        return

    ts = (
        df.set_index("timestamp")
        .resample("1min")
        .size()
        .reset_index(name="alert_count")
    )

    fig = px.line(ts, x="timestamp", y="alert_count")
    fig.update_traces(line_color=BLUE_CYAN, line_width=2)
    fig.update_layout(
        height=260,
        margin=dict(l=10, r=10, t=10, b=10),
        xaxis_title=None,
        yaxis_title=None,
        dragmode=False,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e0e0e0"),
    )

    st.plotly_chart(fig, width="stretch", config=FIXED_CHART_CONFIG)


def top_signatures_chart(df, n=10):
    if df.empty or "signature" not in df:
        st.info("No signatures to rank.")
        return

    cleaned_df = df.copy()
    emoji_pattern = re.compile(
        r"[\U00010000-\U0010ffff]|[\u2600-\u27BF]|[\U0001f300-\U0001f5ff]"
        r"|[\U0001f600-\U0001f64f]|[\U0001f680-\U0001f6ff]|[\U0001f700-\U0001f77f]"
        r"|[\U0001f780-\U0001f7ff]|[\U0001f800-\U0001f8ff]|[\U0001f900-\U0001f9ff]"
        r"|[\U0001fa00-\U0001fa6f]|[\U0001fa70-\U0001faff]|[\u2700-\u27bf]",
        flags=re.UNICODE,
    )

    cleaned_df["signature"] = cleaned_df["signature"].astype(str).apply(
        lambda x: emoji_pattern.sub(r"", x).strip()
    )

    counts = cleaned_df["signature"].value_counts().head(n).reset_index()
    counts.columns = ["signature", "count"]
    counts = counts.sort_values(by="count", ascending=True)

    # Dynamic X-axis headroom (adds 20% padding to the right for labels)
    max_count = counts["count"].max() if not counts.empty else 0
    x_max = max(10, int(max_count * 1.20))

    fig = px.bar(
        counts,
        x="count",
        y="signature",
        orientation="h",
        text="count",
    )
    
    fig.update_traces(
        marker_color=BLUE_PRIMARY,
        textposition="outside",
        cliponaxis=False,  # Stops Plotly from clipping text outside the plot area
    )
    
    fig.update_layout(
        height=280,
        margin=dict(l=10, r=30, t=10, b=10),  # Extra right margin space for text
        xaxis=dict(range=[0, x_max], title=None),
        yaxis_title=None,
        dragmode=False,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e0e0e0"),
    )

    st.plotly_chart(fig, width="stretch", config=FIXED_CHART_CONFIG)


def traffic_over_time_chart(df):
    if df.empty or df["timestamp"].isna().all():
        st.info("No timestamped data for the traffic timeline.")
        return

    ts = (
        df.set_index("timestamp")
        .resample("1min")
        .size()
        .reset_index(name="event_count")
    )

    fig = px.line(ts, x="timestamp", y="event_count")
    fig.update_traces(line_color=BLUE_PRIMARY, line_width=2)
    fig.update_layout(
        height=260,
        margin=dict(l=10, r=10, t=10, b=10),
        xaxis_title=None,
        yaxis_title=None,
        dragmode=False,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e0e0e0"),
    )

    st.plotly_chart(fig, width="stretch", config=FIXED_CHART_CONFIG)


def top_talkers_chart(df, n=10, ip_column="src_ip"):
    if df.empty or ip_column not in df:
        st.info("No IP data for top talkers.")
        return

    counts = df[ip_column].dropna().value_counts().head(n).reset_index()
    if counts.empty:
        st.info("No IP data for top talkers.")
        return

    counts.columns = [ip_column, "count"]

    max_count = counts["count"].max() if not counts.empty else 0
    y_max = max(10, int(max_count * 1.18))

    fig = px.bar(counts, x=ip_column, y="count", text="count")
    fig.update_traces(
        marker_color=BLUE_SECONDARY,
        textposition="outside",
        cliponaxis=False,
    )
    fig.update_layout(
        height=260,
        margin=dict(l=10, r=10, t=30, b=10),
        xaxis_title=None,
        yaxis=dict(range=[0, y_max], title=None),
        dragmode=False,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e0e0e0"),
    )

    st.plotly_chart(fig, width="stretch", config=FIXED_CHART_CONFIG)


def protocol_distribution_chart(df):
    if df.empty or "proto" not in df:
        st.info("No protocol data available.")
        return

    counts = df["proto"].dropna().value_counts().reset_index()
    if counts.empty:
        st.info("No protocol data available.")
        return

    counts.columns = ["proto", "count"]

    max_count = counts["count"].max() if not counts.empty else 0
    y_max = max(10, int(max_count * 1.18))

    fig = px.bar(counts, x="proto", y="count", text="count")
    fig.update_traces(
        marker_color=BLUE_PRIMARY,
        textposition="outside",
        cliponaxis=False,
    )
    fig.update_layout(
        height=260,
        margin=dict(l=10, r=10, t=30, b=10),
        xaxis_title=None,
        yaxis=dict(range=[0, y_max], title=None),
        dragmode=False,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e0e0e0"),
    )

    st.plotly_chart(fig, width="stretch", config=FIXED_CHART_CONFIG)


def kpi_row(alerts_df, traffic_df):
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Alerts", len(alerts_df))
    high_sev = len(alerts_df[alerts_df["severity"] == 1]) if not alerts_df.empty else 0
    col2.metric("High Severity", high_sev)
    col3.metric(
        "Unique Signatures",
        alerts_df["signature"].nunique() if not alerts_df.empty else 0,
    )
    col4.metric("Traffic Events", len(traffic_df))
    unique_talkers = (
        traffic_df["src_ip"].nunique()
        if not traffic_df.empty and "src_ip" in traffic_df
        else 0
    )
    col5.metric("Active Source IPs", unique_talkers)