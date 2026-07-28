import json
import sqlite3
from zoneinfo import ZoneInfo
import pandas as pd
import streamlit as st
from modules import alert_store
from modules.charts import (
    alerts_over_time_chart,
    kpi_row,
    severity_breakdown_chart,
    top_signatures_chart,
)
from modules.data_loader import load_rule_catalog
from modules.filters import sidebar_alert_filters, sidebar_traffic_filters
from modules.ingestor import ingest_logs

st.set_page_config(page_title="Suricata Monitor", layout="wide")

st.markdown(
    """
<style>
    /* Disable the fade/dim effect during fragment reruns */
    div[data-testid="stFragment"] {
        opacity: 1 !important;
        transition: none !important;
    }
    div[data-testid="stMetric"] {
        background-color: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 10px;
        padding: 12px 16px;
    }
    div[data-testid="stExpander"] {
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 8px;
    }
    .sev-chip {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 999px;
        font-size: 0.8em;
        font-weight: 600;
        margin-right: 6px;
    }
    .sev-high { background-color: rgba(220,60,60,0.25); color: #ff8080; }
    .sev-medium { background-color: rgba(220,150,40,0.25); color: #ffb84d; }
    .sev-low { background-color: rgba(80,140,220,0.25); color: #7fb2ff; }
    .sev-unknown { background-color: rgba(150,150,150,0.2); color: #bbbbbb; }
</style>
""",
    unsafe_allow_html=True,
)

st.title("Suricata Monitoring Dashboard")

rule_catalog = load_rule_catalog()
LOCAL_TZ = ZoneInfo("Asia/Karachi")


@st.cache_data(ttl=5)
def load_alerts_from_db(include_reviewed=False):
  conn = sqlite3.connect("alerts.db")
  conn.execute("PRAGMA journal_mode=WAL;")  # <-- Add here
  query = "SELECT * FROM alerts"
  if not include_reviewed:
    query += " WHERE status = 'new'"
  query += " ORDER BY timestamp DESC"
  df = pd.read_sql_query(query, conn)
  conn.close()
  if not df.empty:
    if "timestamp" in df.columns:
      df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if "raw_json" in df.columns:
      df["raw"] = df["raw_json"].apply(lambda x: json.loads(x) if x else {})
  return df


@st.cache_data(ttl=5)
def load_traffic_from_db():
  conn = sqlite3.connect("alerts.db")
  conn.execute("PRAGMA journal_mode=WAL;")  # <-- And add here
  try:
    df = pd.read_sql_query(
        "SELECT * FROM traffic ORDER BY timestamp DESC LIMIT 2000", conn
    )
  except Exception:
    df = pd.DataFrame()
  conn.close()
  if not df.empty and "timestamp" in df.columns:
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
  return df


def _format_local(ts_series, use_12hr):
  if ts_series.empty:
    return ts_series
  local = ts_series.dt.tz_convert(LOCAL_TZ)
  fmt = "%Y-%m-%d %I:%M:%S %p" if use_12hr else "%Y-%m-%d %H:%M:%S"
  return local.dt.strftime(fmt)


def _sev_chip_class(sev_label):
  label = str(sev_label or "").lower()
  if "high" in label or "1" in label:
    return "sev-high"
  elif "medium" in label or "2" in label:
    return "sev-medium"
  else:
    return "sev-low"


@st.fragment(run_every=15)
def render_dashboard():
  try:
    ingest_logs()
  except Exception as e:
    st.error(f"Ingestion error: {e}")

  # Load traffic events from SQLite database
  traffic_df = load_traffic_from_db()

  use_12hr = st.sidebar.checkbox(
      "Use 12-hour clock (AM/PM)", value=False, key="use_12hr_toggle"
  )
  show_reviewed = st.sidebar.checkbox(
      "Show reviewed / false-positive alerts",
      value=False,
      key="show_reviewed_toggle",
  )
  st.sidebar.divider()

  alerts_df = load_alerts_from_db(include_reviewed=show_reviewed)

  kpi_row(alerts_df, traffic_df)
  st.divider()

  tab_alerts, tab_traffic = st.tabs(["Alerts", "Traffic"])

  with tab_alerts:
    filtered_alerts = sidebar_alert_filters(alerts_df)

    sort_option = st.selectbox(
        "Sort by",
        [
            "Most urgent first (severity)",
            "Newest first",
            "Oldest first",
            "Confidence (High to Low)",
        ],
        key="alert_sort_option",
    )
    if (
        sort_option == "Most urgent first (severity)"
        and not filtered_alerts.empty
    ):
      filtered_alerts = filtered_alerts.sort_values(
          "severity", ascending=True, na_position="last"
      )
    elif sort_option == "Newest first":
      filtered_alerts = filtered_alerts.sort_values(
          "timestamp", ascending=False
      )
    elif sort_option == "Oldest first":
      filtered_alerts = filtered_alerts.sort_values("timestamp", ascending=True)
    elif (
        sort_option == "Confidence (High to Low)" and not filtered_alerts.empty
    ):
      conf_rank = {"High": 0, "Medium": 1, "Low": 2}
      filtered_alerts = filtered_alerts.assign(
          _conf_rank=filtered_alerts["confidence"].map(conf_rank).fillna(3)
      ).sort_values("_conf_rank").drop(columns="_conf_rank")

    group_mode = st.checkbox(
        "Group similar alerts by Signature & Source IP",
        value=False,
        key="group_alerts_toggle",
    )

    if group_mode and not filtered_alerts.empty:
      st.subheader(
          f"Grouped Alert Summary ({len(filtered_alerts)} total events"
          " aggregated)"
      )

      grouped_df = filtered_alerts.groupby(
          ["signature", "signature_id", "severity", "src_ip"]
      ).agg(
          count=("id", "count"),
          first_seen=("timestamp", "min"),
          last_seen=("timestamp", "max"),
          sample_dest=("dest_ip", "first"),
      ).reset_index().sort_values(
          by="count", ascending=False
      )

      for _, group_row in grouped_df.iterrows():
        sev_label = {1: "High", 2: "Medium", 3: "Low"}.get(
            group_row["severity"], "Unknown"
        )
        chip_class = _sev_chip_class(sev_label)

        with st.expander(
            f"[{group_row['count']} events] {sev_label} |"
            f" {group_row['signature']} | Src: {group_row['src_ip']}"
        ):
          st.markdown(
              f'<span class="sev-chip {chip_class}">{sev_label}</span>'
              f' **Total Occurrences:** `{group_row["count"]}`',
              unsafe_allow_html=True,
          )
          st.write(
              f"**Signature ID (SID):** {group_row['signature_id']}  |"
              f" **Source IP:** {group_row['src_ip']}"
          )
          st.write(
              f"**First Seen:** {group_row['first_seen']}  | **Last Seen:**"
              f" {group_row['last_seen']}"
          )
          st.caption(
              "Tip: Uncheck the grouping toggle above if you need to triage or"
              " review individual raw events for this signature."
          )

    else:
      st.subheader(f"Live Alert Stream ({len(filtered_alerts)} matching)")

      if not filtered_alerts.empty:
        export_df = filtered_alerts.drop(
            columns=["raw", "raw_json"], errors="ignore"
        )
        st.download_button(
            "Download filtered alerts as CSV",
            export_df.to_csv(index=False).encode("utf-8"),
            "alerts_export.csv",
            "text/csv",
            key="alerts_csv_dl",
        )

        for _, row in filtered_alerts.head(100).iterrows():
          sev_label = {1: "High", 2: "Medium", 3: "Low"}.get(
              row["severity"], "Unknown"
          )
          chip_class = _sev_chip_class(sev_label)

          with st.expander(
              f"{sev_label} | {row['signature']} | {row['src_ip']} ->"
              f" {row['dest_ip']}"
          ):
            st.markdown(
                f'<span class="sev-chip {chip_class}">{sev_label}</span>',
                unsafe_allow_html=True,
            )

            local_ts = row["timestamp"].tz_convert(LOCAL_TZ).strftime(
                "%Y-%m-%d %I:%M:%S %p" if use_12hr else "%Y-%m-%d %H:%M:%S"
            )
            st.write(f"**Timestamp:** {local_ts}")
            st.write(
                f"**SID:** {row['signature_id']}  | **Category:**"
                f" {row.get('category', 'N/A')}"
            )

            detail_bits = []
            if row.get("confidence"):
              detail_bits.append(f"**Confidence:** {row['confidence']}")
            if row.get("attack_target"):
              detail_bits.append(f"**Target:** {row['attack_target']}")
            if detail_bits:
              st.write("  |  ".join(detail_bits))

            enrichment = rule_catalog.get(row["signature_id"])
            if enrichment:
              st.write(
                  f"**Full description ({enrichment.get('severity', 'N/A')}"
                  " severity):**"
              )
              st.write(
                  enrichment.get("description")
                  or "No description text available."
              )
              if enrichment.get("references"):
                st.write("**References:**", enrichment["references"])
            else:
              st.caption("No extended description available for this SID yet.")

            st.write("**Full raw event:**")
            st.json(row.get("raw", {}))

            btn_col1, btn_col2, btn_col3 = st.columns(3)
            with btn_col1:
              if row["status"] == "new":
                if st.button("Mark Reviewed", key=f"review_{row['id']}"):
                  alert_store.update_status(row["id"], "reviewed")
                  st.rerun()
            with btn_col2:
              if row["status"] == "new":
                if st.button("Mark False Positive", key=f"fp_{row['id']}"):
                  alert_store.update_status(row["id"], "false_positive")
                  st.rerun()
            with btn_col3:
              if row["status"] != "new":
                st.caption(f"Status: {row['status']}")
                if st.button("Reopen (mark as new)", key=f"reopen_{row['id']}"):
                  alert_store.update_status(row["id"], "new")
                  st.rerun()

    st.divider()
    st.subheader("Analytics & Trends")
    col_a, col_b = st.columns(2)
    with col_a:
      st.markdown("##### Alerts Over Time")
      alerts_over_time_chart(filtered_alerts)
    with col_b:
      st.markdown("##### Top Signatures")
      top_signatures_chart(filtered_alerts)

    st.markdown("##### Severity Breakdown")
    severity_breakdown_chart(filtered_alerts)

  with tab_traffic:
    filtered_traffic = sidebar_traffic_filters(traffic_df)
    st.subheader(f"Traffic Events ({len(filtered_traffic)} matching)")

    if not filtered_traffic.empty:
      base_cols = ["timestamp", "event_type", "src_ip", "dest_ip", "proto"]
      optional_cols = ["src_port", "dest_port", "app_proto"]

      display_cols = base_cols + [c for c in optional_cols if c in filtered_traffic.columns]

      stats_cols = [
          "uptime_sec",
          "packets_captured",
          "packets_dropped",
          "decoder_pkts",
          "decoder_bytes",
      ]
      display_cols += [c for c in stats_cols if c in filtered_traffic.columns]

      export_df = filtered_traffic[[c for c in display_cols if c in filtered_traffic.columns]].drop(
          columns=["raw"], errors="ignore"
      )
      st.download_button(
          "Download filtered traffic as CSV",
          export_df.to_csv(index=False).encode("utf-8"),
          "traffic_export.csv",
          "text/csv",
          key="traffic_csv_dl",
      )

      display_df = filtered_traffic.copy()
      display_df["timestamp"] = _format_local(display_df["timestamp"], use_12hr)

      st.dataframe(
          display_df[[c for c in display_cols if c in display_df.columns]].sort_values("timestamp", ascending=False),
          width="stretch",
          key="traffic_table",
      )


render_dashboard()