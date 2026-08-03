import json
import re
import sqlite3
import time
from zoneinfo import ZoneInfo
import pandas as pd
import streamlit as st

from modules import alert_store
from modules.charts import (
    alerts_over_time_chart,
    kpi_row,
    protocol_distribution_chart,
    severity_breakdown_chart,
    top_signatures_chart,
    top_talkers_chart,
    traffic_over_time_chart,
)
from modules.data_loader import load_rule_catalog
from modules.filters import sidebar_alert_filters, sidebar_traffic_filters
from modules.ingestor import ingest_logs

st.set_page_config(page_title="Suricata Monitor", layout="wide")

st.markdown(
    """
<style>
    /* Broadened from just stFragment - stDataFrame, stVerticalBlock, and
       stElementContainer all get their own fade/dim treatment during
       fragment reruns, which the narrower selector wasn't catching. */
    div[data-testid="stFragment"],
    div[data-testid="stDataFrame"],
    div[data-testid="stVerticalBlock"],
    div[data-testid="stElementContainer"] {
        opacity: 1 !important;
        transition: none !important;
    }
    div[data-testid="stMetric"] {
        background: linear-gradient(135deg, rgba(80,140,220,0.1) 0%, rgba(255,255,255,0.03) 100%);
        border: 1px solid rgba(80,140,220,0.3);
        border-radius: 12px;
        padding: 16px 20px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
    }
    div[data-testid="stMetric"] label {
        font-size: 0.9rem !important;
        color: #90b4ff !important;
        font-weight: 600;
    }
    div[data-testid="stMetric"] [data-testid="stMetricValue"] {
        font-size: 2rem !important;
        font-weight: 700;
    }
    div[data-testid="stExpander"] {
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 8px;
        background-color: rgba(255,255,255,0.01);
        margin-bottom: 6px;
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

    div[role="radiogroup"] {
        gap: 4px;
    }
    div[role="radiogroup"] label {
        background-color: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 8px 8px 0 0;
        padding: 8px 20px;
        margin-bottom: 0px;
    }
    div[role="radiogroup"] label:has(input:checked) {
        background-color: rgba(80,140,220,0.15);
        border-bottom: 2px solid #7fb2ff;
    }

    h1 a, h2 a, h3 a, h4 a, h5 a, h6 a,
    a.stAnchorLink,
    span[data-testid="stHeaderAnchor"] {
        display: none !important;
    }
</style>
""",
    unsafe_allow_html=True,
)

st.title("Suricata Monitoring Dashboard")

LOCAL_TZ = ZoneInfo("Asia/Karachi")
INGEST_INTERVAL_SECONDS = 15


@st.cache_data(ttl=300)
def get_cached_rule_catalog():
    return load_rule_catalog()


def sanitize_rule_text(text):
    if not text:
        return ""
    emoji_pattern = re.compile(
        r"[\U00010000-\U0010ffff]"
        r"|[\u2600-\u27BF]"
        r"|[\U0001f300-\U0001f9ff]"
        r"|[🐾🚨🥱]",
        flags=re.UNICODE,
    )
    cleaned = emoji_pattern.sub("", text)
    cleaned = re.sub(r"\s*-\s*-\s*", " - ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip(" -")


def sanitize_json_data(data):
    if isinstance(data, str):
        return sanitize_rule_text(data)
    elif isinstance(data, dict):
        return {k: sanitize_json_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_json_data(item) for item in data]
    return data


def _is_blank(value):
    if value is None:
        return True
    if isinstance(value, float) and pd.isna(value):
        return True
    if isinstance(value, str) and value.strip().lower() in ("", "null", "none", "n/a"):
        return True
    return False


def _write_if_present(container, label, value, code_format=False):
    if _is_blank(value):
        return
    if code_format:
        container.write(f"**{label}:** `{value}`")
    else:
        container.write(f"**{label}:** {value}")


def _maybe_ingest():
    now = time.time()
    last = st.session_state.get("_last_ingest_time", 0)
    if now - last >= INGEST_INTERVAL_SECONDS:
        try:
            ingest_logs()
        except Exception as e:
            st.error(f"Ingestion error: {e}")
        st.session_state["_last_ingest_time"] = now


@st.cache_data(ttl=5)
def load_alerts_from_db(include_reviewed=False):
    conn = sqlite3.connect("alerts.db")
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        query = "SELECT * FROM alerts"
        if not include_reviewed:
            query += " WHERE status = 'new'"
        query += " ORDER BY timestamp DESC"
        df = pd.read_sql_query(query, conn)
    finally:
        conn.close()

    if not df.empty:
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        if "raw_json" in df.columns:
            df["raw"] = df["raw_json"].apply(
                lambda x: sanitize_json_data(json.loads(x)) if x else {}
            )
        if "enrichment_json" in df.columns:
            df["enrichment"] = df["enrichment_json"].apply(
                lambda x: json.loads(x) if isinstance(x, str) and x.strip() else None
            )
    return df


@st.cache_data(ttl=5)
def load_traffic_from_db():
    conn = sqlite3.connect("alerts.db")
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        df = pd.read_sql_query(
            "SELECT * FROM traffic ORDER BY timestamp DESC LIMIT 2000", conn
        )
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()

    if not df.empty and "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def _format_local(ts_series, use_12hr):
    if ts_series.empty:
        return ts_series
    if ts_series.dt.tz is None:
        local = ts_series.dt.tz_localize("UTC").dt.tz_convert(LOCAL_TZ)
    else:
        local = ts_series.dt.tz_convert(LOCAL_TZ)
    fmt = "%Y-%m-%d %I:%M:%S %p" if use_12hr else "%Y-%m-%d %H:%M:%S"
    return local.dt.strftime(fmt)


def _format_single_ts(ts, use_12hr):
    if pd.isna(ts):
        return "N/A"
    ts_obj = ts.tz_localize("UTC") if ts.tzinfo is None else ts
    local_ts = ts_obj.tz_convert(LOCAL_TZ)
    fmt = "%Y-%m-%d %I:%M:%S %p" if use_12hr else "%Y-%m-%d %H:%M:%S"
    return local_ts.strftime(fmt)


def _sev_chip_class(sev_label):
    label = str(sev_label or "").lower()
    if "high" in label or "1" in label:
        return "sev-high"
    elif "medium" in label or "2" in label:
        return "sev-medium"
    else:
        return "sev-low"


@st.fragment(run_every=30)
def render_dashboard():
    _maybe_ingest()
    rule_catalog = get_cached_rule_catalog()

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

    active_tab = st.radio(
        "View",
        ["Alerts", "Traffic"],
        horizontal=True,
        key="active_tab_selector",
        label_visibility="collapsed",
    )

    if active_tab == "Alerts":
        filtered_alerts = sidebar_alert_filters(alerts_df)

        if not filtered_alerts.empty and "signature" in filtered_alerts.columns:
            filtered_alerts["signature"] = filtered_alerts["signature"].apply(
                sanitize_rule_text
            )

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
        if sort_option == "Most urgent first (severity)" and not filtered_alerts.empty:
            filtered_alerts = filtered_alerts.sort_values(
                "severity", ascending=True, na_position="last"
            )
        elif sort_option == "Newest first":
            filtered_alerts = filtered_alerts.sort_values("timestamp", ascending=False)
        elif sort_option == "Oldest first":
            filtered_alerts = filtered_alerts.sort_values("timestamp", ascending=True)
        elif sort_option == "Confidence (High to Low)" and not filtered_alerts.empty:
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
                f"Grouped Alert Summary ({len(filtered_alerts)} total events aggregated)"
            )

            grouped_df = (
                filtered_alerts.groupby(
                    ["signature", "signature_id", "severity", "src_ip"]
                )
                .agg(
                    count=("id", "count"),
                    first_seen=("timestamp", "min"),
                    last_seen=("timestamp", "max"),
                    sample_dest=("dest_ip", "first"),
                )
                .reset_index()
                .sort_values(by="count", ascending=False)
            )

            for _, group_row in grouped_df.iterrows():
                sev_label = {1: "High", 2: "Medium", 3: "Low"}.get(
                    group_row["severity"], "Unknown"
                )
                chip_class = _sev_chip_class(sev_label)

                first_seen_str = _format_single_ts(group_row["first_seen"], use_12hr)
                last_seen_str = _format_single_ts(group_row["last_seen"], use_12hr)

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
                        f"**First Seen:** {first_seen_str}  | **Last Seen:** {last_seen_str}"
                    )

        else:
            st.subheader(f"Live Alert Stream ({len(filtered_alerts)} matching)")

            if not filtered_alerts.empty:
                export_df = filtered_alerts.drop(
                    columns=["raw", "raw_json", "enrichment", "enrichment_json"],
                    errors="ignore",
                )
                st.download_button(
                    "Download filtered alerts as CSV",
                    export_df.to_csv(index=False).encode("utf-8"),
                    "alerts_export.csv",
                    "text/csv",
                    key="alerts_csv_dl",
                )

                st.caption(
                    "Click on any alert row below to open its full details,"
                    " rule descriptions, raw JSON, and review actions."
                )

                table_df = filtered_alerts.copy()
                table_df["Formatted_Time"] = _format_local(table_df["timestamp"], use_12hr)
                table_df["Severity"] = (
                    table_df["severity"].map({1: "High", 2: "Medium", 3: "Low"}).fillna("Unknown")
                )
                table_df["SID"] = table_df["signature_id"]

                display_columns = [
                    "SID", "Formatted_Time", "Severity", "signature", "src_ip", "dest_ip", "status",
                ]
                available_cols = [c for c in display_columns if c in table_df.columns]

                event = st.dataframe(
                    table_df[available_cols],
                    use_container_width=True,
                    key="alerts_table_view",
                    selection_mode="single-row",
                    on_select="rerun",
                    hide_index=True,
                )

                selected_rows = event.selection.get("rows", [])
                if selected_rows:
                    selected_idx = selected_rows[0]
                    row = filtered_alerts.iloc[selected_idx]

                    st.markdown("---")
                    st.subheader(f"Detailed View for Alert ID: {row.get('id', 'N/A')}")

                    sev_label = {1: "High", 2: "Medium", 3: "Low"}.get(row["severity"], "Unknown")
                    chip_class = _sev_chip_class(sev_label)
                    st.markdown(
                        f'<span class="sev-chip {chip_class}">{sev_label}</span>',
                        unsafe_allow_html=True,
                    )

                    local_ts = _format_single_ts(row["timestamp"], use_12hr)
                    st.write(f"**Timestamp:** {local_ts}")

                    sid_line = f"**SID:** {row['signature_id']}"
                    if not _is_blank(row.get("category")):
                        sid_line += f"  | **Category:** {row['category']}"
                    st.write(sid_line)

                    detail_bits = []
                    if not _is_blank(row.get("confidence")):
                        detail_bits.append(f"**Confidence:** {row['confidence']}")
                    if not _is_blank(row.get("attack_target")):
                        detail_bits.append(f"**Target:** {row['attack_target']}")
                    if detail_bits:
                        st.write("  |  ".join(detail_bits))

                    enrichment = row.get("enrichment")
                    if not enrichment:
                        try:
                            sid_key = str(int(row["signature_id"]))
                        except (ValueError, TypeError):
                            sid_key = str(row["signature_id"])
                        enrichment = rule_catalog.get(sid_key)

                    has_any_value = enrichment and any(
                        not _is_blank(v) for v in enrichment.values()
                    )

                    if has_any_value:
                        st.markdown("#### Rule Catalog Information")

                        msg_val = enrichment.get("msg")
                        if not _is_blank(msg_val):
                            st.write(f"**Rule Message (`msg`):** {sanitize_rule_text(msg_val)}")

                        col1, col2, col3 = st.columns(3)

                        _write_if_present(col1, "Action", enrichment.get("action"), code_format=True)
                        _write_if_present(col1, "Classtype", enrichment.get("classtype"), code_format=True)
                        _write_if_present(col1, "Protocol", enrichment.get("protocol"), code_format=True)
                        _write_if_present(col1, "Revision (`rev`)", enrichment.get("rev"), code_format=True)

                        _write_if_present(col2, "Source Net", enrichment.get("src_net"), code_format=True)
                        _write_if_present(col2, "Source Port", enrichment.get("src_port"), code_format=True)
                        _write_if_present(col2, "Direction", enrichment.get("direction"), code_format=True)
                        _write_if_present(col2, "Dest Net", enrichment.get("dst_net"), code_format=True)
                        _write_if_present(col2, "Dest Port", enrichment.get("dst_port"), code_format=True)

                        _write_if_present(col3, "Ruleset", enrichment.get("ruleset"), code_format=True)
                        _write_if_present(col3, "Vendor", enrichment.get("vendor"), code_format=True)
                    else:
                        st.caption("No extended description available for this SID yet.")

                    st.write("**Full raw event:**")
                    st.json(row.get("raw", {}))

                    btn_col1, btn_col2, btn_col3 = st.columns(3)
                    with btn_col1:
                        if row["status"] == "new":
                            if st.button("Mark Reviewed", key=f"table_review_{row['id']}"):
                                alert_store.update_status(row["id"], "reviewed")
                                st.rerun()
                    with btn_col2:
                        if row["status"] == "new":
                            if st.button("Mark False Positive", key=f"table_fp_{row['id']}"):
                                alert_store.update_status(row["id"], "false_positive")
                                st.rerun()
                    with btn_col3:
                        if row["status"] != "new":
                            st.caption(f"Status: {row['status']}")
                            if st.button("Reopen (mark as new)", key=f"table_reopen_{row['id']}"):
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

    else:
        filtered_traffic = sidebar_traffic_filters(traffic_df)

        st.subheader(f"Traffic Events ({len(filtered_traffic)} matching)")

        if not filtered_traffic.empty:
            display_df = filtered_traffic.copy()

            base_cols = [
                "timestamp", "event_type", "src_ip", "src_port",
                "dest_ip", "dest_port", "proto", "app_proto",
            ]
            optional_cols = [
                "flow_id", "in_iface", "bytes_toclient", "bytes_toserver",
                "pkts_toclient", "pkts_toserver",
            ]
            stats_cols = [
                "uptime_sec", "packets_captured", "packets_dropped",
                "decoder_pkts", "decoder_bytes",
            ]

            display_cols = (
                base_cols
                + [c for c in optional_cols if c in display_df.columns]
                + [c for c in stats_cols if c in display_df.columns]
            )

            export_df = display_df[
                [c for c in display_cols if c in display_df.columns]
            ].drop(columns=["raw"], errors="ignore")

            st.download_button(
                "Download filtered traffic as CSV",
                export_df.to_csv(index=False).encode("utf-8"),
                "traffic_export.csv",
                "text/csv",
                key="traffic_csv_dl",
            )

            display_df["timestamp"] = _format_local(display_df["timestamp"], use_12hr)

            st.dataframe(
                display_df[[c for c in display_cols if c in display_df.columns]].sort_values(
                    "timestamp", ascending=False
                ),
                use_container_width=True,
                key="traffic_table",
                hide_index=True,
            )

        st.divider()
        st.subheader("Traffic Analytics")
        col_t1, col_t2 = st.columns(2)
        with col_t1:
            st.markdown("##### Traffic Over Time")
            traffic_over_time_chart(filtered_traffic)
        with col_t2:
            st.markdown("##### Top Talkers (Source IP)")
            top_talkers_chart(filtered_traffic)

        st.markdown("##### Protocol Distribution")
        protocol_distribution_chart(filtered_traffic)


render_dashboard()