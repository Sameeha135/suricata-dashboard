import json
import re
import sqlite3
import time
import threading
from contextlib import contextmanager
from zoneinfo import ZoneInfo
import pandas as pd
import streamlit as st

INGEST_LOCK = threading.Lock()
_LAST_GLOBAL_INGEST_TIME = 0.0

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
    /* Force standard arrow mouse pointer across all Plotly charts */
    div[data-testid="stPlotlyChart"],
    div[data-testid="stPlotlyChart"] .main-svg,
    div[data-testid="stPlotlyChart"] .draglayer,
    div[data-testid="stPlotlyChart"] .nsewdrag {
        cursor: default !important;
    }

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

    h1 a, h2 a, h3 a, h4 a, h5 a, h6 a,
    a.stAnchorLink,
    span[data-testid="stHeaderAnchor"] {
        display: none !important;
    }
    /* Hide Streamlit background execution toasts and spinners */
    div[data-testid="stStatusWidget"],
    div[data-testid="stNotification"],
    .stSpinner {
        display: none !important;
    }
</style>
""",

    unsafe_allow_html=True,
)

st.title("Suricata Monitoring Dashboard")

LOCAL_TZ = ZoneInfo("Asia/Karachi")
INGEST_INTERVAL_SECONDS = 2  # CHANGE 1: Reduced throttle from 15s to 2s


@st.cache_data(ttl=3600)
def get_cached_rule_catalog():
    return load_rule_catalog()


def get_single_rule_info(sid):
    if not sid:
        return None
    catalog = get_cached_rule_catalog()
    try:
        sid_key = str(int(sid))
    except (ValueError, TypeError):
        sid_key = str(sid)
    return catalog.get(sid_key)


# Compile regex patterns once globally at module startup
EMOJI_PATTERN = re.compile(
    r"[\U00010000-\U0010ffff]|[\u2600-\u27BF]|[\U0001f300-\U0001f9ff]|[🐾🚨🥱]",
    flags=re.UNICODE,
)
DASH_PATTERN = re.compile(r"\s*-\s*-\s*")
WHITESPACE_PATTERN = re.compile(r"\s+")


def sanitize_rule_text(text):
    if not text:
        return ""
    cleaned = EMOJI_PATTERN.sub("", str(text))
    cleaned = DASH_PATTERN.sub(" - ", cleaned)
    cleaned = WHITESPACE_PATTERN.sub(" ", cleaned)
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


def _paginate(df, state_key_prefix, default_rows=25):
    total = len(df)
    if total == 0:
        return df, 0, 1, 1

    col_a, col_b, col_c = st.columns([2, 2, 4])

    with col_a:
        page_size_choice = st.selectbox(
            "Rows per page",
            [25, 50, 100, 250, "All"],
            index=0,
            key=f"{state_key_prefix}_page_size",
        )

    if page_size_choice == "All":
        return df, total, 1, 1

    page_size = int(page_size_choice)
    total_pages = max(1, (total - 1) // page_size + 1)

    with col_b:
        current_page = st.number_input(
            "Page",
            min_value=1,
            max_value=total_pages,
            value=1,
            step=1,
            key=f"{state_key_prefix}_page_num",
        )
    current_page = min(max(1, int(current_page)), total_pages)

    with col_c:
        st.caption(f"Showing page {current_page} of {total_pages} ({total} total rows)")

    start = (current_page - 1) * page_size
    end = start + page_size
    return df.iloc[start:end], total, current_page, total_pages


def _background_ingest():
    """Runs ingestion in a background thread to prevent UI freezing."""
    try:
        ingest_logs()
    except Exception as e:
        print(f"[ERROR] Background ingestion failed: {e}")
    finally:
        if INGEST_LOCK.locked():
            INGEST_LOCK.release()


def _maybe_ingest():
    global _LAST_GLOBAL_INGEST_TIME
    now = time.time()

    # 1. Enforce global interval across all tabs/sessions
    if now - _LAST_GLOBAL_INGEST_TIME < INGEST_INTERVAL_SECONDS:
        return

    # 2. Acquire lock non-blockingly; if another thread is already ingesting, skip
    if INGEST_LOCK.acquire(blocking=False):
        _LAST_GLOBAL_INGEST_TIME = now
        threading.Thread(target=_background_ingest, daemon=True).start()


@contextmanager
def get_db_connection():
    """Context manager for SQLite connections with WAL mode enabled."""
    conn = sqlite3.connect("alerts.db", timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    try:
        yield conn
    finally:
        conn.close()


@st.cache_data(ttl=1, show_spinner=False)
def load_alerts_from_db(include_reviewed=False, fetch_limit=500):
    try:
        with get_db_connection() as conn:
            query = "SELECT * FROM alerts"
            if not include_reviewed:
                query += " WHERE status = 'new'"
            query += f" ORDER BY timestamp DESC LIMIT {fetch_limit}"
            df = pd.read_sql_query(query, conn)
    except Exception:
        df = pd.DataFrame()

    if not df.empty and "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def _get_parsed_raw(row):
    x = row.get("raw_json")
    if not x or (isinstance(x, float) and pd.isna(x)):
        return {}
    try:
        return json.loads(x)
    except (json.JSONDecodeError, TypeError):
        return {}


def _get_parsed_enrichment(row):
    x = row.get("enrichment_json")
    if not isinstance(x, str) or not x.strip():
        return None
    try:
        return json.loads(x)
    except json.JSONDecodeError:
        return None


@st.cache_data(ttl=5, show_spinner=False)
def load_traffic_from_db(fetch_limit=1000):
    try:
        with get_db_connection() as conn:
            df = pd.read_sql_query(
                f"SELECT * FROM traffic ORDER BY timestamp DESC LIMIT {fetch_limit}", conn
            )
    except Exception:
        df = pd.DataFrame()

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
    ts_obj = pd.to_datetime(ts)
    ts_obj = ts_obj.tz_localize("UTC") if ts_obj.tzinfo is None else ts_obj
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


def render_alerts_table_and_details(filtered_alerts, use_12hr):
    """Renders only the table and detail panel."""
    t_frag_start = time.perf_counter()

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

    if not filtered_alerts.empty:
        if sort_option == "Most urgent first (severity)":
            filtered_alerts = filtered_alerts.sort_values(
                "severity", ascending=True, na_position="last"
            )
        elif sort_option == "Newest first":
            filtered_alerts = filtered_alerts.sort_values(
                "timestamp", ascending=False
            )
        elif sort_option == "Oldest first":
            filtered_alerts = filtered_alerts.sort_values(
                "timestamp", ascending=True
            )
        elif sort_option == "Confidence (High to Low)":
            conf_rank = {"High": 0, "Medium": 1, "Low": 2}
            filtered_alerts = filtered_alerts.assign(
                _conf_rank=filtered_alerts["confidence"]
                .map(conf_rank)
                .fillna(3)
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
                ["signature", "signature_id", "severity", "src_ip"],
                dropna=False,
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

        grouped_page, _, _, _ = _paginate(
            grouped_df, "grouped_alerts", default_rows=25
        )

        for _, group_row in grouped_page.iterrows():
            sev_label = {1: "High", 2: "Medium", 3: "Low"}.get(
                group_row["severity"], "Unknown"
            )
            chip_class = _sev_chip_class(sev_label)
            clean_sig = sanitize_rule_text(group_row["signature"])

            first_seen_str = _format_single_ts(
                group_row["first_seen"], use_12hr
            )
            last_seen_str = _format_single_ts(group_row["last_seen"], use_12hr)

            with st.expander(
                f"[{group_row['count']} events] {sev_label} | {clean_sig} | Src: {group_row['src_ip']}"
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
        st.subheader(
            f"Live Alert Stream ({len(filtered_alerts)} loaded in view)"
        )

        if not filtered_alerts.empty:
            export_df = filtered_alerts.drop(
                columns=["raw_json", "enrichment_json"], errors="ignore"
            )
            st.download_button(
                "Download filtered alerts as CSV",
                export_df.to_csv(index=False).encode("utf-8"),
                "alerts_export.csv",
                "text/csv",
                key="alerts_csv_dl",
            )

            st.caption(
                "Click on any alert row below to open its full details, rule descriptions, raw JSON, and review actions."
            )

            page_df, total_rows, current_page, total_pages = _paginate(
                filtered_alerts, "alerts_table", default_rows=25
            )

            if not page_df.empty:
                display_df = pd.DataFrame()
                display_df["id"] = page_df["id"]
                display_df["SID"] = page_df["signature_id"]
                display_df["Formatted_Time"] = _format_local(
                    page_df["timestamp"], use_12hr
                )
                display_df["Severity"] = (
                    page_df["severity"]
                    .map({1: "High", 2: "Medium", 3: "Low"})
                    .fillna("Unknown")
                )
                display_df["signature"] = page_df["signature"].apply(
                    sanitize_rule_text
                )
                display_df["src_ip"] = page_df["src_ip"]
                display_df["dest_ip"] = page_df["dest_ip"]
                display_df["status"] = page_df["status"]

                view_df = display_df.drop(columns=["id"])

                event = st.dataframe(
                    view_df,
                    width="stretch",
                    key="alerts_table_view",
                    selection_mode="single-row",
                    on_select="rerun",
                    hide_index=True,
                )

                selected_rows = event.selection.get("rows", [])
                if selected_rows:
                    selected_page_row = display_df.iloc[selected_rows[0]]
                    selected_id = selected_page_row["id"]
                    matching = filtered_alerts[
                        filtered_alerts["id"] == selected_id
                    ]
                    row = (
                        matching.iloc[0]
                        if not matching.empty
                        else page_df.iloc[selected_rows[0]]
                    )

                    st.markdown("---")
                    st.subheader(
                        f"Detailed View for Alert ID: {row.get('id', 'N/A')}"
                    )

                    sev_label = {1: "High", 2: "Medium", 3: "Low"}.get(
                        row["severity"], "Unknown"
                    )
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
                        detail_bits.append(
                            f"**Confidence:** {row['confidence']}"
                        )
                    if not _is_blank(row.get("attack_target")):
                        detail_bits.append(f"**Target:** {row['attack_target']}")
                    if detail_bits:
                        st.write("  |  ".join(detail_bits))

                    enrichment = _get_parsed_enrichment(
                        row
                    ) or get_single_rule_info(row["signature_id"])

                    has_any_value = enrichment and any(
                        not _is_blank(v) for v in enrichment.values()
                    )

                    if has_any_value:
                        st.markdown("#### Rule Catalog Information")

                        msg_val = enrichment.get("msg")
                        if not _is_blank(msg_val):
                            st.write(
                                f"**Rule Message (`msg`):** {sanitize_rule_text(msg_val)}"
                            )

                        col1, col2, col3 = st.columns(3)

                        _write_if_present(
                            col1,
                            "Action",
                            enrichment.get("action"),
                            code_format=True,
                        )
                        _write_if_present(
                            col1,
                            "Classtype",
                            enrichment.get("classtype"),
                            code_format=True,
                        )
                        _write_if_present(
                            col1,
                            "Protocol",
                            enrichment.get("protocol"),
                            code_format=True,
                        )
                        _write_if_present(
                            col1,
                            "Revision (`rev`)",
                            enrichment.get("rev"),
                            code_format=True,
                        )

                        _write_if_present(
                            col2,
                            "Source Net",
                            enrichment.get("src_net"),
                            code_format=True,
                        )
                        _write_if_present(
                            col2,
                            "Source Port",
                            enrichment.get("src_port"),
                            code_format=True,
                        )
                        _write_if_present(
                            col2,
                            "Direction",
                            enrichment.get("direction"),
                            code_format=True,
                        )
                        _write_if_present(
                            col2,
                            "Dest Net",
                            enrichment.get("dst_net"),
                            code_format=True,
                        )
                        _write_if_present(
                            col2,
                            "Dest Port",
                            enrichment.get("dst_port"),
                            code_format=True,
                        )

                        _write_if_present(
                            col3,
                            "Ruleset",
                            enrichment.get("ruleset"),
                            code_format=True,
                        )
                        _write_if_present(
                            col3,
                            "Vendor",
                            enrichment.get("vendor"),
                            code_format=True,
                        )
                    else:
                        st.caption(
                            "No extended description available for this SID yet."
                        )

                    st.write("**Full raw event:**")
                    st.json(_get_parsed_raw(row), expanded=False)

                    btn_col1, btn_col2, btn_col3 = st.columns(3)
                    with btn_col1:
                        if row["status"] == "new":
                            if st.button(
                                "Mark Reviewed", key=f"table_review_{row['id']}"
                            ):
                                alert_store.update_status(row["id"], "reviewed")
                                st.rerun()
                    with btn_col2:
                        if row["status"] == "new":
                            if st.button(
                                "Mark False Positive",
                                key=f"table_fp_{row['id']}",
                            ):
                                alert_store.update_status(
                                    row["id"], "false_positive"
                                )
                                st.rerun()
                    with btn_col3:
                        if row["status"] != "new":
                            st.caption(f"Status: {row['status']}")
                            if st.button(
                                "Reopen (mark as new)",
                                key=f"table_reopen_{row['id']}",
                            ):
                                alert_store.update_status(row["id"], "new")
                                st.rerun()

    t_frag_total = time.perf_counter() - t_frag_start
    print(f"[TIMING] table_and_details_render={t_frag_total:.2f}s")


@st.fragment(run_every="2s")
def render_live_alerts_section(include_reviewed, fetch_limit, use_12hr):
    _maybe_ingest()
    alerts_df = load_alerts_from_db(include_reviewed=include_reviewed, fetch_limit=fetch_limit)
    filtered_alerts = sidebar_alert_filters(alerts_df, key_prefix="alerts_tab")
    render_alerts_table_and_details(filtered_alerts, use_12hr)


@st.fragment(run_every="15s")
def render_alerts_analytics(include_reviewed, fetch_limit):
    """Fetches, filters, and renders analytical charts on a 15-second tick."""
    alerts_df = load_alerts_from_db(include_reviewed=include_reviewed, fetch_limit=fetch_limit)
    filtered_alerts = sidebar_alert_filters(alerts_df, key_prefix="analytics_tab")
    
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


def render_alerts_tab(include_reviewed, fetch_limit, use_12hr):
    # 1. Live table fragment (Auto-refreshes every 2s)
    render_live_alerts_section(include_reviewed, fetch_limit, use_12hr)

    # 2. Analytics fragment (Auto-refreshes every 15s)
    render_alerts_analytics(include_reviewed, fetch_limit)


def render_dashboard():
    t_start = time.perf_counter()

    # CHANGE 4: Removed _maybe_ingest() call here so full page refreshes stay instant

    use_12hr = st.sidebar.checkbox(
        "Use 12-hour clock (AM/PM)", value=False, key="use_12hr_toggle"
    )
    show_reviewed = st.sidebar.checkbox(
        "Show reviewed / false-positive alerts",
        value=False,
        key="show_reviewed_toggle",
    )
    fetch_limit = st.sidebar.select_slider(
        "Max DB Fetch Limit",
        options=[250, 500, 1000, 2000],
        value=500,
        key="db_fetch_limit",
        help="Lower limits increase dashboard speed.",
    )
    st.sidebar.divider()

    t0 = time.perf_counter()
    alerts_df = load_alerts_from_db(include_reviewed=show_reviewed, fetch_limit=fetch_limit)
    t_alerts_load = time.perf_counter() - t0

    t0 = time.perf_counter()
    traffic_df = load_traffic_from_db(fetch_limit=fetch_limit)
    t_traffic_load = time.perf_counter() - t0

    kpi_row(alerts_df, traffic_df)
    st.divider()

    selected_tab = st.radio(
        "Navigation View",
        ["Alerts", "Traffic"],
        horizontal=True,
        label_visibility="collapsed",
        key="main_nav_radio",
    )

    if selected_tab == "Alerts":
        render_alerts_tab(show_reviewed, fetch_limit, use_12hr)

    elif selected_tab == "Traffic":
        filtered_traffic = sidebar_traffic_filters(traffic_df)

        st.subheader(f"Traffic Events ({len(filtered_traffic)} loaded in view)")

        if not filtered_traffic.empty:
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
                + [c for c in optional_cols if c in filtered_traffic.columns]
                + [c for c in stats_cols if c in filtered_traffic.columns]
            )

            export_df = filtered_traffic[
                [c for c in display_cols if c in filtered_traffic.columns]
            ].drop(columns=["raw"], errors="ignore")

            st.download_button(
                "Download filtered traffic as CSV",
                export_df.to_csv(index=False).encode("utf-8"),
                "traffic_export.csv",
                "text/csv",
                key="traffic_csv_dl",
            )

            page_df, total_rows, current_page, total_pages = _paginate(
                filtered_traffic, "traffic_table", default_rows=25
            )

            if not page_df.empty:
                page_display = page_df[[c for c in display_cols if c in page_df.columns]].copy()
                page_display["timestamp"] = _format_local(page_display["timestamp"], use_12hr)
                page_display = page_display.sort_values("timestamp", ascending=False)

                st.dataframe(
                    page_display,
                    width="stretch",
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

    t_total = time.perf_counter() - t_start
    print(
        f"[TIMING] "
        f"alerts_load={t_alerts_load:.2f}s traffic_load={t_traffic_load:.2f}s "
        f"TOTAL={t_total:.2f}s"
    )


render_dashboard()