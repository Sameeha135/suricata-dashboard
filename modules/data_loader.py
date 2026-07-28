import os
import json
import pandas as pd
import streamlit as st
from modules import alert_store

EVE_JSON_PATH = "/var/log/suricata/eve.json"
MAX_TRAFFIC_EVENTS = 3000  # traffic stays session-only rolling window - alerts now persist in SQLite instead
OFFSET_CACHE_FILE = "eve_offset.txt"


def load_raw_events(path=EVE_JSON_PATH):
    """Reads new lines from eve.json. Alerts are written straight into the
    persistent SQLite store (survives browser reload / VM restart). Traffic
    events (flow/stats/dns/etc) go into a session-only rolling window since
    they're high-volume and not worth persisting forever."""

    if "eve_offset" not in st.session_state:
        if os.path.exists(OFFSET_CACHE_FILE):
            try:
                with open(OFFSET_CACHE_FILE, "r") as f:
                    st.session_state.eve_offset = int(f.read().strip())
            except (ValueError, FileNotFoundError):
                st.session_state.eve_offset = os.path.getsize(path)
        else:
            st.session_state.eve_offset = os.path.getsize(path)

    if "traffic_events" not in st.session_state:
        st.session_state.traffic_events = []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(st.session_state.eve_offset)
            new_lines = f.readlines()
            st.session_state.eve_offset = f.tell()
            with open(OFFSET_CACHE_FILE, "w") as f_off:
                f_off.write(str(st.session_state.eve_offset))
    except FileNotFoundError:
        return st.session_state.traffic_events
    except PermissionError:
        st.error(f"Permission denied reading {path}. Check user group permissions.")
        return st.session_state.traffic_events

    for line in new_lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") == "alert":
            alert_store.insert_alert(event)
        else:
            st.session_state.traffic_events.append(event)

    if len(st.session_state.traffic_events) > MAX_TRAFFIC_EVENTS:
        st.session_state.traffic_events = st.session_state.traffic_events[-MAX_TRAFFIC_EVENTS:]

    return st.session_state.traffic_events


def _safe_get(d, *keys, default=None):
    cur = d
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur


def get_traffic_df(events):
    rows = []
    for e in events:
        etype = e.get("event_type")
        if etype in (None, "alert"):
            continue

        row = {
            "timestamp": e.get("timestamp"),
            "event_type": etype,
            "src_ip": e.get("src_ip"),
            "src_port": e.get("src_port"),
            "dest_ip": e.get("dest_ip"),
            "dest_port": e.get("dest_port"),
            "proto": e.get("proto"),
            "app_proto": e.get("app_proto"),
            "in_iface": e.get("in_iface"),
            "flow_id": e.get("flow_id"),
            "direction": e.get("direction"),
            "bytes_toserver": _safe_get(e, "flow", "bytes_toserver"),
            "bytes_toclient": _safe_get(e, "flow", "bytes_toclient"),
            "raw": e,
        }

        if etype == "stats":
            stats = e.get("stats", {})
            row["uptime_sec"] = stats.get("uptime")
            row["packets_captured"] = _safe_get(stats, "capture", "kernel_packets")
            row["packets_dropped"] = _safe_get(stats, "capture", "kernel_drops")
            row["decoder_pkts"] = _safe_get(stats, "decoder", "pkts")
            row["decoder_bytes"] = _safe_get(stats, "decoder", "bytes")

        rows.append(row)

    df = pd.DataFrame(rows)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


@st.cache_data
def load_rule_catalog(path="suricata_et_rules.json"):
    try:
        with open(path, "r") as f:
            rules = json.load(f)
        return {r["sid"]: r for r in rules}
    except FileNotFoundError:
        return {}