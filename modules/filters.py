import streamlit as st
import re


def _synced_multiselect(label, options, key, container=st, **kwargs):
    # 1. Sanitize/filter session state BEFORE instantiating the widget
    if key in st.session_state and st.session_state[key]:
        st.session_state[key] = [v for v in st.session_state[key] if v in options]

    # 2. Instantiate the widget AFTER modifying session_state
    return container.multiselect(label, options, key=key, **kwargs)


def _parse_int_range(text):
    text = (text or "").strip()
    if not text:
        return None
    try:
        if "-" in text:
            lo, hi = text.split("-", 1)
            lo, hi = int(lo.strip()), int(hi.strip())
            return ("range", min(lo, hi), max(lo, hi))
        return ("set", {int(p.strip()) for p in text.split(",") if p.strip()})
    except ValueError:
        return None


def _apply_int_filter(df, column, parsed):
    if parsed is None:
        return df
    kind = parsed[0]
    if kind == "range":
        _, lo, hi = parsed
        return df[(df[column] >= lo) & (df[column] <= hi)]
    else:
        _, values = parsed
        return df[df[column].isin(values)]


def _text_filter_with_regex(container, label, key_prefix):
    col1, col2 = container.columns([3, 1])
    with col1:
        text = st.text_input(label, "", key=f"{key_prefix}_text")
    with col2:
        use_regex = st.checkbox("Regex", value=False, key=f"{key_prefix}_regex")
    return text, use_regex


def _apply_text_filter(df, column, text, use_regex):
    if not text:
        return df
    if use_regex:
        try:
            re.compile(text)
        except re.error as e:
            st.sidebar.warning(f"Invalid regex for '{column}': {e}. Filter not applied.")
            return df
        return df[df[column].astype(str).str.contains(text, regex=True, na=False)]
    return df[df[column].astype(str).str.contains(text, case=False, regex=False, na=False)]


def sidebar_alert_filters(df, key_prefix="alert"):
    st.sidebar.subheader("Alert Filters")
    st.sidebar.caption("Leave any filter empty/blank to include everything for that field.")

    if df.empty:
        st.sidebar.info("No alert events loaded yet.")
        return df

    p = key_prefix

    with st.sidebar.expander("Severity / Confidence / Target", expanded=True):
        severities = sorted(df["severity"].dropna().unique().tolist())
        selected_sev = _synced_multiselect("Severity (numeric)", severities, f"{p}_sev_filter", container=st)

        sig_severities = sorted(df["signature_severity"].dropna().unique().tolist()) if "signature_severity" in df else []
        selected_sig_sev = _synced_multiselect("Signature Severity", sig_severities, f"{p}_sigsev_filter", container=st)

        standard_confidences = ["High", "Medium", "Low"]
        existing_confidences = df["confidence"].dropna().unique().tolist() if "confidence" in df else []
        confidences = sorted(list(set(standard_confidences + existing_confidences)))
        selected_confidence = _synced_multiselect("Confidence", confidences, f"{p}_conf_filter", container=st)

        targets = sorted(df["attack_target"].dropna().unique().tolist()) if "attack_target" in df else []
        selected_target = _synced_multiselect("Attack Target", targets, f"{p}_target_filter", container=st)

    with st.sidebar.expander("Protocol / Category / Signature", expanded=False):
        protocols = sorted(df["proto"].dropna().unique().tolist())
        selected_proto = _synced_multiselect("Protocol", protocols, f"{p}_proto_filter", container=st)

        categories = sorted(df["category"].dropna().unique().tolist()) if "category" in df else []
        selected_categories = _synced_multiselect("Category", categories, f"{p}_cat_filter", container=st)

        sid_search = st.text_input("Signature ID (exact or partial)", "", key=f"{p}_sid_search")
        sig_search, sig_regex = _text_filter_with_regex(st, "Signature message contains", f"{p}_sig")

    with st.sidebar.expander("IPs / Ports", expanded=False):
        src_ip_filter, src_ip_regex = _text_filter_with_regex(st, "Source IP", f"{p}_src_ip")
        dst_ip_filter, dst_ip_regex = _text_filter_with_regex(st, "Dest IP", f"{p}_dst_ip")

        col3, col4 = st.columns(2)
        with col3:
            src_port_filter = st.text_input("Source Port (e.g. 80 or 1000-2000)", "", key=f"{p}_src_port")
        with col4:
            dst_port_filter = st.text_input("Dest Port (e.g. 443 or 1-1024)", "", key=f"{p}_dst_port")

    with st.sidebar.expander("Interface / Flow / Direction", expanded=False):
        interfaces = sorted(df["in_iface"].dropna().unique().tolist()) if "in_iface" in df else []
        selected_iface = _synced_multiselect("Interface", interfaces, f"{p}_iface_filter", container=st)

        directions = sorted(df["direction"].dropna().unique().tolist()) if "direction" in df else []
        selected_direction = _synced_multiselect("Direction", directions, f"{p}_direction_filter", container=st)

        flow_id_search = st.text_input("Flow ID (exact)", "", key=f"{p}_flow_id_search")

        col5, col6 = st.columns(2)
        with col5:
            bytes_toserver_filter = st.text_input("Bytes to server (e.g. 1000-50000)", "", key=f"{p}_bytes_toserver")
        with col6:
            bytes_toclient_filter = st.text_input("Bytes to client (e.g. 1000-50000)", "", key=f"{p}_bytes_toclient")

    time_range = None
    if df["timestamp"].notna().any():
        min_t, max_t = df["timestamp"].min(), df["timestamp"].max()
        if min_t != max_t:
            with st.sidebar.expander("Time Range", expanded=False):
                time_range = st.slider(
                    "Show alerts between",
                    min_value=min_t.to_pydatetime(),
                    max_value=max_t.to_pydatetime(),
                    value=(min_t.to_pydatetime(), max_t.to_pydatetime()),
                    key=f"{p}_time_slider"
                )

    filtered = df.copy()
    if selected_sev:
        filtered = filtered[filtered["severity"].isin(selected_sev)]
    if selected_sig_sev and "signature_severity" in filtered:
        filtered = filtered[filtered["signature_severity"].isin(selected_sig_sev)]
    if selected_confidence and "confidence" in filtered:
        filtered = filtered[filtered["confidence"].isin(selected_confidence)]
    if selected_target and "attack_target" in filtered:
        filtered = filtered[filtered["attack_target"].isin(selected_target)]
    if selected_proto:
        filtered = filtered[filtered["proto"].isin(selected_proto)]
    if selected_categories and "category" in filtered:
        filtered = filtered[filtered["category"].isin(selected_categories)]
    if sid_search:
        filtered = filtered[filtered["signature_id"].astype(str).str.contains(sid_search, na=False)]

    filtered = _apply_text_filter(filtered, "signature", sig_search, sig_regex)
    filtered = _apply_text_filter(filtered, "src_ip", src_ip_filter, src_ip_regex)
    filtered = _apply_text_filter(filtered, "dest_ip", dst_ip_filter, dst_ip_regex)

    if selected_iface and "in_iface" in filtered:
        filtered = filtered[filtered["in_iface"].isin(selected_iface)]
    if selected_direction and "direction" in filtered:
        filtered = filtered[filtered["direction"].isin(selected_direction)]
    if flow_id_search and "flow_id" in filtered:
        filtered = filtered[filtered["flow_id"].astype(str).str.contains(flow_id_search, na=False)]

    filtered = _apply_int_filter(filtered, "src_port", _parse_int_range(src_port_filter))
    filtered = _apply_int_filter(filtered, "dest_port", _parse_int_range(dst_port_filter))
    if "bytes_toserver" in filtered:
        filtered = _apply_int_filter(filtered, "bytes_toserver", _parse_int_range(bytes_toserver_filter))
    if "bytes_toclient" in filtered:
        filtered = _apply_int_filter(filtered, "bytes_toclient", _parse_int_range(bytes_toclient_filter))

    if time_range:
        filtered = filtered[(filtered["timestamp"] >= time_range[0]) & (filtered["timestamp"] <= time_range[1])]

    return filtered


def sidebar_traffic_filters(df, key_prefix="traffic"):
    st.sidebar.subheader("Traffic Filters")
    st.sidebar.caption("Leave any filter empty/blank to include everything for that field.")

    if df.empty:
        st.sidebar.info("No traffic events loaded yet.")
        return df

    p = key_prefix

    with st.sidebar.expander("Event Type / Protocol", expanded=True):
        event_types = sorted(df["event_type"].dropna().unique().tolist())
        selected_types = _synced_multiselect("Event type", event_types, f"{p}_type_filter", container=st)

        protocols = sorted(df["proto"].dropna().unique().tolist())
        selected_proto = _synced_multiselect("Protocol", protocols, f"{p}_proto_filter", container=st)

        app_protos = sorted(df["app_proto"].dropna().unique().tolist()) if "app_proto" in df else []
        selected_app_proto = _synced_multiselect("App Protocol", app_protos, f"{p}_app_proto_filter", container=st)

    with st.sidebar.expander("IPs / Ports", expanded=False):
        src_ip_filter, src_ip_regex = _text_filter_with_regex(st, "Source IP", f"{p}_src_ip")
        dst_ip_filter, dst_ip_regex = _text_filter_with_regex(st, "Dest IP", f"{p}_dst_ip")

        col3, col4 = st.columns(2)
        with col3:
            src_port_filter = st.text_input("Source Port", "", key=f"{p}_src_port")
        with col4:
            dst_port_filter = st.text_input("Dest Port", "", key=f"{p}_dst_port")

    with st.sidebar.expander("Interface / Flow / Direction", expanded=False):
        interfaces = sorted(df["in_iface"].dropna().unique().tolist()) if "in_iface" in df else []
        selected_iface = _synced_multiselect("Interface", interfaces, f"{p}_iface_filter", container=st)

        directions = sorted(df["direction"].dropna().unique().tolist()) if "direction" in df else []
        selected_direction = _synced_multiselect("Direction", directions, f"{p}_direction_filter", container=st)

        flow_id_search = st.text_input("Flow ID (exact)", "", key=f"{p}_flow_id_search")

        col5, col6 = st.columns(2)
        with col5:
            bytes_toserver_filter = st.text_input("Bytes to server (e.g. 1000-50000)", "", key=f"{p}_bytes_toserver")
        with col6:
            bytes_toclient_filter = st.text_input("Bytes to client (e.g. 1000-50000)", "", key=f"{p}_bytes_toclient")

    filtered = df.copy()
    if selected_types:
        filtered = filtered[filtered["event_type"].isin(selected_types)]
    if selected_proto:
        filtered = filtered[filtered["proto"].isin(selected_proto)]
    if selected_app_proto and "app_proto" in filtered:
        filtered = filtered[filtered["app_proto"].isin(selected_app_proto)]

    filtered = _apply_text_filter(filtered, "src_ip", src_ip_filter, src_ip_regex)
    filtered = _apply_text_filter(filtered, "dest_ip", dst_ip_filter, dst_ip_regex)

    if selected_iface and "in_iface" in filtered:
        filtered = filtered[filtered["in_iface"].isin(selected_iface)]
    if selected_direction and "direction" in filtered:
        filtered = filtered[filtered["direction"].isin(selected_direction)]
    if flow_id_search and "flow_id" in filtered:
        filtered = filtered[filtered["flow_id"].astype(str).str.contains(flow_id_search, na=False)]

    filtered = _apply_int_filter(filtered, "src_port", _parse_int_range(src_port_filter))
    filtered = _apply_int_filter(filtered, "dest_port", _parse_int_range(dst_port_filter))
    if "bytes_toserver" in filtered:
        filtered = _apply_int_filter(filtered, "bytes_toserver", _parse_int_range(bytes_toserver_filter))
    if "bytes_toclient" in filtered:
        filtered = _apply_int_filter(filtered, "bytes_toclient", _parse_int_range(bytes_toclient_filter))

    return filtered