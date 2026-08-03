import json
import os
import streamlit as st

COMMON_FIELDS = {
    "sid", "rev", "msg", "classtype", "action", "protocol", "src_net",
    "src_port", "direction", "dst_net", "dst_port", "ruleset", "vendor",
    "flow", "flowbits", "references", "rule_metadata",
}

def _load_and_trim(filename):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base_dir, "..", filename) if not os.path.isabs(filename) else filename

    if not os.path.exists(path):
        path = filename

    if not os.path.exists(path):
        print(f"[INFO] Rule file '{filename}' not found. Skipping UI enrichment for this file.")
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            rules = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load JSON from '{filename}': {e}")
        return {}

    trimmed = {}
    for r in rules:
        sid = r.get("sid")
        if sid is None:
            continue
        trimmed[str(sid)] = {k: v for k, v in r.items() if k in COMMON_FIELDS}
    return trimmed


@st.cache_data
def load_rule_catalog(
    et_path="suricata_et_rules.json",
    community_path="suricata_community_sample.json",
):
    catalog = {}
    catalog.update(_load_and_trim(et_path))
    catalog.update(_load_and_trim(community_path))

    print(f"[DEBUG] Total SIDs loaded into catalog: {len(catalog)}")
    return catalog