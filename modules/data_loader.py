# modules/data_loader.py
import json
import os
import pandas as pd
import streamlit as st
from typing import Dict, Any

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
    """Restored for compatibility with app.py imports."""
    catalog = {}
    catalog.update(_load_and_trim(et_path))
    catalog.update(_load_and_trim(community_path))

    print(f"[DEBUG] Total SIDs loaded into catalog: {len(catalog)}")
    return catalog


@st.cache_data(ttl=3600)
def load_sid_catalog(json_path: str = "suricata_community_sample.json") -> Dict[int, Dict[str, Any]]:
    """
    Loads rules into an O(1) dictionary mapping: sid (int) -> rule details (dict)
    """
    sid_dict = {}
    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base_dir, "..", json_path) if not os.path.isabs(json_path) else json_path

    if not os.path.exists(path):
        path = json_path

    if not os.path.exists(path):
        return sid_dict

    try:
        with open(path, "r", encoding="utf-8") as f:
            rules = json.load(f)
            for rule in rules:
                sid_val = rule.get("sid")
                if sid_val is not None:
                    sid = int(sid_val)
                    sid_dict[sid] = {
                        "msg": rule.get("msg", "No description available"),
                        "classtype": rule.get("classtype", "Unknown"),
                        "rev": rule.get("rev", 1),
                        "raw_rule": rule.get("raw", "")
                    }
    except Exception as e:
        print(f"[ERROR] Failed to load catalog from '{json_path}': {e}")
        
    return sid_dict

def prepare_alerts_dataframe(df: pd.DataFrame, sid_catalog: Dict[int, Dict[str, Any]]) -> pd.DataFrame:
    """
    Pre-processes raw alerts: O(1) SID enrichment and JSON pre-formatting.
    """
    if df.empty:
        return df

    enriched_rows = []
    
    for _, row in df.iterrows():
        sid = int(row.get("sid", 0))
        rule_info = sid_catalog.get(sid, {})
        
        raw_payload = row.get("payload_json", "{}")
        if isinstance(raw_payload, str):
            try:
                parsed_json = json.loads(raw_payload)
                formatted_json = json.dumps(parsed_json, indent=2)
            except Exception:
                formatted_json = raw_payload
        else:
            formatted_json = json.dumps(raw_payload, indent=2)

        row_dict = row.to_dict()
        row_dict["rule_msg"] = rule_info.get("msg", row.get("msg", "N/A"))
        row_dict["rule_classtype"] = rule_info.get("classtype", "N/A")
        row_dict["formatted_payload"] = formatted_json
        
        enriched_rows.append(row_dict)

    return pd.DataFrame(enriched_rows)