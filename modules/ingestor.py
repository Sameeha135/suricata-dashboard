import json
import os
import sqlite3
from datetime import datetime

from modules.data_loader import load_rule_catalog

EVE_LOG_PATH = "/var/log/suricata/eve.json"
DB_PATH = "alerts.db"

MAX_TRAFFIC_ROWS = 5000
MAX_ALERT_ROWS_BEFORE_ROTATE = 25000




def _connect(db_path=DB_PATH):
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db(conn=None):
    close_at_end = False
    if conn is None:
        conn = _connect()
        close_at_end = True

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dedup_key TEXT UNIQUE,
            timestamp TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dest_ip TEXT,
            dest_port INTEGER,
            proto TEXT,
            in_iface TEXT,
            flow_id TEXT,
            direction TEXT,
            bytes_toserver INTEGER,
            bytes_toclient INTEGER,
            signature TEXT,
            signature_id INTEGER,
            category TEXT,
            severity INTEGER,
            signature_severity TEXT,
            confidence TEXT,
            attack_target TEXT,
            raw_json TEXT,
            enrichment_json TEXT,
            status TEXT DEFAULT 'new'
        )
    """)

    # Migration guard: if alerts.db already existed from before this column
    # was added, ALTER TABLE adds it. If the column is already there (brand
    # new DB created via the CREATE TABLE above), this just fails silently -
    # that's expected and fine, not an error worth surfacing.
    try:
        cursor.execute("ALTER TABLE alerts ADD COLUMN enrichment_json TEXT")
    except sqlite3.OperationalError:
        pass

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dest_ip TEXT,
            dest_port INTEGER,
            proto TEXT,
            app_proto TEXT,
            in_iface TEXT,
            flow_id TEXT,
            direction TEXT,
            bytes_toserver INTEGER,
            bytes_toclient INTEGER,
            uptime_sec INTEGER,
            packets_captured INTEGER,
            packets_dropped INTEGER,
            decoder_pkts INTEGER,
            decoder_bytes INTEGER
        )
    """)

    cursor.execute("CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT)")
    conn.commit()

    if close_at_end:
        conn.close()


def _safe_get(d, *keys, default=None):
    cur = d
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur


def get_last_position(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM state WHERE key='file_offset'")
    row = cursor.fetchone()
    return int(row[0]) if row else 0


def save_position(conn, offset):
    conn.execute(
        "INSERT OR REPLACE INTO state (key, value) VALUES ('file_offset', ?)",
        (str(offset),),
    )
    conn.commit()


def check_and_rotate_db():
    if not os.path.exists(DB_PATH):
        return

    conn = _connect()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT COUNT(*) FROM alerts")
        alert_count = cursor.fetchone()[0]
        offset = get_last_position(conn)
    except sqlite3.OperationalError:
        conn.close()
        return

    if alert_count >= MAX_ALERT_ROWS_BEFORE_ROTATE:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()

        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_name = f"alerts_archive_{timestamp_str}.db"
        os.rename(DB_PATH, archive_name)

        for ext in ["-wal", "-shm"]:
            if os.path.exists(DB_PATH + ext):
                try:
                    os.remove(DB_PATH + ext)
                except OSError:
                    pass

        new_conn = _connect()
        init_db(new_conn)
        save_position(new_conn, offset)
        new_conn.close()

        print(f"[+] Rotated active database ({alert_count} alerts) to '{archive_name}'.")
    else:
        conn.close()


def _find_enrichment(rule_catalog, signature_id):
    """Looks up the matching rule-catalog entry for a signature_id. Catalog
    keys are strings (see data_loader.py), so we normalize before lookup."""
    if signature_id is None:
        return None
    key = str(signature_id)
    return rule_catalog.get(key)


def _insert_alert(cursor, data, rule_catalog):
    alert = data.get("alert", {}) or {}
    metadata = alert.get("metadata", {}) or {}

    def _first(field):
        val = metadata.get(field)
        return val[0] if isinstance(val, list) and val else None

    flow_id = data.get("flow_id")
    sig_id = alert.get("signature_id")
    ts = data.get("timestamp")
    dedup_key = f"{flow_id}_{sig_id}_{ts}"

    # Snapshot whatever rule-catalog data matches this SID at the moment the
    # alert is ingested, and store it alongside the alert itself. This means
    # each alert keeps its own enrichment even if the catalog files change
    # later, and the dashboard can read it directly without a live lookup.
    enrichment = _find_enrichment(rule_catalog, sig_id)
    enrichment_json = json.dumps(enrichment) if enrichment else None

    cursor.execute(
        """
        INSERT OR IGNORE INTO alerts
        (dedup_key, timestamp, src_ip, src_port, dest_ip, dest_port, proto,
         in_iface, flow_id, direction, bytes_toserver, bytes_toclient,
         signature, signature_id, category, severity, signature_severity,
         confidence, attack_target, raw_json, enrichment_json, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new')
    """,
        (
            dedup_key, ts, data.get("src_ip"), data.get("src_port"),
            data.get("dest_ip"), data.get("dest_port"), data.get("proto"),
            data.get("in_iface"), flow_id, data.get("direction"),
            _safe_get(data, "flow", "bytes_toserver"),
            _safe_get(data, "flow", "bytes_toclient"),
            alert.get("signature"), sig_id, alert.get("category"), alert.get("severity"),
            _first("signature_severity"), _first("confidence"), _first("attack_target"),
            json.dumps(data), enrichment_json,
        ),
    )


def _insert_traffic(cursor, data, event_type):
    stats = data.get("stats", {}) or {}
    cursor.execute(
        """
        INSERT INTO traffic
        (timestamp, event_type, src_ip, src_port, dest_ip, dest_port, proto,
         app_proto, in_iface, flow_id, direction, bytes_toserver, bytes_toclient,
         uptime_sec, packets_captured, packets_dropped, decoder_pkts, decoder_bytes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            data.get("timestamp"), event_type, data.get("src_ip"), data.get("src_port"),
            data.get("dest_ip"), data.get("dest_port"), data.get("proto"), data.get("app_proto"),
            data.get("in_iface"), data.get("flow_id"), data.get("direction"),
            _safe_get(data, "flow", "bytes_toserver"), _safe_get(data, "flow", "bytes_toclient"),
            stats.get("uptime"), _safe_get(stats, "capture", "kernel_packets"),
            _safe_get(stats, "capture", "kernel_drops"), _safe_get(stats, "decoder", "pkts"),
            _safe_get(stats, "decoder", "bytes"),
        ),
    )


def ingest_logs():
    check_and_rotate_db()
    init_db()
    if not os.path.exists(EVE_LOG_PATH):
        return

    rule_catalog = load_rule_catalog()

    conn = _connect()
    conn.execute("PRAGMA synchronous = OFF;")
    cursor = conn.cursor()
    
    last_offset = get_last_position(conn)
    file_size = os.path.getsize(EVE_LOG_PATH)
    if file_size < last_offset:
        last_offset = 0

    alert_count = 0
    traffic_count = 0
    batch_count = 0

    try:
        with open(EVE_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(last_offset)
            
            conn.execute("BEGIN TRANSACTION;")
            while True:
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event_type = data.get("event_type")
                if event_type == "alert":
                    _insert_alert(cursor, data, rule_catalog)
                    alert_count += 1
                    batch_count += 1
                elif event_type is not None:
                    _insert_traffic(cursor, data, event_type)
                    traffic_count += 1
                    batch_count += 1

                # Commit every 500 records to release write lock briefly
                if batch_count >= 500:
                    new_offset = f.tell()
                    save_position(conn, new_offset)
                    conn.commit()
                    conn.execute("BEGIN TRANSACTION;")
                    batch_count = 0

            new_offset = f.tell()
            save_position(conn, new_offset)
            conn.commit()

        cursor.execute("SELECT COUNT(*) FROM traffic")
        traffic_total = cursor.fetchone()[0]
        if traffic_total > MAX_TRAFFIC_ROWS:
            cursor.execute("""
                DELETE FROM traffic WHERE id NOT IN (
                    SELECT id FROM traffic ORDER BY id DESC LIMIT ?
                )
            """, (MAX_TRAFFIC_ROWS,))
            conn.commit()

    finally:
        conn.close()

    if alert_count or traffic_count:
        print(f"Ingested {alert_count} alerts and {traffic_count} traffic events into SQLite.")

# --- Add these functions to the bottom of ingestor.py ---

def get_alerts_page(limit=50, offset=0, status_filter=None):
    conn = _connect()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = "SELECT * FROM alerts"
    params = []
    
    if status_filter and status_filter != "All":
        query += " WHERE status = ?"
        params.append(status_filter)
        
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    rows = [dict(row) for row in cursor.fetchall()]
    
    # Get total count for pagination controls
    count_query = "SELECT COUNT(*) FROM alerts"
    if status_filter and status_filter != "All":
        count_query += " WHERE status = ?"
        cursor.execute(count_query, (status_filter,))
    else:
        cursor.execute(count_query)
    total_count = cursor.fetchone()[0]
    
    conn.close()
    return rows, total_count


def get_single_alert_details(alert_id):
    conn = _connect()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT raw_json, enrichment_json FROM alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None, None
        
    raw_payload = row["raw_json"]
    try:
        parsed = json.loads(raw_payload)
        formatted_json = json.dumps(parsed, indent=2)
    except Exception:
        formatted_json = raw_payload
        
    enrichment = json.loads(row["enrichment_json"]) if row["enrichment_json"] else {}
    return formatted_json, enrichment

if __name__ == "__main__":
    ingest_logs()