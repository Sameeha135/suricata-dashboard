import json
import os
import sqlite3

EVE_LOG_PATH = "/var/log/suricata/eve.json"
DB_PATH = "alerts.db"
MAX_TRAFFIC_ROWS = 5000  # traffic is high-volume - cap so the DB file doesn't grow forever now that it's persisted


def _connect():
    conn = sqlite3.connect(DB_PATH)
    # WAL mode lets the dashboard READ from the db while ingestion WRITES to it,
    # without one blocking the other - reduces stutter/locking pauses.
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = _connect()
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
            status TEXT DEFAULT 'new'
        )
    """)

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
    conn.execute("INSERT OR REPLACE INTO state (key, value) VALUES ('file_offset', ?)", (str(offset),))
    conn.commit()


def _insert_alert(cursor, data):
    alert = data.get("alert", {}) or {}
    metadata = alert.get("metadata", {}) or {}

    def _first(field):
        val = metadata.get(field)
        return val[0] if isinstance(val, list) and val else None

    flow_id = data.get("flow_id")
    sig_id = alert.get("signature_id")
    ts = data.get("timestamp")
    dedup_key = f"{flow_id}_{sig_id}_{ts}"

    cursor.execute("""
        INSERT OR IGNORE INTO alerts
        (dedup_key, timestamp, src_ip, src_port, dest_ip, dest_port, proto,
         in_iface, flow_id, direction, bytes_toserver, bytes_toclient,
         signature, signature_id, category, severity, signature_severity,
         confidence, attack_target, raw_json, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new')
    """, (
        dedup_key, ts, data.get("src_ip"), data.get("src_port"),
        data.get("dest_ip"), data.get("dest_port"), data.get("proto"),
        data.get("in_iface"), flow_id, data.get("direction"),
        _safe_get(data, "flow", "bytes_toserver"),
        _safe_get(data, "flow", "bytes_toclient"),
        alert.get("signature"), sig_id, alert.get("category"), alert.get("severity"),
        _first("signature_severity"), _first("confidence"), _first("attack_target"),
        json.dumps(data),
    ))


def _insert_traffic(cursor, data, event_type):
    stats = data.get("stats", {}) or {}
    cursor.execute("""
        INSERT INTO traffic
        (timestamp, event_type, src_ip, src_port, dest_ip, dest_port, proto,
         app_proto, in_iface, flow_id, direction, bytes_toserver, bytes_toclient,
         uptime_sec, packets_captured, packets_dropped, decoder_pkts, decoder_bytes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("timestamp"), event_type, data.get("src_ip"), data.get("src_port"),
        data.get("dest_ip"), data.get("dest_port"), data.get("proto"), data.get("app_proto"),
        data.get("in_iface"), data.get("flow_id"), data.get("direction"),
        _safe_get(data, "flow", "bytes_toserver"), _safe_get(data, "flow", "bytes_toclient"),
        stats.get("uptime"), _safe_get(stats, "capture", "kernel_packets"),
        _safe_get(stats, "capture", "kernel_drops"), _safe_get(stats, "decoder", "pkts"),
        _safe_get(stats, "decoder", "bytes"),
    ))


def ingest_logs():
    init_db()
    if not os.path.exists(EVE_LOG_PATH):
        return

    conn = _connect()
    cursor = conn.cursor()
    last_offset = get_last_position(conn)
    file_size = os.path.getsize(EVE_LOG_PATH)
    if file_size < last_offset:
        last_offset = 0  # file was rotated/truncated - restart from the beginning

    alert_count = 0
    traffic_count = 0
    new_offset = last_offset

    with open(EVE_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(last_offset)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_type = data.get("event_type")
            if event_type == "alert":
                _insert_alert(cursor, data)
                alert_count += 1
            elif event_type is not None:
                _insert_traffic(cursor, data, event_type)
                traffic_count += 1

        new_offset = f.tell()

    conn.commit()
    save_position(conn, new_offset)

    # Cap traffic table growth - it's persisted to disk now, so it needs a retention limit
    cursor.execute("SELECT COUNT(*) FROM traffic")
    traffic_total = cursor.fetchone()[0]
    if traffic_total > MAX_TRAFFIC_ROWS:
        cursor.execute("""
            DELETE FROM traffic WHERE id NOT IN (
                SELECT id FROM traffic ORDER BY id DESC LIMIT ?
            )
        """, (MAX_TRAFFIC_ROWS,))
        conn.commit()

    conn.close()

    if alert_count or traffic_count:
        print(f"Ingested {alert_count} alerts and {traffic_count} traffic events into SQLite.")


if __name__ == "__main__":
    ingest_logs()