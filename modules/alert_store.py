import sqlite3

DB_PATH = "alerts.db"


def update_status(alert_id, status):
    """Updates the review status of one alert. Table schema and ingestion
    both live in ingestor.py (the single source of truth for the DB) -
    this file only handles this one write the UI needs."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    conn.commit()
    conn.close()