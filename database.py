# database.py
import sqlite3

DB_PATH = "threat_intel.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS breaches (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source          TEXT NOT NULL,
            breach_date     TEXT,
            data_type       TEXT,
            affected_count  INTEGER,
            severity        TEXT DEFAULT 'Medium',
            ingested_at     TEXT DEFAULT (datetime('now'))
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            email_hash   TEXT NOT NULL,
            domain       TEXT,
            breach_id    INTEGER,
            found_in_sim INTEGER DEFAULT 0,
            checked_at   TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (breach_id) REFERENCES breaches(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            breach_id   INTEGER,
            cred_id     INTEGER,
            risk_level  TEXT,
            threat_type TEXT,
            detected_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (breach_id) REFERENCES breaches(id),
            FOREIGN KEY (cred_id)   REFERENCES credentials(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id INTEGER,
            email_to  TEXT,
            sent_at   TEXT DEFAULT (datetime('now')),
            status    TEXT DEFAULT 'Pending',
            FOREIGN KEY (threat_id) REFERENCES threats(id)
        )
    """)

    conn.commit()
    conn.close()
    print("[✔] Database initialized successfully.")

if __name__ == "__main__":
    init_db()