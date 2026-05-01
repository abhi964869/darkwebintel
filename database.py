import os
import shutil
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
BUNDLED_DB_PATH = BASE_DIR / "threat_intel.db"


def _runtime_root() -> Path:
    configured = os.environ.get("APP_RUNTIME_DIR")
    if configured:
        return Path(configured)
    if os.environ.get("VERCEL"):
        return Path("/tmp/dark-intel")
    return BASE_DIR


RUNTIME_ROOT = _runtime_root()
DB_PATH = RUNTIME_ROOT / "threat_intel.db"


def ensure_runtime_db():
    RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
    if DB_PATH.exists():
        return
    if BUNDLED_DB_PATH.exists() and BUNDLED_DB_PATH != DB_PATH:
        shutil.copy2(BUNDLED_DB_PATH, DB_PATH)


def get_connection():
    ensure_runtime_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS breaches (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source          TEXT NOT NULL,
            breach_date     TEXT,
            data_type       TEXT,
            affected_count  INTEGER,
            severity        TEXT DEFAULT 'Medium',
            ingested_at     TEXT DEFAULT (datetime('now'))
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS credentials (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            email_hash   TEXT NOT NULL,
            domain       TEXT,
            breach_id    INTEGER,
            found_in_sim INTEGER DEFAULT 0,
            checked_at   TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (breach_id) REFERENCES breaches(id)
        )
        """
    )

    cursor.execute(
        """
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
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id INTEGER,
            email_to  TEXT,
            sent_at   TEXT DEFAULT (datetime('now')),
            status    TEXT DEFAULT 'Pending',
            FOREIGN KEY (threat_id) REFERENCES threats(id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS tracked_emails (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            email            TEXT NOT NULL UNIQUE,
            domain           TEXT NOT NULL,
            last_risk_label  TEXT DEFAULT '',
            last_score       INTEGER DEFAULT 0,
            last_summary     TEXT DEFAULT '',
            last_checked_at  TEXT DEFAULT (datetime('now')),
            lookup_count     INTEGER DEFAULT 0,
            report_count     INTEGER DEFAULT 0
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS email_lookup_history (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            tracked_email TEXT NOT NULL,
            query_value   TEXT NOT NULL,
            source        TEXT NOT NULL DEFAULT 'internet',
            result_count  INTEGER DEFAULT 0,
            payload_json  TEXT NOT NULL,
            created_at    TEXT DEFAULT (datetime('now'))
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS email_reports (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            tracked_email TEXT NOT NULL,
            risk_label    TEXT NOT NULL,
            score         INTEGER NOT NULL,
            summary       TEXT DEFAULT '',
            payload_json  TEXT NOT NULL,
            created_at    TEXT DEFAULT (datetime('now'))
        )
        """
    )

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tracked_emails_email ON tracked_emails(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_lookup_history_email ON email_lookup_history(tracked_email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_reports_email ON email_reports(tracked_email)")

    conn.commit()
    conn.close()
    print("[ok] Database initialized successfully.")


if __name__ == "__main__":
    init_db()
