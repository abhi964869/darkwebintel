# modules/data_collector.py
# MODULE 1: OSINT Data Collection Engine

import pandas as pd
import sqlite3
import os
import hashlib
from datetime import datetime
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import get_connection

DATASET_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "simulated_breaches.csv"
)

def ingest_breach_data():
    if not os.path.exists(DATASET_PATH):
        return {"status": "error", "message": "Dataset file not found."}

    df = pd.read_csv(DATASET_PATH)
    conn = get_connection()
    cursor = conn.cursor()
    ingested = 0
    skipped  = 0

    for _, row in df.iterrows():
        cursor.execute("SELECT id FROM breaches WHERE source = ?", (row['source'],))
        if cursor.fetchone():
            skipped += 1
            continue

        cursor.execute("""
            INSERT INTO breaches (source, breach_date, data_type, affected_count, severity)
            VALUES (?, ?, ?, ?, ?)
        """, (
            row['source'],
            row['breach_date'],
            row['data_type'],
            int(row['affected_count']),
            row['severity']
        ))

        breach_id = cursor.lastrowid

        if pd.notna(row.get('sample_emails', '')):
            for email in str(row['sample_emails']).split(';'):
                email = email.strip()
                if '@' not in email:
                    continue
                domain     = email.split('@')[1]
                email_hash = hashlib.sha256(email.lower().encode()).hexdigest()
                cursor.execute("""
                    INSERT INTO credentials (email_hash, domain, breach_id, found_in_sim)
                    VALUES (?, ?, ?, 1)
                """, (email_hash, domain, breach_id))

        ingested += 1

    conn.commit()
    conn.close()

    return {
        "status"    : "success",
        "ingested"  : ingested,
        "skipped"   : skipped,
        "total"     : len(df),
        "timestamp" : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def get_all_breaches():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM breaches ORDER BY ingested_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_breach_stats():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM breaches")
    total_breaches = cursor.fetchone()['total']

    cursor.execute("SELECT SUM(affected_count) as total FROM breaches")
    total_affected = cursor.fetchone()['total'] or 0

    cursor.execute("SELECT severity, COUNT(*) as count FROM breaches GROUP BY severity")
    severity_breakdown = {row['severity']: row['count'] for row in cursor.fetchall()}

    cursor.execute("SELECT COUNT(*) as total FROM credentials WHERE found_in_sim = 1")
    dark_web_hits = cursor.fetchone()['total']

    conn.close()

    return {
        "total_breaches"    : total_breaches,
        "total_affected"    : total_affected,
        "severity_breakdown": severity_breakdown,
        "dark_web_hits"     : dark_web_hits
    }