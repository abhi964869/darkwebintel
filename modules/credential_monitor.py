# modules/credential_monitor.py
# MODULE 2: Credential Monitoring System
#
# How it works:
# 1. User submits an email address via the web form
# 2. We hash it with SHA-256 (never store the raw email)
# 3. We compare the hash against all hashes in our credentials table
# 4. If matched, we return breach details and risk level
# 5. We also check if the domain itself appears in any breach

import hashlib
import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import get_connection


def hash_email(email: str) -> str:
    """
    Converts a plaintext email into a SHA-256 hash.
    Example: 'user@gmail.com' → 'a1b2c3d4e5f6...' (64 hex chars)
    This hash is one-way — it cannot be reversed back to the email.
    """
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()


def check_email(email: str) -> dict:
    """
    Main function: checks if an email has been exposed in any breach.
    
    Steps:
    - Hash the input email
    - Search credentials table for matching hash
    - If found, fetch the associated breach details
    - Calculate overall risk level
    - Return structured result
    """

    if not email or '@' not in email:
        return {
            "status" : "error",
            "message": "Invalid email address provided."
        }

    email_hash = hash_email(email)
    domain     = email.strip().lower().split('@')[1]

    conn   = get_connection()
    cursor = conn.cursor()

    # ── Step 1: Check if this exact email hash exists in any breach ──
    cursor.execute("""
        SELECT 
            c.id         AS cred_id,
            c.email_hash,
            c.domain,
            c.found_in_sim,
            c.checked_at,
            b.id         AS breach_id,
            b.source,
            b.breach_date,
            b.data_type,
            b.affected_count,
            b.severity
        FROM credentials c
        JOIN breaches b ON c.breach_id = b.id
        WHERE c.email_hash = ?
    """, (email_hash,))

    email_matches = [dict(row) for row in cursor.fetchall()]

    # ── Step 2: Also check if the domain appears in any breach ──────
    cursor.execute("""
        SELECT 
            c.domain,
            b.source,
            b.breach_date,
            b.data_type,
            b.severity,
            b.affected_count
        FROM credentials c
        JOIN breaches b ON c.breach_id = b.id
        WHERE c.domain = ?
        GROUP BY b.id
    """, (domain,))

    domain_matches = [dict(row) for row in cursor.fetchall()]

    conn.close()

    # ── Step 3: Determine overall risk level ────────────────────────
    risk_level = calculate_risk(email_matches, domain_matches)

    # ── Step 4: Log this search into the threats table ───────────────
    if email_matches:
        log_threat(
            breach_id  = email_matches[0]['breach_id'],
            cred_id    = email_matches[0]['cred_id'],
            risk_level = risk_level,
            threat_type= "Credential Exposure"
        )

    # ── Step 5: Build and return the result ─────────────────────────
    return {
        "status"        : "found" if email_matches else "clean",
        "email_checked" : email[:3] + "***@" + domain,  # mask the email in response
        "hash_used"     : email_hash[:16] + "...",        # show partial hash for UI
        "risk_level"    : risk_level,
        "breach_count"  : len(email_matches),
        "domain_exposure": len(domain_matches),
        "breaches"      : email_matches,
        "domain_breaches": domain_matches,
        "checked_at"    : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def check_domain(domain: str) -> dict:
    """
    Checks if an entire domain (e.g., 'gmail.com') appears in breaches.
    Useful for organizations checking if their company domain is exposed.
    """

    if not domain or '.' not in domain:
        return {"status": "error", "message": "Invalid domain."}

    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            b.source,
            b.breach_date,
            b.data_type,
            b.severity,
            b.affected_count,
            COUNT(c.id) AS credential_count
        FROM credentials c
        JOIN breaches b ON c.breach_id = b.id
        WHERE c.domain = ?
        GROUP BY b.id
        ORDER BY b.affected_count DESC
    """, (domain.strip().lower(),))

    results = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return {
        "status"          : "found" if results else "clean",
        "domain"          : domain,
        "breach_count"    : len(results),
        "breaches"        : results,
        "checked_at"      : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def calculate_risk(email_matches: list, domain_matches: list) -> str:
    """
    Rule-based risk classification engine.
    
    Rules:
    - No matches at all            → Safe
    - Only domain match            → Low
    - 1 email match, Low severity  → Low
    - 1 email match, Medium        → Medium
    - Multiple matches OR High     → High
    - Any Critical breach match    → Critical
    """

    if not email_matches and not domain_matches:
        return "Safe"

    if not email_matches and domain_matches:
        return "Low"

    severities = [m['severity'] for m in email_matches]

    if 'Critical' in severities:
        return "Critical"
    if len(email_matches) >= 3 or 'High' in severities:
        return "High"
    if 'Medium' in severities:
        return "Medium"

    return "Low"


def log_threat(breach_id, cred_id, risk_level, threat_type):
    """
    Saves a detected threat into the threats table.
    This builds up our threat history for reporting and dashboard analytics.
    """
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO threats (breach_id, cred_id, risk_level, threat_type)
        VALUES (?, ?, ?, ?)
    """, (breach_id, cred_id, risk_level, threat_type))
    conn.commit()
    conn.close()


def get_recent_threats(limit: int = 10) -> list:
    """
    Returns the most recent threat detections.
    Used by the dashboard to show live threat feed.
    """
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            t.id,
            t.risk_level,
            t.threat_type,
            t.detected_at,
            b.source,
            b.severity
        FROM threats t
        JOIN breaches b ON t.breach_id = b.id
        ORDER BY t.detected_at DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]