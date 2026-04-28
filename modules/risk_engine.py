# modules/risk_engine.py
# MODULE 4: Risk Assessment Engine
#
# Implements a multi-factor, rule-based threat scoring system.
# Each threat is scored 0-100 across 5 weighted parameters.
# Final score maps to: Low / Medium / High / Critical
#
# Real-world equivalent: CVSS scoring (NIST NVD), IBM QRadar
# risk scoring, Splunk Enterprise Security risk-based alerting.

import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import get_connection

# ── Scoring Weights (must total 100) ─────────────────────────────
WEIGHTS = {
    "severity"       : 30,   # How severe was the source breach?
    "data_type"      : 25,   # What kind of data was exposed?
    "dark_web"       : 20,   # Was it found on simulated dark web?
    "breach_count"   : 15,   # How many breaches contain this credential?
    "verification"   : 10    # Was the leak verified/confirmed?
}

# ── Severity Score Map ────────────────────────────────────────────
SEVERITY_SCORES = {
    "Critical" : 30,
    "High"     : 22,
    "Medium"   : 14,
    "Low"      : 6,
    "Safe"     : 0
}

# ── Data Type Scores (higher = more sensitive) ────────────────────
DATA_TYPE_SCORES = {
    "plaintext_password" : 25,
    "password"           : 20,
    "password_hash"      : 15,
    "encrypted_password" : 12,
    "credit_card"        : 25,
    "ssn"                : 25,
    "phone"              : 8,
    "email"              : 5,
    "username"           : 5,
    "name"               : 3,
    "location"           : 3,
    "country"            : 2,
    "birthdate"          : 7,
    "subscription_type"  : 2
}

# ── Final Score → Risk Label Thresholds ──────────────────────────
RISK_THRESHOLDS = {
    "Critical" : 80,
    "High"     : 60,
    "Medium"   : 35,
    "Low"      : 0
}


def score_data_types(data_types_str: str) -> int:
    """
    Scores the sensitivity of exposed data types.
    data_types_str: semicolon or comma separated string
    e.g. 'email;password_hash;phone' → score
    """
    if not data_types_str:
        return 0

    # Handle both semicolon and comma separated formats
    separators = [';', ',']
    types = [data_types_str]
    for sep in separators:
        if sep in data_types_str:
            types = data_types_str.split(sep)
            break

    total = 0
    for dtype in types:
        dtype = dtype.strip().lower().replace(' ', '_')
        total += DATA_TYPE_SCORES.get(dtype, 0)

    # Cap at maximum weight for this factor
    return min(total, WEIGHTS["data_type"])


def calculate_risk_score(
    severity     : str,
    data_types   : str,
    dark_web_hit : bool,
    breach_count : int,
    verified     : bool
) -> dict:
    """
    Master scoring function — calculates a 0-100 risk score.

    Parameters:
    - severity     : breach severity string (Critical/High/Medium/Low)
    - data_types   : semicolon-separated exposed data types
    - dark_web_hit : True if found in dark web simulation
    - breach_count : number of breaches the credential appears in
    - verified     : whether the leak was independently verified

    Returns:
    - dict with score breakdown and final risk label
    """

    # ── Factor 1: Severity Score (0-30) ──────────────────────────
    severity_score = SEVERITY_SCORES.get(severity, 0)

    # ── Factor 2: Data Type Score (0-25) ─────────────────────────
    data_score = score_data_types(data_types)

    # ── Factor 3: Dark Web Presence Score (0-20) ─────────────────
    dark_web_score = WEIGHTS["dark_web"] if dark_web_hit else 0

    # ── Factor 4: Breach Count Score (0-15) ──────────────────────
    # More appearances = higher risk
    if breach_count >= 5:
        bc_score = 15
    elif breach_count >= 3:
        bc_score = 10
    elif breach_count == 2:
        bc_score = 6
    else:
        bc_score = 2

    # ── Factor 5: Verification Score (0-10) ──────────────────────
    verification_score = WEIGHTS["verification"] if verified else 3

    # ── Total Score ───────────────────────────────────────────────
    total_score = (severity_score + data_score +
                   dark_web_score + bc_score + verification_score)

    # Cap at 100
    total_score = min(total_score, 100)

    # ── Map Score to Risk Label ───────────────────────────────────
    if total_score >= RISK_THRESHOLDS["Critical"]:
        risk_label = "Critical"
    elif total_score >= RISK_THRESHOLDS["High"]:
        risk_label = "High"
    elif total_score >= RISK_THRESHOLDS["Medium"]:
        risk_label = "Medium"
    else:
        risk_label = "Low"

    return {
        "total_score"       : total_score,
        "risk_label"        : risk_label,
        "score_breakdown"   : {
            "severity_score"     : severity_score,
            "data_type_score"    : data_score,
            "dark_web_score"     : dark_web_score,
            "breach_count_score" : bc_score,
            "verification_score" : verification_score
        },
        "factors_used" : {
            "severity"    : severity,
            "dark_web_hit": dark_web_hit,
            "breach_count": breach_count,
            "verified"    : verified
        }
    }


def assess_email_risk(email_result: dict, dark_web_result: dict) -> dict:
    """
    Combines Module 2 (credential check) and Module 3 (dark web scan)
    results to produce a comprehensive risk assessment for an email.

    This is the integration point of the entire intelligence pipeline.
    """
    breaches     = email_result.get("breaches", [])
    dw_hits      = dark_web_result.get("dark_web_hits", 0)
    dw_matches   = dark_web_result.get("matches", [])

    if not breaches and dw_hits == 0:
        return {
            "risk_label"  : "Safe",
            "total_score" : 0,
            "summary"     : "No exposure detected in breach database or dark web simulation.",
            "score_breakdown": {},
            "recommendations": get_recommendations("Safe")
        }

    # Use the worst breach for scoring (highest severity)
    severity_order = ["Critical", "High", "Medium", "Low"]
    worst_severity = "Low"
    all_data_types = []

    for breach in breaches:
        sev = breach.get("severity", "Low")
        if severity_order.index(sev) < severity_order.index(worst_severity):
            worst_severity = sev
        dt = breach.get("data_type", "")
        if dt:
            all_data_types.extend(dt.replace(';', ',').split(','))

    # Also check dark web match severity
    for match in dw_matches:
        sev = match.get("threat_level", "Low")
        if sev in severity_order:
            if severity_order.index(sev) < severity_order.index(worst_severity):
                worst_severity = sev

    combined_data_types = ";".join(set(all_data_types))
    dark_web_hit        = dw_hits > 0
    breach_count        = len(breaches)
    verified            = any(m.get("verified", False) for m in dw_matches)

    # Calculate the risk score
    result = calculate_risk_score(
        severity     = worst_severity,
        data_types   = combined_data_types,
        dark_web_hit = dark_web_hit,
        breach_count = breach_count,
        verified     = verified
    )

    # Add summary and recommendations
    result["summary"] = build_summary(
        breach_count, dw_hits, worst_severity, result["total_score"]
    )
    result["recommendations"] = get_recommendations(result["risk_label"])
    result["assessed_at"]     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save this assessment to the threats table
    save_threat_assessment(result, breach_count)

    return result


def build_summary(breach_count, dw_hits, severity, score) -> str:
    """Generates a human-readable threat summary."""
    parts = []
    if breach_count > 0:
        parts.append(
            f"Found in {breach_count} breach record(s) with "
            f"{severity}-severity exposure."
        )
    if dw_hits > 0:
        parts.append(
            f"Detected in {dw_hits} simulated dark web source(s)."
        )
    parts.append(f"Composite risk score: {score}/100.")
    return " ".join(parts)


def get_recommendations(risk_label: str) -> list:
    """
    Returns actionable security recommendations based on risk level.
    This is what separates a threat intelligence tool from a simple
    search engine — it tells the user what to DO about the risk.
    """
    recommendations = {
        "Safe": [
            "Continue monitoring regularly — threat landscape changes daily.",
            "Enable two-factor authentication (2FA) on all accounts.",
            "Use a password manager to maintain unique passwords."
        ],
        "Low": [
            "Change your password for the affected service immediately.",
            "Enable two-factor authentication (2FA) as a priority.",
            "Check if you reuse this password on other services.",
            "Monitor your email for suspicious login alerts."
        ],
        "Medium": [
            "URGENT: Change passwords for all affected accounts now.",
            "Enable 2FA on email, banking, and social media immediately.",
            "Check HaveIBeenPwned.com for additional exposure.",
            "Review recent account activity for unauthorized access.",
            "Consider using a credit monitoring service."
        ],
        "High": [
            "CRITICAL ACTION: Reset ALL passwords — assume full compromise.",
            "Contact your bank if any financial accounts share this email.",
            "Enable account freezes or alerts on financial institutions.",
            "Revoke all active sessions on affected platforms.",
            "File a report with your national cyber crime authority.",
            "Consider identity theft protection services."
        ],
        "Critical": [
            "IMMEDIATE ACTION REQUIRED: Assume full identity compromise.",
            "Contact banks and financial institutions immediately.",
            "Place a fraud alert with credit bureaus.",
            "Reset all accounts — email, banking, social media, work.",
            "Report to national cybercrime authority (India: cybercrime.gov.in).",
            "Engage professional identity theft restoration services.",
            "Monitor all financial statements for 12 months."
        ]
    }
    return recommendations.get(risk_label, recommendations["Low"])


def save_threat_assessment(assessment: dict, breach_count: int):
    """Persists the risk assessment result to the threats table."""
    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO threats (risk_level, threat_type, detected_at)
            VALUES (?, ?, datetime('now'))
        """, (
            assessment.get("risk_label", "Low"),
            f"Multi-factor Assessment (score: {assessment.get('total_score', 0)})"
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        pass  # Non-critical — don't crash the app if logging fails


def get_all_assessments() -> list:
    """Returns all threat assessments from the database."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, risk_level, threat_type, detected_at
        FROM threats
        ORDER BY detected_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_risk_distribution() -> dict:
    """
    Returns count of threats per risk level.
    Used by the dashboard risk distribution chart.
    """
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT risk_level, COUNT(*) as count
        FROM threats
        GROUP BY risk_level
    """)
    rows = cursor.fetchall()
    conn.close()
    return {row["risk_level"]: row["count"] for row in rows}