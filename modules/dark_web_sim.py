# modules/dark_web_sim.py
# MODULE 3: Dark Web Simulation Layer
#
# ACADEMIC NOTICE: This module simulates dark web data structures
# for educational purposes only. No actual TOR network access occurs.
# All .onion references are clearly marked [SIMULATED].
#
# Real-world equivalent: This mimics how tools like DarkOwl, Terbium
# Signal, and Recorded Future ingest dark web intelligence feeds.

import json
import os
import hashlib
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import get_connection

# Path to our simulated dark web dataset
SIM_DATA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "dark_web_sim.json"
)


def load_sim_data() -> dict:
    """Loads the simulated dark web JSON dataset into memory."""
    if not os.path.exists(SIM_DATA_PATH):
        return {}
    with open(SIM_DATA_PATH, 'r') as f:
        return json.load(f)


def scan_dark_web_for_email(email: str) -> dict:
    """
    Simulates scanning dark web paste sites and leak forums
    for a specific email address.

    In a real tool, this would:
    1. Connect via TOR SOCKS5 proxy
    2. Crawl known .onion paste sites
    3. Parse leaked credential lists
    4. Return matches

    In our simulation, we check the JSON dataset directly.
    """
    if not email or '@' not in email:
        return {"status": "error", "message": "Invalid email."}

    email_clean = email.strip().lower()
    email_hash  = hashlib.sha256(email_clean.encode()).hexdigest()
    data        = load_sim_data()
    matches     = []

    # Search through each leaked credential set in our simulation
    for leak in data.get("leaked_credentials", []):
        if email_clean in [e.lower() for e in leak.get("emails", [])]:
            matches.append({
                "sim_source"   : leak["sim_source"],
                "leak_type"    : leak["leak_type"],
                "post_title"   : leak["post_title"],
                "data_exposed" : leak["data_exposed"],
                "threat_level" : leak["threat_level"],
                "date_posted"  : leak["date_posted"],
                "verified"     : leak["verified"]
            })

    return {
        "status"      : "found" if matches else "not_found",
        "email_masked": email_clean[:3] + "***@" + email_clean.split('@')[1],
        "email_hash"  : email_hash[:16] + "...",
        "dark_web_hits": len(matches),
        "matches"     : matches,
        "scanned_at"  : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "disclaimer"  : "SIMULATED DATA — Academic project only"
    }


def get_threat_actors() -> list:
    """
    Returns the list of simulated threat actor profiles.
    In real threat intelligence, these would come from
    dark web forum monitoring and attribution analysis.
    """
    data = load_sim_data()
    return data.get("threat_actors", [])


def get_paste_sites() -> list:
    """
    Returns monitored paste site statistics.
    Real-world equivalent: DarkOwl monitors 900+ dark web sites.
    """
    data = load_sim_data()
    return data.get("paste_sites", [])


def get_all_dark_web_leaks() -> list:
    """
    Returns all simulated leak records.
    Used by the dashboard to show dark web activity feed.
    """
    data = load_sim_data()
    return data.get("leaked_credentials", [])


def get_dark_web_stats() -> dict:
    """
    Returns summary statistics for the dark web simulation layer.
    Used by the dashboard overview cards.
    """
    data    = load_sim_data()
    leaks   = data.get("leaked_credentials", [])
    actors  = data.get("threat_actors", [])
    pastes  = data.get("paste_sites", [])

    # Count threat levels across all leaks
    threat_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    total_emails  = 0

    for leak in leaks:
        level = leak.get("threat_level", "Low")
        if level in threat_counts:
            threat_counts[level] += 1
        total_emails += len(leak.get("emails", []))

    # Total posts monitored across all paste sites
    total_posts = sum(p.get("posts_monitored", 0) for p in pastes)

    return {
        "total_leaks"       : len(leaks),
        "total_actors"      : len(actors),
        "total_paste_sites" : len(pastes),
        "total_posts_monitored": total_posts,
        "total_emails_exposed" : total_emails,
        "threat_level_breakdown": threat_counts,
        "last_scan"         : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def explain_tor_architecture() -> dict:
    """
    Returns a structured explanation of TOR architecture.
    Used in the about/info section of the dashboard.
    This is purely educational — no TOR connection is made.
    """
    return {
        "tor_overview": (
            "The Onion Router (TOR) anonymizes internet traffic by encrypting "
            "data in multiple layers and routing it through a series of volunteer "
            "relay nodes. Each node decrypts one layer, revealing only the next hop."
        ),
        "layers": [
            {
                "layer": 1,
                "name" : "Entry Guard Node",
                "role" : "Knows the user's real IP but not the destination"
            },
            {
                "layer": 2,
                "name" : "Middle Relay Node",
                "role" : "Knows neither source nor destination"
            },
            {
                "layer": 3,
                "name" : "Exit Node",
                "role" : "Knows the destination but not the user's real IP"
            }
        ],
        "onion_services": (
            ".onion addresses are hidden services that exist only within TOR. "
            "They use 16 or 56-character addresses derived from public key cryptography."
        ),
        "academic_note": (
            "This project does NOT connect to TOR. All .onion references "
            "in this tool are clearly marked [SIMULATED] for academic safety."
        )
    }