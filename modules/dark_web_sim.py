# modules/dark_web_sim.py
# MODULE 3: Simulated dark web data + live public internet lookup

import hashlib
import json
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from email.utils import parsedate_to_datetime
from urllib.parse import quote_plus
from urllib.request import Request, urlopen

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SIM_DATA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "dark_web_sim.json",
)


def load_sim_data() -> dict:
    """Loads the simulated dark web JSON dataset into memory."""
    if not os.path.exists(SIM_DATA_PATH):
        return {}
    with open(SIM_DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def scan_dark_web_for_email(email: str) -> dict:
    """
    Simulates scanning dark web paste sites and leak forums for a specific email.
    """
    if not email or "@" not in email:
        return {"status": "error", "message": "Invalid email."}

    email_clean = email.strip().lower()
    email_hash = hashlib.sha256(email_clean.encode()).hexdigest()
    data = load_sim_data()
    matches = []

    for leak in data.get("leaked_credentials", []):
        if email_clean in [e.lower() for e in leak.get("emails", [])]:
            matches.append(
                {
                    "sim_source": leak["sim_source"],
                    "leak_type": leak["leak_type"],
                    "post_title": leak["post_title"],
                    "data_exposed": leak["data_exposed"],
                    "threat_level": leak["threat_level"],
                    "date_posted": leak["date_posted"],
                    "verified": leak["verified"],
                }
            )

    return {
        "status": "found" if matches else "not_found",
        "email_masked": email_clean[:3] + "***@" + email_clean.split("@")[1],
        "email_hash": email_hash[:16] + "...",
        "dark_web_hits": len(matches),
        "matches": matches,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "disclaimer": "SIMULATED DATA - Academic project only",
    }


def _extract_domain(query: str) -> str:
    cleaned = query.strip().lower()
    if "@" in cleaned:
        return cleaned.split("@", 1)[1]
    return cleaned


def _infer_severity(text: str) -> str:
    lowered = text.lower()
    if any(token in lowered for token in ["ransomware", "critical", "breach", "leak", "stolen"]):
        return "High"
    if any(token in lowered for token in ["malware", "attack", "phishing", "cyber"]):
        return "Medium"
    return "Low"


def _format_article(item: ET.Element) -> dict:
    title = (item.findtext("title") or "").strip()
    link = (item.findtext("link") or "").strip()
    summary = (item.findtext("description") or "").strip()
    source_node = item.find("source")
    source = source_node.text.strip() if source_node is not None and source_node.text else "Google News"
    raw_date = (item.findtext("pubDate") or "").strip()

    published_at = raw_date
    if raw_date:
        try:
            published_at = parsedate_to_datetime(raw_date).isoformat()
        except Exception:
            pass

    return {
        "title": title,
        "link": link,
        "summary": summary,
        "source": source,
        "published_at": published_at,
        "severity": _infer_severity(f"{title} {summary}"),
    }


def fetch_live_intel(query: str, limit: int = 6) -> dict:
    """
    Fetch recent public internet coverage for a domain/email using Google News RSS.
    This is public web intelligence, not dark web access.
    """
    if not query or len(query.strip()) < 2:
        return {"status": "error", "message": "Query must be at least 2 characters."}

    cleaned = query.strip()
    target = _extract_domain(cleaned)
    rss_query = quote_plus(f'"{target}" cybersecurity OR breach OR leak OR "data exposure"')
    url = f"https://news.google.com/rss/search?q={rss_query}&hl=en-IN&gl=IN&ceid=IN:en"
    request = Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; DarkIntel/1.0)"},
    )

    try:
        with urlopen(request, timeout=10) as response:
            payload = response.read()
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Live internet lookup failed: {exc}",
            "query": target,
            "results": [],
            "count": 0,
            "fetched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    try:
        root = ET.fromstring(payload)
    except ET.ParseError:
        return {
            "status": "error",
            "message": "Could not parse live intelligence feed.",
            "query": target,
            "results": [],
            "count": 0,
            "fetched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    channel = root.find("channel")
    items = channel.findall("item") if channel is not None else []
    results = [_format_article(item) for item in items[:limit]]

    return {
        "status": "ok",
        "query": target,
        "results": results,
        "count": len(results),
        "fetched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "disclaimer": "Live public internet results from Google News RSS.",
    }


def get_threat_actors() -> list:
    data = load_sim_data()
    return data.get("threat_actors", [])


def get_paste_sites() -> list:
    data = load_sim_data()
    return data.get("paste_sites", [])


def get_all_dark_web_leaks() -> list:
    data = load_sim_data()
    return data.get("leaked_credentials", [])


def get_dark_web_stats() -> dict:
    data = load_sim_data()
    leaks = data.get("leaked_credentials", [])
    actors = data.get("threat_actors", [])
    pastes = data.get("paste_sites", [])

    threat_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    total_emails = 0

    for leak in leaks:
        level = leak.get("threat_level", "Low")
        if level in threat_counts:
            threat_counts[level] += 1
        total_emails += len(leak.get("emails", []))

    total_posts = sum(p.get("posts_monitored", 0) for p in pastes)

    return {
        "total_leaks": len(leaks),
        "total_actors": len(actors),
        "total_paste_sites": len(pastes),
        "total_posts_monitored": total_posts,
        "total_emails_exposed": total_emails,
        "threat_level_breakdown": threat_counts,
        "last_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def explain_tor_architecture() -> dict:
    return {
        "tor_overview": (
            "The Onion Router (TOR) anonymizes internet traffic by encrypting "
            "data in multiple layers and routing it through a series of volunteer "
            "relay nodes. Each node decrypts one layer, revealing only the next hop."
        ),
        "layers": [
            {
                "layer": 1,
                "name": "Entry Guard Node",
                "role": "Knows the user's real IP but not the destination",
            },
            {
                "layer": 2,
                "name": "Middle Relay Node",
                "role": "Knows neither source nor destination",
            },
            {
                "layer": 3,
                "name": "Exit Node",
                "role": "Knows the destination but not the user's real IP",
            },
        ],
        "onion_services": (
            ".onion addresses are hidden services that exist only within TOR. "
            "They use 16 or 56-character addresses derived from public key cryptography."
        ),
        "academic_note": (
            "This project does NOT connect to TOR. All .onion references "
            "in this tool are clearly marked [SIMULATED] for academic safety."
        ),
    }
