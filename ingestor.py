"""
ingestor.py — Simulated Dark Web Data Ingestor
================================================
Since direct Tor access is restricted in most lab/classroom environments,
this module simulates realistic dark web threat data:

  1. SIMULATED MODE  — Generates randomised but realistic threat entries.
  2. PASTEBIN MODE   — Scrapes public Pastebin pastes (no Tor needed).
  3. TOR MODE        — Real Tor scraping via requests[socks] (advanced).

Run standalone:  python ingestor.py --mode simulated --count 50
                 python ingestor.py --mode pastebin
Schedule it:     Use APScheduler or cron to run every N minutes.
"""

import random
import re
import time
import argparse
import logging
from datetime import datetime, timezone, timedelta
from pymongo import MongoClient
from models import new_threat, ensure_indexes

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ──────────────────────────────────────────────────────────────────────────────
# Simulated Threat Data Pools
# ──────────────────────────────────────────────────────────────────────────────

CATEGORIES = ["credential_leak", "malware_sale", "ransomware", "data_breach",
              "forum_post", "exploit_sale", "phishing_kit", "zero_day"]

SOURCES = ["tor_forum_alpha", "tor_forum_beta", "pastebin_sim",
           "breach_db_sim", "marketplace_sim"]

SEVERITY_WEIGHTS = {
    "low":      0.35,
    "medium":   0.30,
    "high":     0.25,
    "critical": 0.10,
}

FAKE_DOMAINS = [
    "corp-example.com", "acme-internal.net", "globalbank.io",
    "techcorp.org",     "financehub.com",    "medicaldata.net",
]

FAKE_ORGS = [
    "Acme Corporation", "GlobalBank Ltd", "TechCorp Inc",
    "HealthFirst",      "FinanceHub",     "RetailGiant",
]

TITLE_TEMPLATES = [
    "Fresh {count}k credentials from {org} — {date}",
    "Full DB dump: {domain} users and passwords",
    "0day exploit for {product} v{ver} — working PoC",
    "Ransomware affiliate program — {pct}% revenue share",
    "Phishing kit for {bank} — updated {date}",
    "CC dump: {count}k cards from {region} banks",
    "Source code leak: {org} internal repository",
    "Corporate VPN credentials — {org} ({count} accounts)",
    "Malware-as-a-service: {malware} loader — new build",
    "Data breach: {domain} — {count}k records",
]

CONTENT_TEMPLATES = [
    """We are selling a fresh database dump from {org}. 
The data includes usernames, bcrypt hashed passwords, email addresses, and in some cases 
plain-text passwords from users who reused them elsewhere. Total {count}k rows.
Contact via Jabber: seller_{handle}@exploit.im
Price: {price} BTC for full dump, {sample_price} BTC for 1k sample.""",

    """Selling working exploit for {product}. Tested on versions {ver_min}–{ver_max}.
Allows unauthenticated RCE. PoC available for verified buyers.
Requirements: basic Linux knowledge, no AV on target recommended.
Price negotiable. Escrow accepted.""",

    """URGENT — selling {count}k fullz (SSN+DOB+CC) from {region}.
Fresh from Q{quarter} {year}. High validity rate, tested {valid_pct}%.
Bulk discounts available. Crypto only.""",

    """New phishing page for {bank}. Includes:
- Realistic login clone
- OTP bypass (MFA capture)
- Cookie stealer
- Admin panel for real-time victim monitoring
Price: {price} BTC/month licence. DM for demo.""",

    """Ransomware group {group} announces new affiliate program.
{pct}% revenue split. Decryptor guaranteed after payment.
Targets: English-speaking countries, healthcare / finance / logistics.
Contact our support bot on Telegram: @{tg_handle}""",
]

MALWARE_NAMES = ["LockBit", "BlackCat", "Cl0p", "Redline", "Emotet",
                 "IcedID", "Cobalt Strike", "Vidar", "Snake"]
PRODUCTS      = ["Apache HTTP Server", "Microsoft Exchange", "Cisco IOS",
                 "OpenSSL", "WordPress Plugin", "VMware ESXi"]
REGIONS       = ["EU", "North America", "APAC", "LATAM", "Middle East"]
BANKS         = ["GlobalBank", "FinCorp", "TrustSavings", "EuroCredit"]


def random_iocs(n: int = 3) -> list[str]:
    """Generate fake but format-valid IOCs (IPs, emails, MD5 hashes)."""
    iocs = []
    for _ in range(n):
        kind = random.choice(["ip", "email", "hash"])
        if kind == "ip":
            iocs.append(f"{random.randint(1,254)}.{random.randint(0,254)}"
                        f".{random.randint(0,254)}.{random.randint(1,254)}")
        elif kind == "email":
            handle = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=8))
            iocs.append(f"{handle}@{random.choice(FAKE_DOMAINS)}")
        else:
            iocs.append("".join(random.choices("0123456789abcdef", k=32)))
    return iocs


def pick_severity() -> str:
    """Weighted random severity selection."""
    pool = []
    for sev, weight in SEVERITY_WEIGHTS.items():
        pool.extend([sev] * int(weight * 100))
    return random.choice(pool)


def generate_simulated_threat() -> dict:
    """Build one realistic simulated threat document."""
    org      = random.choice(FAKE_ORGS)
    domain   = random.choice(FAKE_DOMAINS)
    product  = random.choice(PRODUCTS)
    malware  = random.choice(MALWARE_NAMES)
    bank     = random.choice(BANKS)
    region   = random.choice(REGIONS)
    count    = random.choice([10, 50, 100, 250, 500, 1000])
    quarter  = random.randint(1, 4)
    year     = random.randint(2023, 2025)
    ver      = f"{random.randint(2,8)}.{random.randint(0,9)}.{random.randint(0,9)}"
    handle   = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=8))
    pct      = random.randint(60, 85)
    tg_handle= "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=10)) + "_bot"
    price    = round(random.uniform(0.1, 2.5), 3)

    title_tpl   = random.choice(TITLE_TEMPLATES)
    content_tpl = random.choice(CONTENT_TEMPLATES)

    fmtargs = dict(
        org=org, domain=domain, product=product, malware=malware, bank=bank,
        region=region, count=count, quarter=quarter, year=year, ver=ver,
        ver_min=ver, ver_max=ver, handle=handle, pct=pct, tg_handle=tg_handle,
        price=price, sample_price=round(price/10, 4), valid_pct=random.randint(70,95),
        group=malware, date=datetime.now().strftime("%Y-%m"),
        valid_count=int(count * 0.9), total_count=count
    )

    title   = title_tpl.format_map(fmtargs)
    content = content_tpl.format_map(fmtargs)

    return new_threat(
        title      = title,
        content    = content,
        source     = random.choice(SOURCES),
        source_url = f"http://{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=12))}.onion/post/{random.randint(1000,9999)}",
        category   = random.choice(CATEGORIES),
        severity   = pick_severity(),
        iocs       = random_iocs(random.randint(1, 5)),
        tags       = random.sample(["leaked", "fresh", "bulk", "verified", "exclusive"], k=random.randint(1, 3)),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Pastebin Public Scraper (no Tor needed — uses public API)
# ──────────────────────────────────────────────────────────────────────────────

def scrape_pastebin_public(limit: int = 10) -> list[dict]:
    """
    Fetch recent public Pastebin pastes that may contain credential patterns.
    Uses Pastebin's public scraping API — no key required for public pastes.

    NOTE: For classroom use, this is safe and legal.
          For production, apply for a Pastebin Pro API key.
    """
    try:
        import requests
    except ImportError:
        logger.error("Install requests: pip install requests")
        return []

    threats = []
    try:
        # Public recent pastes list (no auth needed)
        resp = requests.get(
            "https://scrape.pastebin.com/api_scraping.php?limit=" + str(limit),
            timeout=10
        )
        if resp.status_code != 200:
            logger.warning(f"Pastebin API returned {resp.status_code}")
            return []

        items = resp.json()

        # Patterns that indicate potential threat data
        SUSPICIOUS_PATTERNS = [
            r"password",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # email
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",                             # IP
            r"[0-9a-f]{32}",                                             # MD5
            r"credit.?card|cvv|expir",
            r"ssn|social.security",
        ]

        for item in items:
            raw_url = item.get("scrape_url", "")
            key     = item.get("key", "")

            raw_resp = requests.get(raw_url, timeout=5)
            if raw_resp.status_code != 200:
                continue

            text = raw_resp.text[:5000]
            matched = [p for p in SUSPICIOUS_PATTERNS if re.search(p, text, re.IGNORECASE)]

            if not matched:
                continue   # Skip non-suspicious pastes

            severity = "critical" if len(matched) > 3 else \
                       "high"     if len(matched) > 1 else "medium"

            iocs = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)[:5]

            threats.append(new_threat(
                title      = item.get("title") or f"Pastebin paste {key}",
                content    = text,
                source     = "pastebin_live",
                source_url = f"https://pastebin.com/{key}",
                category   = "credential_leak",
                severity   = severity,
                iocs       = iocs,
                tags       = ["pastebin", "auto-detected"],
            ))
            time.sleep(0.5)   # Be polite to the API

    except Exception as e:
        logger.error(f"Pastebin scrape error: {e}")

    return threats


# ──────────────────────────────────────────────────────────────────────────────
# Tor Scraper (Advanced — requires Tor running on 127.0.0.1:9050)
# ──────────────────────────────────────────────────────────────────────────────

def scrape_via_tor(onion_urls: list[str]) -> list[dict]:
    """
    Fetch .onion pages through Tor.

    Prerequisites:
      pip install requests[socks] PySocks
      systemctl start tor   (Linux)
      brew services start tor  (macOS)

    WARNING: Only scrape sites you have legal authorisation to access.
             This function is provided for educational simulation purposes.
    """
    try:
        import requests
    except ImportError:
        logger.error("pip install requests[socks]")
        return []

    session = requests.Session()
    session.proxies = {
        "http":  "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050",
    }
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; ThreatIntel/1.0)"

    threats = []
    for url in onion_urls:
        try:
            resp = session.get(url, timeout=20)
            resp.raise_for_status()
            threats.append(new_threat(
                title    = url,
                content  = resp.text[:5000],
                source   = "tor_live",
                source_url = url,
                category = "forum_post",
                severity = "medium",
            ))
            logger.info(f"Scraped: {url}")
            time.sleep(2)   # Rate limit — don't hammer .onion sites
        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")

    return threats


# ──────────────────────────────────────────────────────────────────────────────
# Keyword Matcher — runs after ingestion
# ──────────────────────────────────────────────────────────────────────────────

def match_keywords(db, threat: dict, threat_id) -> int:
    """
    Compare a threat's title + content against all active keywords.
    Creates an Alert document for each match.
    Returns the number of alerts created.
    """
    from models import new_alert
    from bson import ObjectId

    text = (threat.get("title", "") + " " + threat.get("content", "")).lower()
    alerts_created = 0

    keywords = list(db.keywords.find({"active": True}))
    for kw_doc in keywords:
        keyword   = kw_doc["keyword"]
        is_regex  = kw_doc.get("is_regex", False)

        if is_regex:
            match = bool(re.search(keyword, text, re.IGNORECASE))
        else:
            match = keyword in text

        if match:
            # Extract a small snippet around the match
            idx = text.find(keyword) if not is_regex else 0
            snippet = text[max(0, idx-50): idx+100].strip()

            alert = new_alert(
                threat_id       = ObjectId(threat_id),
                keyword         = kw_doc["keyword"],
                user_id         = kw_doc["user_id"],
                severity        = threat["severity"],
                context_snippet = snippet,
            )
            db.alerts.insert_one(alert)

            # Increment keyword hit counter
            db.keywords.update_one({"_id": kw_doc["_id"]}, {"$inc": {"hit_count": 1}})
            alerts_created += 1

    # Mark threat as processed
    from bson import ObjectId
    db.threats.update_one({"_id": ObjectId(threat_id)}, {"$set": {"processed": True}})
    return alerts_created


# ──────────────────────────────────────────────────────────────────────────────
# CLI Runner
# ──────────────────────────────────────────────────────────────────────────────

def run_ingestor(mode: str = "simulated", count: int = 20, mongo_uri: str = "mongodb://localhost:27017/dark_web_intel"):
    client = MongoClient(mongo_uri)
    db     = client["dark_web_intel"]
    ensure_indexes(db)

    if mode == "simulated":
        threats = [generate_simulated_threat() for _ in range(count)]
        logger.info(f"Generated {len(threats)} simulated threats.")

    elif mode == "pastebin":
        threats = scrape_pastebin_public(limit=count)
        logger.info(f"Scraped {len(threats)} Pastebin threats.")

    else:
        logger.error(f"Unknown mode: {mode}")
        return

    inserted = 0
    for threat in threats:
        result = db.threats.insert_one(threat)
        alerts = match_keywords(db, threat, result.inserted_id)
        inserted += 1
        if inserted % 10 == 0:
            logger.info(f"Inserted {inserted}/{len(threats)}, alerts: {alerts}")

    logger.info(f"Ingestion complete. {inserted} threats inserted.")
    client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dark Web Threat Ingestor")
    parser.add_argument("--mode",  choices=["simulated", "pastebin", "tor"],
                        default="simulated")
    parser.add_argument("--count", type=int, default=20,
                        help="Number of threats to ingest")
    parser.add_argument("--mongo", default="mongodb://localhost:27017/dark_web_intel",
                        help="MongoDB connection URI")
    args = parser.parse_args()
    run_ingestor(mode=args.mode, count=args.count, mongo_uri=args.mongo)
