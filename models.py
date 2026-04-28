"""
models.py — MongoDB document schemas
=====================================
All document structures used in the dark_web_intel database.

Collections:
  - threats       : scraped / ingested threat entries
  - alerts        : generated alerts for matching keywords
  - keywords      : monitored keywords / IOCs per user
  - users         : registered analyst accounts
  - audit_logs    : action history for compliance
"""

from datetime import datetime, timezone
from bson import ObjectId


# ──────────────────────────────────────────────────────────────────────────────
# Helper
# ──────────────────────────────────────────────────────────────────────────────

def utcnow():
    """Timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


# ──────────────────────────────────────────────────────────────────────────────
# Threat Document
# ──────────────────────────────────────────────────────────────────────────────

def new_threat(
    title: str,
    content: str,
    source: str,
    source_url: str,
    category: str,        # e.g. "credential_leak", "malware", "forum_post"
    severity: str,        # "low" | "medium" | "high" | "critical"
    iocs: list[str] = (), # Indicators of Compromise (IPs, emails, hashes)
    tags: list[str] = (),
    raw_html: str = ""
) -> dict:
    """
    Returns a new threat document ready for MongoDB insertion.
    """
    return {
        "title":       title,
        "content":     content[:5000],   # Truncate to avoid giant docs
        "source":      source,           # e.g. "tor_forum", "pastebin_sim"
        "source_url":  source_url,
        "category":    category,
        "severity":    severity,
        "iocs":        list(iocs),
        "tags":        list(tags),
        "raw_html":    raw_html,
        "processed":   False,            # Set True after keyword matching
        "created_at":  utcnow(),
        "updated_at":  utcnow(),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Alert Document
# ──────────────────────────────────────────────────────────────────────────────

def new_alert(
    threat_id: ObjectId,
    keyword: str,
    user_id: ObjectId,
    severity: str,
    context_snippet: str = ""
) -> dict:
    """
    Alert generated when a threat matches a monitored keyword.
    """
    return {
        "threat_id":       threat_id,
        "keyword":         keyword,
        "user_id":         user_id,
        "severity":        severity,
        "context_snippet": context_snippet[:500],
        "status":          "new",       # "new" | "acknowledged" | "dismissed"
        "created_at":      utcnow(),
        "acknowledged_at": None,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Keyword Document
# ──────────────────────────────────────────────────────────────────────────────

def new_keyword(
    user_id: ObjectId,
    keyword: str,
    category: str = "general",   # "brand", "domain", "email", "hash", "general"
    is_regex: bool = False,
    active: bool = True
) -> dict:
    """
    A monitored keyword or IOC pattern belonging to a user.
    """
    return {
        "user_id":    user_id,
        "keyword":    keyword.strip().lower(),
        "category":   category,
        "is_regex":   is_regex,
        "active":     active,
        "hit_count":  0,
        "created_at": utcnow(),
    }


# ──────────────────────────────────────────────────────────────────────────────
# User Document
# ──────────────────────────────────────────────────────────────────────────────

def new_user(
    username: str,
    email: str,
    password_hash: str,
    role: str = "analyst"   # "analyst" | "admin"
) -> dict:
    """
    Analyst / admin account. Passwords are ALWAYS stored as bcrypt hashes.
    """
    return {
        "username":      username.strip(),
        "email":         email.strip().lower(),
        "password_hash": password_hash,
        "role":          role,
        "is_active":     True,
        "last_login":    None,
        "created_at":    utcnow(),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Audit Log Document
# ──────────────────────────────────────────────────────────────────────────────

def new_audit_log(
    user_id: ObjectId,
    action: str,         # e.g. "login", "create_keyword", "dismiss_alert"
    resource: str = "",  # e.g. "threat:abc123"
    ip_address: str = "",
    detail: str = ""
) -> dict:
    """
    Append-only audit trail for compliance and forensics.
    """
    return {
        "user_id":    user_id,
        "action":     action,
        "resource":   resource,
        "ip_address": ip_address,
        "detail":     detail,
        "created_at": utcnow(),
    }


# ──────────────────────────────────────────────────────────────────────────────
# MongoDB Index Definitions
# Call this once at startup to ensure performance + uniqueness
# ──────────────────────────────────────────────────────────────────────────────

def ensure_indexes(db):
    """Create all required MongoDB indexes."""
    # Threats: fast lookup by severity and date
    db.threats.create_index([("severity", 1), ("created_at", -1)])
    db.threats.create_index([("category", 1)])
    db.threats.create_index([("processed", 1)])

    # Full-text search on content + title
    db.threats.create_index([("title", "text"), ("content", "text")])

    # Alerts: per-user queries
    db.alerts.create_index([("user_id", 1), ("status", 1), ("created_at", -1)])
    db.alerts.create_index([("threat_id", 1)])

    # Keywords: per-user active lookups
    db.keywords.create_index([("user_id", 1), ("active", 1)])
    db.keywords.create_index([("keyword", 1)])

    # Users: unique constraint on email + username
    db.users.create_index("email",    unique=True)
    db.users.create_index("username", unique=True)

    # Audit log: append-only, queried by user and date
    db.audit_logs.create_index([("user_id", 1), ("created_at", -1)])
