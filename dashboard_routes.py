"""
dashboard_routes.py — Dashboard Aggregation Endpoints
======================================================
GET /api/dashboard/stats        — Overview counts and severity breakdown
GET /api/dashboard/trends       — Threats-per-day over last 30 days
GET /api/dashboard/top-iocs     — Most frequently seen IOCs
GET /api/dashboard/categories   — Threat counts by category
"""

from flask import Blueprint, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from bson import ObjectId
from datetime import datetime, timezone, timedelta

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/stats", methods=["GET"])
@jwt_required()
def stats():
    """High-level summary card data."""
    db      = current_app.config["DB"]
    user_id = get_jwt_identity()

    total_threats = db.threats.count_documents({})
    critical      = db.threats.count_documents({"severity": "critical"})
    high          = db.threats.count_documents({"severity": "high"})
    new_alerts    = db.alerts.count_documents({"user_id": ObjectId(user_id), "status": "new"})

    # Threats added in the last 24 hours
    since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    recent    = db.threats.count_documents({"created_at": {"$gte": since_24h}})

    return jsonify({
        "total_threats": total_threats,
        "critical":      critical,
        "high":          high,
        "new_alerts":    new_alerts,
        "last_24h":      recent,
    }), 200


@dashboard_bp.route("/trends", methods=["GET"])
@jwt_required()
def trends():
    """Return daily threat counts for the past 30 days."""
    db    = current_app.config["DB"]
    since = datetime.now(timezone.utc) - timedelta(days=30)

    pipeline = [
        {"$match": {"created_at": {"$gte": since}}},
        {"$group": {
            "_id": {
                "year":  {"$year":  "$created_at"},
                "month": {"$month": "$created_at"},
                "day":   {"$dayOfMonth": "$created_at"},
            },
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id.year": 1, "_id.month": 1, "_id.day": 1}},
    ]

    rows = list(db.threats.aggregate(pipeline))
    data = []
    for row in rows:
        d = row["_id"]
        data.append({
            "date":  f"{d['year']}-{d['month']:02d}-{d['day']:02d}",
            "count": row["count"],
        })

    return jsonify({"data": data}), 200


@dashboard_bp.route("/categories", methods=["GET"])
@jwt_required()
def categories():
    """Threat count grouped by category."""
    db = current_app.config["DB"]

    pipeline = [
        {"$group": {"_id": "$category", "count": {"$sum": 1}}},
        {"$sort":  {"count": -1}},
    ]

    rows = list(db.threats.aggregate(pipeline))
    data = [{"category": r["_id"], "count": r["count"]} for r in rows]
    return jsonify({"data": data}), 200


@dashboard_bp.route("/top-iocs", methods=["GET"])
@jwt_required()
def top_iocs():
    """Most common IOCs across all threats (top 20)."""
    db = current_app.config["DB"]

    pipeline = [
        {"$unwind": "$iocs"},
        {"$group": {"_id": "$iocs", "count": {"$sum": 1}}},
        {"$sort":  {"count": -1}},
        {"$limit": 20},
    ]

    rows = list(db.threats.aggregate(pipeline))
    data = [{"ioc": r["_id"], "count": r["count"]} for r in rows]
    return jsonify({"data": data}), 200
