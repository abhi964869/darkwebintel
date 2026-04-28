"""
alert_routes.py — Alert & Keyword Management Endpoints
=======================================================
Alerts:
  GET  /api/alerts                 — List alerts for current user
  PATCH /api/alerts/<id>/ack       — Acknowledge an alert
  PATCH /api/alerts/<id>/dismiss   — Dismiss an alert

Keywords:
  GET  /api/alerts/keywords        — List user's monitored keywords
  POST /api/alerts/keywords        — Add keyword / IOC
  DELETE /api/alerts/keywords/<id> — Remove keyword
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from bson import ObjectId
from bson.errors import InvalidId
from models import new_keyword, utcnow

alert_bp = Blueprint("alerts", __name__)


def serialize_alert(doc: dict) -> dict:
    return {
        "id":              str(doc["_id"]),
        "threat_id":       str(doc.get("threat_id", "")),
        "keyword":         doc.get("keyword", ""),
        "severity":        doc.get("severity", "low"),
        "status":          doc.get("status", "new"),
        "context_snippet": doc.get("context_snippet", ""),
        "created_at":      doc["created_at"].isoformat() if doc.get("created_at") else None,
        "acknowledged_at": doc["acknowledged_at"].isoformat() if doc.get("acknowledged_at") else None,
    }

def serialize_keyword(doc: dict) -> dict:
    return {
        "id":         str(doc["_id"]),
        "keyword":    doc.get("keyword", ""),
        "category":   doc.get("category", "general"),
        "is_regex":   doc.get("is_regex", False),
        "active":     doc.get("active", True),
        "hit_count":  doc.get("hit_count", 0),
        "created_at": doc["created_at"].isoformat() if doc.get("created_at") else None,
    }


# ── List Alerts ───────────────────────────────────────────────────────────────

@alert_bp.route("", methods=["GET"])
@jwt_required()
def list_alerts():
    db      = current_app.config["DB"]
    user_id = get_jwt_identity()

    # Filters
    status   = request.args.get("status")     # "new" | "acknowledged" | "dismissed"
    severity = request.args.get("severity")
    page     = max(1, int(request.args.get("page", 1)))
    limit    = min(100, int(request.args.get("limit", 20)))
    skip     = (page - 1) * limit

    query = {"user_id": ObjectId(user_id)}
    if status   in {"new", "acknowledged", "dismissed"}:
        query["status"] = status
    if severity in {"low", "medium", "high", "critical"}:
        query["severity"] = severity

    total  = db.alerts.count_documents(query)
    cursor = db.alerts.find(query).sort("created_at", -1).skip(skip).limit(limit)
    items  = [serialize_alert(a) for a in cursor]

    return jsonify({"data": items, "total": total, "page": page}), 200


# ── Acknowledge Alert ─────────────────────────────────────────────────────────

@alert_bp.route("/<alert_id>/ack", methods=["PATCH"])
@jwt_required()
def acknowledge_alert(alert_id):
    db      = current_app.config["DB"]
    user_id = get_jwt_identity()
    try:
        result = db.alerts.update_one(
            {"_id": ObjectId(alert_id), "user_id": ObjectId(user_id)},
            {"$set": {"status": "acknowledged", "acknowledged_at": utcnow()}}
        )
    except InvalidId:
        return jsonify({"error": "Invalid alert ID."}), 400

    if result.matched_count == 0:
        return jsonify({"error": "Alert not found."}), 404
    return jsonify({"message": "Alert acknowledged."}), 200


# ── Dismiss Alert ─────────────────────────────────────────────────────────────

@alert_bp.route("/<alert_id>/dismiss", methods=["PATCH"])
@jwt_required()
def dismiss_alert(alert_id):
    db      = current_app.config["DB"]
    user_id = get_jwt_identity()
    try:
        result = db.alerts.update_one(
            {"_id": ObjectId(alert_id), "user_id": ObjectId(user_id)},
            {"$set": {"status": "dismissed"}}
        )
    except InvalidId:
        return jsonify({"error": "Invalid alert ID."}), 400

    if result.matched_count == 0:
        return jsonify({"error": "Alert not found."}), 404
    return jsonify({"message": "Alert dismissed."}), 200


# ── List Keywords ─────────────────────────────────────────────────────────────

@alert_bp.route("/keywords", methods=["GET"])
@jwt_required()
def list_keywords():
    db      = current_app.config["DB"]
    user_id = get_jwt_identity()

    keywords = list(db.keywords.find({"user_id": ObjectId(user_id)}).sort("created_at", -1))
    return jsonify({"data": [serialize_keyword(k) for k in keywords]}), 200


# ── Add Keyword ───────────────────────────────────────────────────────────────

@alert_bp.route("/keywords", methods=["POST"])
@jwt_required()
def add_keyword():
    db      = current_app.config["DB"]
    user_id = get_jwt_identity()
    data    = request.get_json(silent=True) or {}

    keyword  = data.get("keyword", "").strip()
    category = data.get("category", "general")
    is_regex = bool(data.get("is_regex", False))

    if not keyword or len(keyword) < 2:
        return jsonify({"error": "Keyword must be at least 2 characters."}), 400

    # Prevent duplicates per user
    if db.keywords.find_one({"user_id": ObjectId(user_id), "keyword": keyword.lower()}):
        return jsonify({"error": "Keyword already exists."}), 409

    # Validate regex if provided
    if is_regex:
        import re
        try:
            re.compile(keyword)
        except re.error:
            return jsonify({"error": "Invalid regular expression."}), 400

    kw_doc = new_keyword(
        user_id  = ObjectId(user_id),
        keyword  = keyword,
        category = category,
        is_regex = is_regex,
    )
    result = db.keywords.insert_one(kw_doc)
    kw_doc["_id"] = result.inserted_id
    return jsonify(serialize_keyword(kw_doc)), 201


# ── Delete Keyword ────────────────────────────────────────────────────────────

@alert_bp.route("/keywords/<kw_id>", methods=["DELETE"])
@jwt_required()
def delete_keyword(kw_id):
    db      = current_app.config["DB"]
    user_id = get_jwt_identity()
    try:
        result = db.keywords.delete_one(
            {"_id": ObjectId(kw_id), "user_id": ObjectId(user_id)}
        )
    except InvalidId:
        return jsonify({"error": "Invalid keyword ID."}), 400

    if result.deleted_count == 0:
        return jsonify({"error": "Keyword not found."}), 404
    return jsonify({"message": "Keyword removed."}), 200
