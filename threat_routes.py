"""
threat_routes.py — Threat Intelligence Endpoints
==================================================
GET  /api/threats            — List threats (paginated, filterable)
GET  /api/threats/<id>       — Get single threat
POST /api/threats            — Manually add a threat
DELETE /api/threats/<id>     — Delete threat (admin only)
GET  /api/threats/search     — Full-text search
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from bson import ObjectId
from bson.errors import InvalidId

threat_bp = Blueprint("threats", __name__)

# ── Helpers ───────────────────────────────────────────────────────────────────

def serialize_threat(doc: dict) -> dict:
    """Convert MongoDB threat doc to JSON-safe dict."""
    return {
        "id":         str(doc["_id"]),
        "title":      doc.get("title", ""),
        "content":    doc.get("content", ""),
        "source":     doc.get("source", ""),
        "source_url": doc.get("source_url", ""),
        "category":   doc.get("category", ""),
        "severity":   doc.get("severity", "low"),
        "iocs":       doc.get("iocs", []),
        "tags":       doc.get("tags", []),
        "processed":  doc.get("processed", False),
        "created_at": doc["created_at"].isoformat() if doc.get("created_at") else None,
    }

VALID_SEVERITIES  = {"low", "medium", "high", "critical"}
VALID_CATEGORIES  = {"credential_leak", "malware_sale", "ransomware", "data_breach",
                     "forum_post", "exploit_sale", "phishing_kit", "zero_day"}


# ── List Threats ──────────────────────────────────────────────────────────────

@threat_bp.route("", methods=["GET"])
@jwt_required()
def list_threats():
    db = current_app.config["DB"]

    # Pagination
    page  = max(1, int(request.args.get("page", 1)))
    limit = min(100, max(1, int(request.args.get("limit", 20))))
    skip  = (page - 1) * limit

    # Filters
    query = {}
    severity = request.args.get("severity")
    category = request.args.get("category")
    source   = request.args.get("source")

    if severity and severity in VALID_SEVERITIES:
        query["severity"] = severity
    if category and category in VALID_CATEGORIES:
        query["category"] = category
    if source:
        query["source"] = source

    total  = db.threats.count_documents(query)
    cursor = db.threats.find(query).sort("created_at", -1).skip(skip).limit(limit)
    items  = [serialize_threat(t) for t in cursor]

    return jsonify({
        "data":       items,
        "total":      total,
        "page":       page,
        "limit":      limit,
        "totalPages": (total + limit - 1) // limit,
    }), 200


# ── Search Threats ────────────────────────────────────────────────────────────

@threat_bp.route("/search", methods=["GET"])
@jwt_required()
def search_threats():
    db    = current_app.config["DB"]
    query = request.args.get("q", "").strip()

    if not query or len(query) < 2:
        return jsonify({"error": "Search query must be at least 2 characters."}), 400

    # MongoDB full-text search on indexed title + content fields
    cursor = db.threats.find(
        {"$text": {"$search": query}},
        {"score": {"$meta": "textScore"}}
    ).sort([("score", {"$meta": "textScore"})]).limit(50)

    results = [serialize_threat(t) for t in cursor]
    return jsonify({"data": results, "count": len(results)}), 200


# ── Get Single Threat ─────────────────────────────────────────────────────────

@threat_bp.route("/<threat_id>", methods=["GET"])
@jwt_required()
def get_threat(threat_id):
    db = current_app.config["DB"]
    try:
        doc = db.threats.find_one({"_id": ObjectId(threat_id)})
    except InvalidId:
        return jsonify({"error": "Invalid threat ID."}), 400

    if not doc:
        return jsonify({"error": "Threat not found."}), 404
    return jsonify(serialize_threat(doc)), 200


# ── Create Threat (manual entry) ─────────────────────────────────────────────

@threat_bp.route("", methods=["POST"])
@jwt_required()
def create_threat():
    db   = current_app.config["DB"]
    data = request.get_json(silent=True) or {}

    title    = data.get("title", "").strip()
    content  = data.get("content", "").strip()
    severity = data.get("severity", "medium")
    category = data.get("category", "forum_post")

    if not title:
        return jsonify({"error": "Title is required."}), 400
    if severity not in VALID_SEVERITIES:
        return jsonify({"error": f"Severity must be one of {VALID_SEVERITIES}."}), 400
    if category not in VALID_CATEGORIES:
        return jsonify({"error": f"Category must be one of {VALID_CATEGORIES}."}), 400

    from models import new_threat
    doc = new_threat(
        title      = title,
        content    = content,
        source     = "manual",
        source_url = data.get("source_url", ""),
        category   = category,
        severity   = severity,
        iocs       = data.get("iocs", []),
        tags       = data.get("tags", []),
    )
    result = db.threats.insert_one(doc)
    doc["_id"] = result.inserted_id
    return jsonify(serialize_threat(doc)), 201


# ── Delete Threat (admin only) ────────────────────────────────────────────────

@threat_bp.route("/<threat_id>", methods=["DELETE"])
@jwt_required()
def delete_threat(threat_id):
    db      = current_app.config["DB"]
    user_id = get_jwt_identity()

    # Role check
    from bson import ObjectId
    user = db.users.find_one({"_id": ObjectId(user_id)})
    if not user or user.get("role") != "admin":
        return jsonify({"error": "Admin access required."}), 403

    try:
        result = db.threats.delete_one({"_id": ObjectId(threat_id)})
    except InvalidId:
        return jsonify({"error": "Invalid threat ID."}), 400

    if result.deleted_count == 0:
        return jsonify({"error": "Threat not found."}), 404
    return jsonify({"message": "Deleted."}), 200
