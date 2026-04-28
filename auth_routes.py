"""
auth_routes.py — Authentication Endpoints
==========================================
POST /api/auth/register  — Create analyst account
POST /api/auth/login     — Obtain JWT access token
GET  /api/auth/me        — Return current user profile
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import bcrypt
import re
from models import new_user

auth_bp = Blueprint("auth", __name__)

# ── Helpers ───────────────────────────────────────────────────────────────────

def valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))

def hash_password(plain: str) -> str:
    """bcrypt-hash a plaintext password."""
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def check_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def serialize_user(doc: dict) -> dict:
    """Return safe public fields (never expose password_hash)."""
    return {
        "id":         str(doc["_id"]),
        "username":   doc["username"],
        "email":      doc["email"],
        "role":       doc["role"],
        "created_at": doc["created_at"].isoformat(),
    }


# ── Register ──────────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["POST"])
def register():
    db   = current_app.config["DB"]
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    email    = data.get("email",    "").strip().lower()
    password = data.get("password", "")

    # Input validation
    if not username or len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters."}), 400
    if not valid_email(email):
        return jsonify({"error": "Invalid email address."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    if db.users.find_one({"email": email}):
        return jsonify({"error": "Email already registered."}), 409
    if db.users.find_one({"username": username}):
        return jsonify({"error": "Username taken."}), 409

    user = new_user(
        username      = username,
        email         = email,
        password_hash = hash_password(password),
        role          = "analyst",
    )
    result = db.users.insert_one(user)
    user["_id"] = result.inserted_id

    token = create_access_token(identity=str(result.inserted_id))
    return jsonify({"token": token, "user": serialize_user(user)}), 201


# ── Login ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["POST"])
def login():
    db   = current_app.config["DB"]
    data = request.get_json(silent=True) or {}

    email    = data.get("email",    "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    user = db.users.find_one({"email": email, "is_active": True})
    if not user or not check_password(password, user["password_hash"]):
        # Vague message — don't reveal which field was wrong
        return jsonify({"error": "Invalid credentials."}), 401

    from models import utcnow
    db.users.update_one({"_id": user["_id"]}, {"$set": {"last_login": utcnow()}})

    token = create_access_token(identity=str(user["_id"]))
    return jsonify({"token": token, "user": serialize_user(user)}), 200


# ── Profile ───────────────────────────────────────────────────────────────────

@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    db      = current_app.config["DB"]
    user_id = get_jwt_identity()
    from bson import ObjectId
    user = db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "User not found."}), 404
    return jsonify(serialize_user(user)), 200
