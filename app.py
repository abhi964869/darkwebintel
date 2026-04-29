import base64
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, g, jsonify, render_template, request, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash

from database import get_connection, init_db
from modules.alert_system import create_alert, generate_pdf_report, get_alert_stats, get_all_alerts
from modules.credential_monitor import check_domain, check_email, get_recent_threats
from modules.dark_web_sim import (
    explain_tor_architecture,
    fetch_live_intel,
    get_all_dark_web_leaks,
    get_dark_web_stats,
    get_paste_sites,
    get_threat_actors,
    scan_dark_web_for_email,
)
from modules.data_collector import get_all_breaches, get_breach_stats, ingest_breach_data
from modules.risk_engine import assess_email_risk, calculate_risk_score, get_all_assessments, get_risk_distribution

BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"
SESSION_TTL_DAYS = 14

app = Flask(__name__)


def serve_frontend():
    if PUBLIC_DIR.joinpath("index.html").exists():
        return send_from_directory(PUBLIC_DIR, "index.html")
    return render_template("dashboard.html")


def bootstrap_runtime():
    init_db()

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) AS total FROM breaches")
    has_breaches = (cursor.fetchone()["total"] or 0) > 0
    conn.close()

    if not has_breaches:
        ingest_breach_data()


def serialize_user(row):
    return {
        "id": row["id"],
        "full_name": row["full_name"],
        "email": row["email"],
        "company": row["company"],
        "plan_name": row["plan_name"],
        "created_at": row["created_at"],
        "last_login_at": row["last_login_at"],
    }


def get_bearer_token():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    return header.split(" ", 1)[1].strip()


def get_current_user():
    token = get_bearer_token()
    if not token:
        return None

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT u.*, s.expires_at
        FROM user_sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ? AND u.is_active = 1
        """,
        (token,),
    )
    user = cursor.fetchone()
    conn.close()

    if not user:
        return None

    try:
        expires_at = datetime.fromisoformat(user["expires_at"])
    except ValueError:
        return None

    if expires_at <= datetime.now(timezone.utc):
        return None
    return user


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required."}), 401
        g.current_user = user
        return fn(*args, **kwargs)

    return wrapper


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + timedelta(days=SESSION_TTL_DAYS)).isoformat()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO user_sessions (user_id, token, expires_at) VALUES (?, ?, ?)",
        (user_id, token, expires_at),
    )
    conn.commit()
    conn.close()
    return token


def maybe_get_authenticated_user():
    user = get_current_user()
    if user:
        g.current_user = user
    return user


def save_lookup_history(user_id, query_value, payload):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO lookup_history (user_id, query_value, source, result_count, payload_json)
        VALUES (?, ?, 'internet', ?, ?)
        """,
        (
            user_id,
            query_value,
            int(payload.get("count", 0)),
            json.dumps(payload),
        ),
    )
    conn.commit()
    conn.close()


def save_report(user_id, email, assessment_payload):
    conn = get_connection()
    cursor = conn.cursor()
    risk = assessment_payload["risk_assessment"]
    cursor.execute(
        """
        INSERT INTO saved_reports (user_id, target_email, risk_label, score, summary, payload_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            email,
            risk.get("risk_label", "Low"),
            int(risk.get("total_score", 0)),
            risk.get("summary", ""),
            json.dumps(assessment_payload),
        ),
    )
    conn.commit()
    conn.close()


bootstrap_runtime()


@app.route("/")
def index():
    if os.environ.get("VERCEL"):
        return "", 404
    return serve_frontend()


@app.route("/flask")
def flask_index():
    return render_template("dashboard.html")


@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    data = request.get_json() or {}
    full_name = data.get("full_name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    company = data.get("company", "").strip()

    if len(full_name) < 2:
        return jsonify({"error": "Full name must be at least 2 characters."}), 400
    if "@" not in email:
        return jsonify({"error": "A valid email is required."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"error": "Email is already registered."}), 409

    cursor.execute(
        """
        INSERT INTO users (full_name, email, password_hash, company)
        VALUES (?, ?, ?, ?)
        """,
        (full_name, email, generate_password_hash(password), company),
    )
    user_id = cursor.lastrowid
    conn.commit()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    token = create_session(user_id)
    return jsonify({"token": token, "user": serialize_user(user)}), 201


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ? AND is_active = 1", (email,))
    user = cursor.fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        conn.close()
        return jsonify({"error": "Invalid email or password."}), 401

    now_iso = datetime.now(timezone.utc).isoformat()
    cursor.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now_iso, user["id"]))
    conn.commit()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user["id"],))
    user = cursor.fetchone()
    conn.close()

    token = create_session(user["id"])
    return jsonify({"token": token, "user": serialize_user(user)}), 200


@app.route("/api/auth/me")
@auth_required
def auth_me():
    return jsonify(serialize_user(g.current_user))


@app.route("/api/auth/logout", methods=["POST"])
@auth_required
def auth_logout():
    token = get_bearer_token()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM user_sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/ingest")
def trigger_ingestion():
    return jsonify(ingest_breach_data())


@app.route("/api/breaches")
def api_breaches():
    return jsonify(get_all_breaches())


@app.route("/api/stats")
def api_stats():
    return jsonify(get_breach_stats())


@app.route("/search")
@app.route("/flask/search")
def search_page():
    return render_template("search.html")


@app.route("/api/check/email", methods=["POST"])
def api_check_email():
    data = request.get_json() or {}
    email = data.get("email", "").strip()
    return jsonify(check_email(email))


@app.route("/api/check/domain", methods=["POST"])
def api_check_domain():
    data = request.get_json() or {}
    domain = data.get("domain", "").strip()
    return jsonify(check_domain(domain))


@app.route("/api/threats/recent")
def api_recent_threats():
    return jsonify(get_recent_threats())


@app.route("/darkweb")
@app.route("/flask/darkweb")
def darkweb_page():
    return render_template("darkweb.html")


@app.route("/api/darkweb/scan", methods=["POST"])
def api_darkweb_scan():
    data = request.get_json() or {}
    email = data.get("email", "").strip()
    return jsonify(scan_dark_web_for_email(email))


@app.route("/api/darkweb/stats")
def api_darkweb_stats():
    return jsonify(get_dark_web_stats())


@app.route("/api/intel/live", methods=["POST"])
def api_live_intel():
    data = request.get_json() or {}
    query = data.get("query", "").strip()
    payload = fetch_live_intel(query)
    user = maybe_get_authenticated_user()
    if user and payload.get("status") == "ok":
        save_lookup_history(user["id"], payload.get("query", query), payload)
    return jsonify(payload)


@app.route("/api/darkweb/actors")
def api_threat_actors():
    return jsonify(get_threat_actors())


@app.route("/api/darkweb/pastes")
def api_paste_sites():
    return jsonify(get_paste_sites())


@app.route("/api/darkweb/leaks")
def api_all_leaks():
    return jsonify(get_all_dark_web_leaks())


@app.route("/api/darkweb/tor-info")
def api_tor_info():
    return jsonify(explain_tor_architecture())


@app.route("/api/user/watchlist", methods=["GET"])
@auth_required
def get_watchlist():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM watchlist_items
        WHERE user_id = ?
        ORDER BY updated_at DESC, created_at DESC
        """,
        (g.current_user["id"],),
    )
    items = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({"items": items})


@app.route("/api/user/watchlist", methods=["POST"])
@auth_required
def add_watchlist_item():
    data = request.get_json() or {}
    query_value = data.get("query_value", "").strip()
    query_type = data.get("query_type", "domain").strip() or "domain"
    notes = data.get("notes", "").strip()

    if len(query_value) < 2:
        return jsonify({"error": "Watchlist value must be at least 2 characters."}), 400

    live = fetch_live_intel(query_value, limit=3)
    severity = ""
    if live.get("results"):
        severities = [item.get("severity", "Low") for item in live["results"]]
        severity = "High" if "High" in severities else "Medium" if "Medium" in severities else "Low"

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO watchlist_items (user_id, query_type, query_value, latest_status, latest_severity, notes)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            g.current_user["id"],
            query_type,
            query_value,
            live.get("status", ""),
            severity,
            notes,
        ),
    )
    item_id = cursor.lastrowid
    conn.commit()
    cursor.execute("SELECT * FROM watchlist_items WHERE id = ?", (item_id,))
    item = dict(cursor.fetchone())
    conn.close()
    return jsonify(item), 201


@app.route("/api/user/watchlist/<int:item_id>", methods=["DELETE"])
@auth_required
def delete_watchlist_item(item_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM watchlist_items WHERE id = ? AND user_id = ?",
        (item_id, g.current_user["id"]),
    )
    conn.commit()
    deleted = cursor.rowcount
    conn.close()
    if not deleted:
        return jsonify({"error": "Watchlist item not found."}), 404
    return jsonify({"status": "ok"})


@app.route("/api/user/history")
@auth_required
def get_user_history():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, query_value, source, result_count, payload_json, created_at
        FROM lookup_history
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 25
        """,
        (g.current_user["id"],),
    )
    rows = []
    for row in cursor.fetchall():
        payload = json.loads(row["payload_json"])
        rows.append(
            {
                "id": row["id"],
                "query_value": row["query_value"],
                "source": row["source"],
                "result_count": row["result_count"],
                "created_at": row["created_at"],
                "top_results": payload.get("results", [])[:3],
            }
        )
    conn.close()
    return jsonify({"items": rows})


@app.route("/api/user/reports")
@auth_required
def get_saved_reports():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, target_email, risk_label, score, summary, created_at
        FROM saved_reports
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 25
        """,
        (g.current_user["id"],),
    )
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({"items": rows})


@app.route("/assess")
@app.route("/flask/assess")
def assess_page():
    return render_template("assess.html")


@app.route("/api/assess/email", methods=["POST"])
def api_assess_email():
    data = request.get_json() or {}
    email = data.get("email", "").strip()
    if not email or "@" not in email:
        return jsonify({"error": "Invalid email"}), 400

    breach_result = check_email(email)
    dark_web_result = scan_dark_web_for_email(email)
    assessment = assess_email_risk(breach_result, dark_web_result)
    payload = {
        "email_checked": breach_result.get("email_checked", ""),
        "breach_result": breach_result,
        "dark_web_result": dark_web_result,
        "risk_assessment": assessment,
    }
    return jsonify(payload)


@app.route("/api/assess/score", methods=["POST"])
def api_manual_score():
    data = request.get_json() or {}
    return jsonify(
        calculate_risk_score(
            severity=data.get("severity", "Low"),
            data_types=data.get("data_types", "email"),
            dark_web_hit=data.get("dark_web_hit", False),
            breach_count=data.get("breach_count", 1),
            verified=data.get("verified", False),
        )
    )


@app.route("/api/assess/distribution")
def api_risk_distribution():
    return jsonify(get_risk_distribution())


@app.route("/api/assess/all")
def api_all_assessments():
    return jsonify(get_all_assessments())


@app.route("/report")
@app.route("/flask/report")
def report_page():
    return render_template("report.html")


@app.route("/api/report/generate", methods=["POST"])
def api_generate_report():
    try:
        data = request.get_json() or {}
        email = data.get("email", "").strip()
        if not email or "@" not in email:
            return jsonify({"error": "Invalid email"}), 400

        breach_result = check_email(email)
        dark_web_result = scan_dark_web_for_email(email)
        assessment = assess_email_risk(breach_result, dark_web_result)

        combined = {
            "email_checked": breach_result.get("email_checked", ""),
            "breach_result": breach_result,
            "dark_web_result": dark_web_result,
            "risk_assessment": assessment,
        }

        alert_result = create_alert(
            email_to=email,
            risk_level=assessment.get("risk_label", "Low"),
            threat_summary=assessment.get("summary", ""),
        )

        pdf_report = generate_pdf_report(combined)
        pdf_base64 = base64.b64encode(pdf_report["content"]).decode("ascii")

        user = maybe_get_authenticated_user()
        if user:
            save_report(user["id"], email, combined)

        return jsonify(
            {
                "status": "success",
                "pdf_filename": pdf_report["filename"],
                "pdf_url": f"data:application/pdf;base64,{pdf_base64}",
                "alert": alert_result,
                "risk_label": assessment.get("risk_label"),
                "score": assessment.get("total_score"),
                "summary": assessment.get("summary", ""),
            }
        )
    except Exception as e:
        import traceback

        error_details = traceback.format_exc()
        print(f"[REPORT ERROR] {error_details}")
        return jsonify({"error": str(e), "details": error_details}), 500


@app.route("/api/alerts")
def api_alerts():
    return jsonify(get_all_alerts())


@app.route("/api/alerts/stats")
def api_alert_stats():
    return jsonify(get_alert_stats())


@app.route("/<path:path>")
def static_or_spa(path):
    if path.startswith("api/") or path.startswith("flask/"):
        return jsonify({"error": "Not found"}), 404
    if os.environ.get("VERCEL"):
        return "", 404

    file_path = PUBLIC_DIR / path
    if file_path.is_file():
        return send_from_directory(PUBLIC_DIR, path)
    return serve_frontend()


if __name__ == "__main__":
    print("[*] Server starting at http://127.0.0.1:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
