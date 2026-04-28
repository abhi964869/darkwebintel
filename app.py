import base64

from flask import Flask, jsonify, render_template, request

from database import get_connection, init_db
from modules.alert_system import create_alert, generate_pdf_report, get_alert_stats, get_all_alerts
from modules.credential_monitor import check_domain, check_email, get_recent_threats
from modules.dark_web_sim import (
    explain_tor_architecture,
    get_all_dark_web_leaks,
    get_dark_web_stats,
    get_paste_sites,
    get_threat_actors,
    scan_dark_web_for_email,
)
from modules.data_collector import get_all_breaches, get_breach_stats, ingest_breach_data
from modules.risk_engine import (
    assess_email_risk,
    calculate_risk_score,
    get_all_assessments,
    get_risk_distribution,
)

app = Flask(__name__, static_folder="public", static_url_path="")


def serve_frontend():
    try:
        return app.send_static_file("index.html")
    except Exception:
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


bootstrap_runtime()


@app.route("/")
def index():
    return serve_frontend()


@app.route("/flask")
def flask_index():
    return render_template("dashboard.html")


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
    return jsonify(
        {
            "email_checked": breach_result.get("email_checked", ""),
            "breach_result": breach_result,
            "dark_web_result": dark_web_result,
            "risk_assessment": assessment,
        }
    )


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

        return jsonify(
            {
                "status": "success",
                "pdf_filename": pdf_report["filename"],
                "pdf_url": f"data:application/pdf;base64,{pdf_base64}",
                "alert": alert_result,
                "risk_label": assessment.get("risk_label"),
                "score": assessment.get("total_score"),
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

    try:
        return app.send_static_file(path)
    except Exception:
        return serve_frontend()


if __name__ == "__main__":
    print("[*] Server starting at http://127.0.0.1:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
