# app.py  —  Main Flask Application (Modules 1-5)
from flask import Flask, jsonify, render_template, request, send_from_directory
from database import init_db
from modules.data_collector     import ingest_breach_data, get_all_breaches, get_breach_stats
from modules.credential_monitor import check_email, check_domain, get_recent_threats
from modules.dark_web_sim       import (scan_dark_web_for_email, get_threat_actors,
                                         get_paste_sites, get_all_dark_web_leaks,
                                         get_dark_web_stats, explain_tor_architecture)
from modules.risk_engine        import (assess_email_risk, get_risk_distribution,
                                         get_all_assessments, calculate_risk_score)
from modules.alert_system       import (create_alert, get_all_alerts,
                                         get_alert_stats, generate_pdf_report)

app = Flask(__name__)

# ── Module 1 ──────────────────────────────────────────────────────
@app.route('/')
@app.route('/flask')
def index():
    return render_template('dashboard.html')

@app.route('/api/ingest')
def trigger_ingestion():
    return jsonify(ingest_breach_data())

@app.route('/api/breaches')
def api_breaches():
    return jsonify(get_all_breaches())

@app.route('/api/stats')
def api_stats():
    return jsonify(get_breach_stats())

# ── Module 2 ──────────────────────────────────────────────────────
@app.route('/search')
@app.route('/flask/search')
def search_page():
    return render_template('search.html')

@app.route('/api/check/email', methods=['POST'])
def api_check_email():
    data  = request.get_json()
    email = data.get('email', '').strip()
    return jsonify(check_email(email))

@app.route('/api/check/domain', methods=['POST'])
def api_check_domain():
    data   = request.get_json()
    domain = data.get('domain', '').strip()
    return jsonify(check_domain(domain))

@app.route('/api/threats/recent')
def api_recent_threats():
    return jsonify(get_recent_threats())

# ── Module 3 ──────────────────────────────────────────────────────
@app.route('/darkweb')
@app.route('/flask/darkweb')
def darkweb_page():
    return render_template('darkweb.html')

@app.route('/api/darkweb/scan', methods=['POST'])
def api_darkweb_scan():
    data  = request.get_json()
    email = data.get('email', '').strip()
    return jsonify(scan_dark_web_for_email(email))

@app.route('/api/darkweb/stats')
def api_darkweb_stats():
    return jsonify(get_dark_web_stats())

@app.route('/api/darkweb/actors')
def api_threat_actors():
    return jsonify(get_threat_actors())

@app.route('/api/darkweb/pastes')
def api_paste_sites():
    return jsonify(get_paste_sites())

@app.route('/api/darkweb/leaks')
def api_all_leaks():
    return jsonify(get_all_dark_web_leaks())

@app.route('/api/darkweb/tor-info')
def api_tor_info():
    return jsonify(explain_tor_architecture())

# ── Module 4 ──────────────────────────────────────────────────────
@app.route('/assess')
@app.route('/flask/assess')
def assess_page():
    return render_template('assess.html')

@app.route('/api/assess/email', methods=['POST'])
def api_assess_email():
    data  = request.get_json()
    email = data.get('email', '').strip()
    if not email or '@' not in email:
        return jsonify({"error": "Invalid email"}), 400
    breach_result   = check_email(email)
    dark_web_result = scan_dark_web_for_email(email)
    assessment      = assess_email_risk(breach_result, dark_web_result)
    return jsonify({
        "email_checked"  : breach_result.get("email_checked", ""),
        "breach_result"  : breach_result,
        "dark_web_result": dark_web_result,
        "risk_assessment": assessment
    })

@app.route('/api/assess/score', methods=['POST'])
def api_manual_score():
    data = request.get_json()
    return jsonify(calculate_risk_score(
        severity     = data.get("severity", "Low"),
        data_types   = data.get("data_types", "email"),
        dark_web_hit = data.get("dark_web_hit", False),
        breach_count = data.get("breach_count", 1),
        verified     = data.get("verified", False)
    ))

@app.route('/api/assess/distribution')
def api_risk_distribution():
    return jsonify(get_risk_distribution())

@app.route('/api/assess/all')
def api_all_assessments():
    return jsonify(get_all_assessments())

# ── Module 5 ──────────────────────────────────────────────────────
@app.route('/report')
@app.route('/flask/report')
def report_page():
    return render_template('report.html')

@app.route('/api/report/generate', methods=['POST'])
def api_generate_report():
    try:
        data  = request.get_json()
        email = data.get('email', '').strip()

        if not email or '@' not in email:
            return jsonify({"error": "Invalid email"}), 400

        breach_result   = check_email(email)
        dark_web_result = scan_dark_web_for_email(email)
        assessment      = assess_email_risk(breach_result, dark_web_result)

        combined = {
            "email_checked"  : breach_result.get("email_checked", ""),
            "breach_result"  : breach_result,
            "dark_web_result": dark_web_result,
            "risk_assessment": assessment
        }

        alert_result = create_alert(
            email_to      = email,
            risk_level    = assessment.get("risk_label", "Low"),
            threat_summary= assessment.get("summary", ""),
        )

        pdf_filename = generate_pdf_report(combined)

        return jsonify({
            "status"      : "success",
            "pdf_filename": pdf_filename,
            "pdf_url"     : f"/reports/{pdf_filename}",
            "alert"       : alert_result,
            "risk_label"  : assessment.get("risk_label"),
            "score"       : assessment.get("total_score")
        })

    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"[REPORT ERROR] {error_details}")
        return jsonify({"error": str(e), "details": error_details}), 500

@app.route('/reports/<filename>')
def download_report(filename):
    import os
    reports_dir = os.path.join(app.root_path, 'static', 'reports')
    return send_from_directory(reports_dir, filename, as_attachment=True)

@app.route('/api/alerts')
def api_alerts():
    return jsonify(get_all_alerts())

@app.route('/api/alerts/stats')
def api_alert_stats():
    return jsonify(get_alert_stats())

# ── Startup ───────────────────────────────────────────────────────
if __name__ == '__main__':
    print("[*] Initializing database...")
    init_db()
    print("[*] Running data ingestion...")
    print("[*] Ingestion ->", ingest_breach_data())
    print("[*] Server starting at http://127.0.0.1:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
