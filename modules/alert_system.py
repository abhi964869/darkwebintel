# modules/alert_system.py
# MODULE 5: Alert & PDF Report Generation System

import os
import sys
from datetime import datetime
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import get_connection


def create_alert(email_to, risk_level, threat_summary, threat_id=None):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        if risk_level not in ["Medium", "High", "Critical"]:
            conn.close()
            return {"status": "skipped"}
        cursor.execute(
            "INSERT INTO alerts (threat_id, email_to, status) VALUES (?, ?, 'Pending')",
            (threat_id, email_to),
        )
        alert_id = cursor.lastrowid
        conn.commit()
        cursor.execute(
            "UPDATE alerts SET status=? WHERE id=?",
            ("Logged (Mock Mode)", alert_id),
        )
        conn.commit()
        conn.close()
        return {
            "status": "Logged (Mock Mode)",
            "alert_id": alert_id,
            "email_to": email_to,
            "risk_level": risk_level,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_all_alerts():
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, threat_id, email_to, sent_at, status FROM alerts ORDER BY sent_at DESC"
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception:
        return []


def get_alert_stats():
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total FROM alerts")
        total = cursor.fetchone()["total"]
        cursor.execute("SELECT status, COUNT(*) as count FROM alerts GROUP BY status")
        by_status = {r["status"]: r["count"] for r in cursor.fetchall()}
        conn.close()
        return {"total_alerts": total, "by_status": by_status}
    except Exception:
        return {"total_alerts": 0, "by_status": {}}


def build_pdf_report(assessment_data):
    try:
        ra = assessment_data.get("risk_assessment", {})
        br = assessment_data.get("breach_result", {})
        dw = assessment_data.get("dark_web_result", {})
        email_chk = assessment_data.get("email_checked", "unknown")
        risk_label = ra.get("risk_label", "Unknown")
        score = ra.get("total_score", 0)
        summary = ra.get("summary", "No summary available.")
        breaches = br.get("breaches", [])
        dw_matches = dw.get("matches", [])
        recos = ra.get("recommendations", [])
        bd = ra.get("score_breakdown", {})

        risk_color_map = {
            "Critical": colors.HexColor("#c0392b"),
            "High": colors.HexColor("#e67e22"),
            "Medium": colors.HexColor("#f39c12"),
            "Low": colors.HexColor("#27ae60"),
            "Safe": colors.HexColor("#27ae60"),
        }
        risk_col = risk_color_map.get(risk_label, colors.grey)

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )
        styles = getSampleStyleSheet()
        story = []

        def S(name, **kw):
            return ParagraphStyle(name, parent=styles["Normal"], **kw)

        title_s = S(
            "T",
            fontSize=18,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
            spaceAfter=4,
            textColor=colors.HexColor("#1a1a2e"),
        )
        sub_s = S("Su", fontSize=9, alignment=TA_CENTER, textColor=colors.grey, spaceAfter=8)
        heading_s = S(
            "H",
            fontSize=12,
            fontName="Helvetica-Bold",
            spaceBefore=12,
            spaceAfter=4,
            textColor=colors.HexColor("#1a1a2e"),
        )
        body_s = S(
            "B",
            fontSize=9,
            leading=14,
            spaceAfter=4,
            textColor=colors.HexColor("#333333"),
        )
        note_s = S("N", fontSize=8, leading=12, spaceAfter=4, textColor=colors.grey)

        def HR():
            return HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey)

        def SP(h=0.1):
            return Spacer(1, h * inch)

        story += [
            Paragraph("DARK WEB THREAT INTELLIGENCE REPORT", title_s),
            Paragraph(
                "Dark Web Intel Tool | BCA Final Year Project | OSINT Academic Implementation | SDG 16",
                sub_s,
            ),
            HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a1a2e")),
            SP(0.15),
        ]

        meta = [
            ["Report Date", datetime.now().strftime("%d %B %Y, %H:%M:%S")],
            ["Target", email_chk],
            ["Risk Level", risk_label],
            ["Composite Score", f"{score} / 100"],
            ["Classification", "CONFIDENTIAL - ACADEMIC USE ONLY"],
        ]
        mt = Table(meta, colWidths=[2.0 * inch, 5.0 * inch])
        mt.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
                    ("BACKGROUND", (0, 2), (1, 2), risk_col),
                    ("TEXTCOLOR", (0, 2), (1, 2), colors.white),
                    ("FONTNAME", (0, 2), (1, 2), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story += [mt, SP(0.2)]

        story += [
            Paragraph("1. EXECUTIVE SUMMARY", heading_s),
            HR(),
            SP(0.08),
            Paragraph(summary, body_s),
            SP(0.1),
        ]

        story += [Paragraph("2. RISK SCORE BREAKDOWN", heading_s), HR(), SP(0.08)]
        score_rows = [
            ["Factor", "Score", "Max", "Weight"],
            ["Breach Severity", str(bd.get("severity_score", 0)), "30", "30%"],
            ["Data Sensitivity", str(bd.get("data_type_score", 0)), "25", "25%"],
            ["Dark Web Presence", str(bd.get("dark_web_score", 0)), "20", "20%"],
            ["Breach Frequency", str(bd.get("breach_count_score", 0)), "15", "15%"],
            ["Leak Verification", str(bd.get("verification_score", 0)), "10", "10%"],
            ["TOTAL", str(score), "100", "100%"],
        ]
        st = Table(score_rows, colWidths=[3.0 * inch, 1.2 * inch, 1.0 * inch, 1.0 * inch])
        st.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2d333b")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("BACKGROUND", (0, -1), (-1, -1), risk_col),
                    ("TEXTCOLOR", (0, -1), (-1, -1), colors.white),
                    ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#f9f9f9")]),
                    ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story += [st, SP(0.2)]

        story += [Paragraph("3. BREACH DATABASE FINDINGS", heading_s), HR(), SP(0.08)]
        if breaches:
            story.append(Paragraph(f"Found in <b>{len(breaches)}</b> breach record(s).", body_s))
            story.append(SP(0.06))
            b_rows = [["#", "Source", "Date", "Data Exposed", "Affected", "Severity"]]
            for i, b in enumerate(breaches, 1):
                b_rows.append(
                    [
                        str(i),
                        str(b.get("source", ""))[:28],
                        str(b.get("breach_date", "")),
                        str(b.get("data_type", ""))[:30],
                        f"{int(b.get('affected_count', 0)):,}",
                        str(b.get("severity", "")),
                    ]
                )
            bt = Table(
                b_rows,
                colWidths=[0.3 * inch, 1.9 * inch, 0.9 * inch, 1.7 * inch, 1.0 * inch, 0.8 * inch],
            )
            bt.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2d333b")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("LEFTPADDING", (0, 0), (-1, -1), 5),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            story += [bt, SP(0.1)]
        else:
            story.append(Paragraph("No matches found in breach database.", body_s))
        story.append(SP(0.1))

        story += [
            Paragraph("4. DARK WEB INTELLIGENCE (SIMULATED)", heading_s),
            HR(),
            SP(0.08),
            Paragraph(f"Dark web scan detected <b>{dw.get('dark_web_hits', 0)}</b> source(s).", body_s),
            SP(0.06),
        ]
        if dw_matches:
            dw_rows = [["Source", "Type", "Title", "Level", "Verified"]]
            for m in dw_matches:
                dw_rows.append(
                    [
                        str(m.get("sim_source", ""))[:28],
                        str(m.get("leak_type", "")),
                        str(m.get("post_title", ""))[:30],
                        str(m.get("threat_level", "")),
                        "Yes" if m.get("verified") else "No",
                    ]
                )
            dwt = Table(dw_rows, colWidths=[1.9 * inch, 1.1 * inch, 1.9 * inch, 0.8 * inch, 0.6 * inch])
            dwt.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2d333b")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("LEFTPADDING", (0, 0), (-1, -1), 5),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            story.append(dwt)

        story += [
            SP(0.06),
            Paragraph("NOTE: All dark web references are simulated. No TOR network access was performed.", note_s),
            SP(0.15),
        ]

        story += [Paragraph("5. SECURITY RECOMMENDATIONS", heading_s), HR(), SP(0.08)]
        for i, rec in enumerate(recos, 1):
            story.append(Paragraph(f"{i}. {rec}", body_s))

        story += [SP(0.2), HR(), SP(0.08)]
        story.append(
            Paragraph(
                "DISCLAIMER: Generated by Dark Web Threat Intelligence Tool - BCA Final Year Academic Project, Sushant University. All data is OSINT-based or simulated for educational purposes. No illegal systems were accessed. Aligns with SDG Goal 16.",
                note_s,
            )
        )

        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    except Exception as e:
        import traceback

        print(f"[PDF ERROR] {traceback.format_exc()}")
        raise e


def generate_pdf_report(assessment_data):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ThreatReport_{timestamp}.pdf"
    return {
        "filename": filename,
        "content": build_pdf_report(assessment_data),
    }
