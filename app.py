from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import io
import sys
import os
import time
import base64
import re
import json
import uuid
import html
import urllib.request
import urllib.error
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# We will import our upgraded scanner next
import scanner

# Added static_folder configuration to serve recordings and live frames
app = Flask(__name__, static_folder='static')
CORS(app)

LAST_REPORT_RAW = ""
HISTORY_FILE = "history.json"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"

# ── Ensure Storage Directories Exist ────────────────────────
os.makedirs(os.path.join("static", "history"), exist_ok=True)
os.makedirs(os.path.join("static", "live"), exist_ok=True)

# ── History Database Helpers ────────────────────────────────
def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []

def save_history(data):
    with open(HISTORY_FILE, 'w') as f:
        json.dump(data, f, indent=4)


def _http_json_post(url, payload, headers=None, timeout=30):
    body = json.dumps(payload).encode("utf-8")
    req_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9"
    }
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, data=body, headers=req_headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def generate_ai_guidance(report_text):
    api_key = os.getenv("GROQ_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GROQ_API_KEY is not configured on the server.")

    prompt = (
        "You are a senior web application security expert. "
        "Analyze the scanner report below and provide:\n"
        "1) A short overall risk summary\n"
        "2) Vulnerabilities explained in simple words\n"
        "3) Actionable remediation steps for each issue\n"
        "4) A prioritized fix order (what to fix first)\n"
        "Keep it practical and concise.\n\n"
        f"SCAN REPORT:\n{report_text}"
    )

    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": "You provide precise web security remediation guidance."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2
    }

    response = _http_json_post(
        GROQ_API_URL,
        payload,
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=45
    )

    choices = response.get("choices", [])
    if not choices:
        raise RuntimeError("Groq API returned an empty response.")

    message = choices[0].get("message", {})
    content = message.get("content", "").strip()
    if not content:
        raise RuntimeError("Groq API did not return analysis text.")
    return content


def build_email_pdf(report_text, ai_text=""):
    summary, owasp_counts, findings = parse_report(report_text)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, rightMargin=20*mm, leftMargin=20*mm,
        topMargin=14*mm, bottomMargin=14*mm
    )

    styles = getSampleStyleSheet()

    def style(name, **kw):
        base = kw.pop("parent", styles["Normal"])
        return ParagraphStyle(name, parent=base, **kw)

    sTitle = style("EmailTitle", fontSize=20, textColor=C_NAVY, fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=8)
    sSmall = style("EmailSmall", fontSize=8.5, textColor=C_MUTED)
    sBody = style("EmailBody", fontSize=9.5, textColor=C_TEXT, leading=14)

    elements = []
    elements.append(Paragraph("Sentinel Security Audit Report", sTitle))
    elements.append(Paragraph(f"<b>Target:</b> {html.escape(summary.get('url') or 'N/A')}", sSmall))
    elements.append(Paragraph(f"<b>Generated:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}", sSmall))
    elements.append(Spacer(1, 8))

    summary_tbl = Table([
        ["Total Threats", summary.get("total", "0")],
        ["Duplicates Removed", summary.get("duplicates", "0")],
        ["Low Confidence (FP)", summary.get("false_positives", "0")],
        ["False Positive Rate", summary.get("fp_rate", "0.00%")],
        ["Scan Duration", summary.get("scan_time", "N/A")],
    ], colWidths=[160, 120])
    summary_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(summary_tbl)
    elements.append(Spacer(1, 10))

    if owasp_counts:
        elements.append(Paragraph("<b>OWASP Breakdown</b>", sBody))
        rows = [["Category", "Count"]]
        for k, v in sorted(owasp_counts.items()):
            rows.append([k, str(v)])
        owasp_tbl = Table(rows, colWidths=[360, 80])
        owasp_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(owasp_tbl)
        elements.append(Spacer(1, 10))

    if findings:
        elements.append(Paragraph("<b>Detailed Findings</b>", sBody))
        for f in findings:
            name = html.escape(f.get("Name", "Unnamed Finding"))
            sev = html.escape(f.get("severity", "LOW"))
            risk = html.escape(f.get("Risk", ""))
            resolution = html.escape(f.get("Resolution", ""))
            source = html.escape(f.get("Source", ""))
            owasp = html.escape(f.get("OWASP", ""))
            elements.append(Paragraph(f"<b>#{f.get('number', '?')} - {name}</b> ({sev})", sBody))
            elements.append(Paragraph(f"<b>OWASP:</b> {owasp}", sBody))
            elements.append(Paragraph(f"<b>Risk:</b> {risk}", sBody))
            elements.append(Paragraph(f"<b>Resolution:</b> {resolution}", sBody))
            elements.append(Paragraph(f"<b>Source:</b> {source}", sBody))
            elements.append(Spacer(1, 6))

    if ai_text:
        elements.append(Paragraph("<b>AI Guidance</b>", sBody))
        for line in ai_text.split("\n"):
            txt = html.escape(line.strip()) or "&nbsp;"
            elements.append(Paragraph(txt, sBody))

    doc.build(elements)
    buf.seek(0)
    return buf.read()


def send_report_email_brevo(receiver_email, subject, report_text, ai_text="", pdf_bytes=None):
    api_key = os.getenv("BREVO_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("BREVO_API_KEY is not configured on the server.")

    sender_name = os.getenv("BREVO_SENDER_NAME", "Sentinel Scanner")

    brevo_sender = os.getenv("BREVO_SENDER_EMAIL", "").strip()
    if not brevo_sender:
        raise RuntimeError("BREVO_SENDER_EMAIL is not configured on the server.")

    ai_section = f"\n\nAI Guidance:\n{ai_text}" if ai_text else ""
    email_text = (
        f"Scanner shared from: {brevo_sender}\n"
        f"\nSecurity report:\n{report_text}{ai_section}\n"
    )

    payload = {
        "sender": {"name": sender_name, "email": brevo_sender},
        "to": [{"email": receiver_email}],
        "replyTo": {"email": brevo_sender},
        "subject": subject,
        "textContent": email_text
    }

    if pdf_bytes:
        payload["attachment"] = [{
            "name": "Sentinel_Security_Report.pdf",
            "content": base64.b64encode(pdf_bytes).decode("utf-8")
        }]

    return _http_json_post(
        BREVO_API_URL,
        payload,
        headers={"api-key": api_key},
        timeout=30
    )


# ── Colour Palette (PDF) ────────────────────────────────────
C_BG_DARK    = colors.HexColor("#0f172a")
C_NAVY       = colors.HexColor("#1e293b")
C_ACCENT     = colors.HexColor("#10b981")
C_ACCENT_LT  = colors.HexColor("#d1fae5")
C_HIGH       = colors.HexColor("#ef4444")
C_HIGH_BG    = colors.HexColor("#fef2f2")
C_MED        = colors.HexColor("#f59e0b")
C_MED_BG     = colors.HexColor("#fffbeb")
C_LOW        = colors.HexColor("#10b981")
C_LOW_BG     = colors.HexColor("#ecfdf5")
C_MUTED      = colors.HexColor("#64748b")
C_WHITE      = colors.white
C_TEXT       = colors.HexColor("#0f172a")
C_BORDER     = colors.HexColor("#e2e8f0")


# ══════════════════════════════════════════════════════════════
# SCAN ENDPOINT
# ══════════════════════════════════════════════════════════════
@app.route("/scan", methods=["POST"])
def scan():
    global LAST_REPORT_RAW

    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "URL missing"}), 400

    url = data["url"]
    
    # Generate a unique ID for this scan session
    scan_id = str(uuid.uuid4())[:8] 
    
    buffer = io.StringIO()
    old_stdout = sys.stdout

    try:
        sys.stdout = buffer
        # Pass scan_id to the upgraded scanner for video naming
        video_filename = scanner.scan_website(url, scan_id)
        LAST_REPORT_RAW = buffer.getvalue()
        
        # Parse the report to get summary details for history
        summary, _, _ = parse_report(LAST_REPORT_RAW)
        
        # Save to Local History JSON
        history = load_history()
        history.insert(0, {
            "id": scan_id,
            "url": url,
            "date": time.strftime('%Y-%m-%d %H:%M:%S'),
            "threats": summary["total"],
            "video": video_filename,
            "report": LAST_REPORT_RAW
        })
        save_history(history)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        sys.stdout = old_stdout

    return jsonify({"report": LAST_REPORT_RAW, "scan_id": scan_id, "url": url, "video": video_filename})


@app.route("/ai-help", methods=["POST"])
def ai_help():
    body = request.get_json(silent=True) or {}
    report_text = body.get("report_raw", "").strip() or LAST_REPORT_RAW

    if not report_text:
        return jsonify({"error": "No scan data available to analyze."}), 400

    try:
        ai_text = generate_ai_guidance(report_text)
        return jsonify({"analysis": ai_text})
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else str(e)
        return jsonify({"error": f"AI service error ({e.code}): {detail}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/share/email", methods=["POST"])
def share_email():
    body = request.get_json(silent=True) or {}
    receiver_email = (body.get("receiver_email") or "").strip()
    report_text = (body.get("report_raw") or "").strip() or LAST_REPORT_RAW
    ai_text = (body.get("ai_analysis") or "").strip()

    if not receiver_email:
        return jsonify({"error": "receiver_email is required."}), 400
    if not report_text:
        return jsonify({"error": "No scan data available to share."}), 400

    subject = (body.get("subject") or "Sentinel Security Report").strip()

    try:
        pdf_bytes = build_email_pdf(report_text, ai_text)
        resp = send_report_email_brevo(receiver_email, subject, report_text, ai_text, pdf_bytes=pdf_bytes)
        return jsonify({"status": "success", "provider_response": resp})
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else str(e)
        return jsonify({"error": f"Email service error ({e.code}): {detail}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════
# HISTORY MANAGEMENT ENDPOINTS
# ══════════════════════════════════════════════════════════════
@app.route("/api/history", methods=["GET"])
def get_history():
    """Returns the list of past scans."""
    return jsonify(load_history())

@app.route("/api/history/<scan_id>", methods=["DELETE"])
def delete_history(scan_id):
    """Deletes a scan entry and its associated video file."""
    history = load_history()
    new_history = [h for h in history if h["id"] != scan_id]
    save_history(new_history)
    
    # Delete the physical .webm video file
    video_path = os.path.join("static", "history", f"{scan_id}.webm")
    if os.path.exists(video_path):
        os.remove(video_path)
        
    return jsonify({"status": "success", "message": f"Scan {scan_id} deleted."})


# ══════════════════════════════════════════════════════════════
# REPORT PARSER
# ══════════════════════════════════════════════════════════════
def parse_report(raw):
    """Parse raw text output into structured dicts."""
    summary = {
        "url": "", "total": "0", "duplicates": "0",
        "false_positives": "0", "fp_rate": "0.00%", "scan_time": "N/A",
    }
    owasp_counts = {}
    findings = []
    current = None

    for line in raw.split("\n"):
        s = line.strip()

        if s.startswith("Scanning:") or "Scanning:" in s:
            summary["url"] = s.split("Scanning:")[-1].strip()
        elif "Total Threats Found" in s:
            summary["total"] = _extract_val(s)
        elif "Duplicate Risks Suppressed" in s:
            summary["duplicates"] = _extract_val(s)
        elif "False Positives (LOW)" in s:
            summary["false_positives"] = _extract_val(s)
        elif "False Positive Rate" in s:
            summary["fp_rate"] = _extract_val(s)
        elif "Total Scan Time" in s:
            summary["scan_time"] = _extract_val(s)
        elif re.match(r"A\d{2}\s*-", s) and ":" in s:
            parts = s.rsplit(":", 1)
            if len(parts) == 2:
                try:
                    count = int(parts[1].strip())
                    owasp_counts[parts[0].strip()] = count
                except ValueError:
                    pass
        elif "Threat #" in s:
            if current: findings.append(current)
            sev = ("HIGH"   if ("HIGH"   in s or "🔴" in s) else
                   "MEDIUM" if ("MEDIUM" in s or "🟠" in s) else "LOW")
            num_m = re.search(r"#(\d+)", s)
            current = {
                "number": num_m.group(1) if num_m else "?", "severity": sev,
                "Name": "", "OWASP": "", "Risk": "", "Resolution": "", "Source": ""
            }
        elif current is not None and ":" in s:
            key, _, val = s.partition(":")
            key = key.strip()
            if key in ("Name", "OWASP", "Risk", "Resolution", "Source"):
                current[key] = val.strip()

    if current: findings.append(current)
    return summary, owasp_counts, findings

def _extract_val(line):
    return line.split(":")[-1].strip()


# ══════════════════════════════════════════════════════════════
# PDF GENERATOR
# ══════════════════════════════════════════════════════════════
@app.route("/download-pdf", methods=["POST"])
def download_pdf():
    global LAST_REPORT_RAW
    
    body = request.get_json(silent=True) or {}
    
    # NEW: Prioritize explicit report data from the payload (useful for History Downloads)
    report_text = body.get("report_raw", LAST_REPORT_RAW)
    
    if not report_text:
        return jsonify({"error": "No scan data available. Run a scan first."}), 400

    bar_b64 = body.get("barChart")
    pie_b64 = body.get("pieChart")

    # Parse using the specifically passed report_text
    summary, owasp_counts, findings = parse_report(report_text)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, rightMargin=20*mm, leftMargin=20*mm,
        topMargin=14*mm, bottomMargin=14*mm
    )

    styles = getSampleStyleSheet()
    W = A4[0] - 40*mm

    def style(name, **kw):
        base = kw.pop("parent", styles["Normal"])
        return ParagraphStyle(name, parent=base, **kw)

    sTitle    = style("sTitle", fontSize=26, textColor=C_ACCENT, alignment=TA_CENTER, fontName="Helvetica-Bold", spaceAfter=2)
    sSubtitle = style("sSubtitle", fontSize=10, textColor=C_MUTED, alignment=TA_CENTER, spaceAfter=4)
    sSectionH = style("sSectionH", fontSize=12, textColor=C_WHITE, fontName="Helvetica-Bold", alignment=TA_LEFT, spaceBefore=14, spaceAfter=6)
    sNormal   = style("sNormal", fontSize=9, textColor=C_TEXT, leading=14)
    sSmall    = style("sSmall", fontSize=8, textColor=C_MUTED)
    sLabel    = style("sLabel", fontSize=8, textColor=C_MUTED, fontName="Helvetica-Bold")
    sFindHead = style("sFindHead", fontSize=10, textColor=C_WHITE, fontName="Helvetica-Bold")
    sFindBody = style("sFindBody", fontSize=9, textColor=C_TEXT, leading=13)

    elements = []

    banner_data = [[
        Paragraph("SENTINEL", style("BannerBig", fontSize=28, textColor=C_ACCENT, fontName="Helvetica-Bold")),
        Paragraph("SECURITY AUDIT REPORT", style("BannerSub", fontSize=11, textColor=C_WHITE, fontName="Helvetica-Bold", alignment=TA_RIGHT))
    ]]
    banner_tbl = Table(banner_data, colWidths=[W*0.5, W*0.5])
    banner_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_NAVY), ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 16), ("RIGHTPADDING", (0,0), (-1,-1), 16),
        ("TOPPADDING", (0,0), (-1,-1), 14), ("BOTTOMPADDING", (0,0), (-1,-1), 14),
        ("ROUNDEDCORNERS", (0,0), (-1,-1), [8,8,8,8]),
    ]))
    elements.append(banner_tbl)
    elements.append(Spacer(1, 6))

    meta_data = [[
        Paragraph(f"<b>Target:</b>  {summary['url'] or 'N/A'}", sSmall),
        Paragraph(f"<b>Generated:</b>  {time.strftime('%Y-%m-%d  %H:%M:%S')}", sSmall),
    ]]
    meta_tbl = Table(meta_data, colWidths=[W*0.6, W*0.4])
    meta_tbl.setStyle(TableStyle([
        ("ALIGN", (1,0), (1,0), "RIGHT"), ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    elements.append(meta_tbl)
    elements.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=10))

    elements.append(_section_header("Scan Summary", W))
    cards = [
        ("Total Threats", summary["total"], C_HIGH), ("Duplicates Removed", summary["duplicates"], C_NAVY),
        ("Low-Confidence (FP)", summary["false_positives"], C_MED), ("FP Rate", summary["fp_rate"], C_MUTED),
        ("Scan Duration", summary["scan_time"], C_ACCENT),
    ]
    col_w = W / len(cards)
    card_cells = [[_stat_card(label, val, col, col_w) for label, val, col in cards]]
    card_tbl = Table(card_cells, colWidths=[col_w]*len(cards))
    card_tbl.setStyle(TableStyle([
        ("ALIGN", (0,0), (-1,-1), "CENTER"), ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 3), ("RIGHTPADDING", (0,0), (-1,-1), 3),
    ]))
    elements.append(card_tbl)
    elements.append(Spacer(1, 10))

    if owasp_counts:
        elements.append(_section_header("OWASP Top 10 Breakdown", W))
        owasp_rows = [[Paragraph(f"<b>{k}</b>", sNormal), _severity_pill(v)] for k, v in sorted(owasp_counts.items())]
        owasp_tbl = Table(
            [[ Paragraph("<b>Category</b>", sLabel), Paragraph("<b>Issues</b>", sLabel) ]] + owasp_rows,
            colWidths=[W*0.82, W*0.18]
        )
        owasp_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), C_NAVY), ("TEXTCOLOR", (0,0), (-1,0), C_WHITE),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_WHITE, colors.HexColor("#f8fafc")]),
            ("GRID", (0,0), (-1,-1), 0.5, C_BORDER), ("ALIGN", (1,0), (1,-1), "CENTER"),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"), ("TOPPADDING", (0,0), (-1,-1), 7),
            ("BOTTOMPADDING", (0,0), (-1,-1), 7), ("LEFTPADDING", (0,0), (-1,-1), 10),
            ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ]))
        elements.append(owasp_tbl)
        elements.append(Spacer(1, 10))

    bar_img = _b64_to_image(bar_b64, W*0.50 - 8, 160)
    pie_img = _b64_to_image(pie_b64, W*0.50 - 8, 160)

    if bar_img or pie_img:
        elements.append(_section_header("Risk Distribution", W))
        chart_tbl = Table([[bar_img or "", pie_img or ""]], colWidths=[W*0.50, W*0.50])
        chart_tbl.setStyle(TableStyle([
            ("ALIGN", (0,0), (-1,-1), "CENTER"), ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ("BOX", (0,0), (-1,-1), 0.5, C_BORDER), ("GRID", (0,0), (-1,-1), 0.5, C_BORDER),
            ("TOPPADDING", (0,0), (-1,-1), 10), ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ]))
        elements.append(chart_tbl)
        elements.append(Spacer(1, 12))

    if findings:
        elements.append(_section_header("Detailed Security Findings", W))
        for f in findings:
            sev = f.get("severity", "LOW")
            bg, fg, pill_bg = _severity_colors(sev)
            header_tbl = Table([[Paragraph(f"<b>#{f['number']}  {f.get('Name','Unnamed Finding')}</b>", sFindHead), _pill_text(sev, fg, pill_bg)]], colWidths=[W - 70, 60])
            header_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), bg), ("ALIGN", (1,0), (1,0), "RIGHT"),
                ("VALIGN", (0,0), (-1,-1), "MIDDLE"), ("LEFTPADDING", (0,0), (-1,-1), 12),
                ("RIGHTPADDING", (0,0), (-1,-1), 8), ("TOPPADDING", (0,0), (-1,-1), 9),
                ("BOTTOMPADDING", (0,0), (-1,-1), 9),
            ]))
            detail_rows = [
                [Paragraph("<b>OWASP</b>", sLabel), Paragraph(f.get("OWASP",""), sFindBody)],
                [Paragraph("<b>Risk</b>", sLabel), Paragraph(f.get("Risk",""), sFindBody)],
                [Paragraph("<b>Resolution</b>", sLabel), Paragraph(f.get("Resolution",""), sFindBody)],
                [Paragraph("<b>Source</b>", sLabel), Paragraph(f.get("Source",""), sFindBody)],
            ]
            detail_tbl = Table(detail_rows, colWidths=[72, W - 72])
            detail_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), C_WHITE), ("GRID", (0,0), (-1,-1), 0.4, C_BORDER),
                ("VALIGN", (0,0), (-1,-1), "TOP"), ("TOPPADDING", (0,0), (-1,-1), 6),
                ("BOTTOMPADDING", (0,0), (-1,-1), 6), ("LEFTPADDING", (0,0), (-1,-1), 10),
                ("RIGHTPADDING", (0,0), (-1,-1), 10), ("LINEBELOW", (0,-1), (-1,-1), 0.4, C_BORDER),
            ]))
            elements.append(KeepTogether([header_tbl, detail_tbl, Spacer(1, 8)]))

    elements.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceBefore=12))
    elements.append(Paragraph(
        "Generated by Sentinel Security Scanner  •  Confidential — For Authorised Use Only",
        style("sFooter", fontSize=7.5, textColor=C_MUTED, alignment=TA_CENTER, spaceBefore=4)
    ))

    doc.build(elements)
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name="Sentinel_Security_Report.pdf", mimetype="application/pdf")

def _section_header(title, width):
    tbl = Table([[Paragraph(title, ParagraphStyle("SH", fontName="Helvetica-Bold", fontSize=10, textColor=colors.white))]], colWidths=[width])
    tbl.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), C_NAVY), ("LEFTPADDING", (0,0), (-1,-1), 14), ("TOPPADDING", (0,0), (-1,-1), 8), ("BOTTOMPADDING", (0,0), (-1,-1), 8)]))
    return tbl

def _stat_card(label, value, accent_color, width):
    inner = [
        [Paragraph(f"<b>{value}</b>", ParagraphStyle("CV", fontName="Helvetica-Bold", fontSize=16, textColor=accent_color, alignment=TA_CENTER))],
        [Paragraph(label, ParagraphStyle("CL", fontSize=7.5, textColor=C_MUTED, alignment=TA_CENTER))]
    ]
    t = Table(inner, colWidths=[width - 6])
    t.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#f8fafc")), ("BOX", (0,0), (-1,-1), 0.5, C_BORDER), ("TOPPADDING", (0,0), (-1,-1), 8), ("BOTTOMPADDING", (0,0), (-1,-1), 8), ("ALIGN", (0,0), (-1,-1), "CENTER")]))
    return t

def _severity_colors(sev):
    return {"HIGH": (C_HIGH, C_WHITE, colors.HexColor("#dc2626")), "MEDIUM": (C_MED, C_WHITE, colors.HexColor("#d97706")), "LOW": (C_LOW, C_WHITE, colors.HexColor("#059669"))}.get(sev, (C_NAVY, C_WHITE, C_MUTED))

def _pill_text(label, fg, bg):
    t = Table([[Paragraph(f"<b>{label}</b>", ParagraphStyle("Pill", fontSize=8, textColor=C_WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER))]], colWidths=[54])
    t.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), bg), ("TOPPADDING", (0,0), (-1,-1), 4), ("BOTTOMPADDING", (0,0), (-1,-1), 4), ("ALIGN", (0,0), (-1,-1), "CENTER")]))
    return t

def _severity_pill(count):
    col = C_HIGH if count >= 3 else (C_MED if count >= 2 else C_LOW)
    t = Table([[Paragraph(f"<b>{count}</b>", ParagraphStyle("P", fontSize=9, textColor=C_WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER))]], colWidths=[36])
    t.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), col), ("TOPPADDING", (0,0), (-1,-1), 3), ("BOTTOMPADDING", (0,0), (-1,-1), 3), ("ALIGN", (0,0), (-1,-1), "CENTER")]))
    return t

def _b64_to_image(b64_str, w, h):
    if not b64_str: return None
    try: return Image(io.BytesIO(base64.b64decode(b64_str.split(",", 1)[-1])), width=w, height=h)
    except Exception: return None

@app.route("/")
def index():
    """Serves the main scanner UI."""
    return send_file('index.html')

@app.route("/history")
def history_page():
    """Serves the history UI."""
    return send_file('history.html')

# Ensure the app serves other root-level files like style.css and script.js
@app.route('/<path:path>')
def send_report_assets(path):
    return send_from_directory('.', path)

if __name__ == "__main__":
    # In Docker, we must listen on 0.0.0.0
    app.run(host="0.0.0.0", port=5001, debug=False)
