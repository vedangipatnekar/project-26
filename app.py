from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import io
import sys
import os
import time
import base64
import re
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

import scanner

app = Flask(__name__)
CORS(app)

LAST_REPORT_RAW = ""

# ── Colour Palette ──────────────────────────────────────────
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
    buffer = io.StringIO()
    old_stdout = sys.stdout

    try:
        sys.stdout = buffer
        scanner.scan_website(url)
        LAST_REPORT_RAW = buffer.getvalue()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        sys.stdout = old_stdout

    return jsonify({"report": LAST_REPORT_RAW})


# ══════════════════════════════════════════════════════════════
# REPORT PARSER
# ══════════════════════════════════════════════════════════════
def parse_report(raw):
    """Parse raw text output into structured dicts."""
    summary = {
        "url": "",
        "total": "0",
        "duplicates": "0",
        "false_positives": "0",
        "fp_rate": "0.00%",
        "scan_time": "N/A",
    }
    owasp_counts = {}
    findings = []
    current = None

    for line in raw.split("\n"):
        s = line.strip()

        # Target URL
        if s.startswith("Scanning:") or "Scanning:" in s:
            summary["url"] = s.split("Scanning:")[-1].strip()

        # Summary numbers
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

        # OWASP breakdown lines like "A03 - Injection : 2"
        elif re.match(r"A\d{2}\s*-", s) and ":" in s:
            parts = s.rsplit(":", 1)
            if len(parts) == 2:
                try:
                    count = int(parts[1].strip())
                    owasp_counts[parts[0].strip()] = count
                except ValueError:
                    pass

        # New finding block
        elif "Threat #" in s:
            if current:
                findings.append(current)
            sev = ("HIGH"   if ("HIGH"   in s or "🔴" in s) else
                   "MEDIUM" if ("MEDIUM" in s or "🟠" in s) else "LOW")
            num_m = re.search(r"#(\d+)", s)
            current = {
                "number": num_m.group(1) if num_m else "?",
                "severity": sev,
                "Name": "", "OWASP": "", "Risk": "",
                "Resolution": "", "Source": ""
            }

        # Finding fields
        elif current is not None and ":" in s:
            key, _, val = s.partition(":")
            key = key.strip()
            if key in ("Name", "OWASP", "Risk", "Resolution", "Source"):
                current[key] = val.strip()

    if current:
        findings.append(current)

    return summary, owasp_counts, findings


def _extract_val(line):
    """Extract the value after ':' from a summary line."""
    return line.split(":")[-1].strip()


# ══════════════════════════════════════════════════════════════
# PDF GENERATOR
# ══════════════════════════════════════════════════════════════
@app.route("/download-pdf", methods=["POST"])
def download_pdf():
    global LAST_REPORT_RAW
    if not LAST_REPORT_RAW:
        return jsonify({"error": "No scan data available. Run a scan first."}), 400

    body = request.get_json(silent=True) or {}
    bar_b64 = body.get("barChart")
    pie_b64 = body.get("pieChart")

    summary, owasp_counts, findings = parse_report(LAST_REPORT_RAW)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        rightMargin=20*mm, leftMargin=20*mm,
        topMargin=14*mm, bottomMargin=14*mm
    )

    styles = getSampleStyleSheet()
    W = A4[0] - 40*mm   # usable width

    # ── Custom paragraph styles ──────────────────────────────
    def style(name, **kw):
        base = kw.pop("parent", styles["Normal"])
        ps = ParagraphStyle(name, parent=base, **kw)
        return ps

    sTitle    = style("sTitle",    fontSize=26, textColor=C_ACCENT,
                      alignment=TA_CENTER, fontName="Helvetica-Bold",
                      spaceAfter=2)
    sSubtitle = style("sSubtitle", fontSize=10, textColor=C_MUTED,
                      alignment=TA_CENTER, spaceAfter=4)
    sSectionH = style("sSectionH", fontSize=12, textColor=C_WHITE,
                      fontName="Helvetica-Bold", alignment=TA_LEFT,
                      spaceBefore=14, spaceAfter=6)
    sNormal   = style("sNormal",   fontSize=9,  textColor=C_TEXT,
                      leading=14)
    sSmall    = style("sSmall",    fontSize=8,  textColor=C_MUTED)
    sLabel    = style("sLabel",    fontSize=8,  textColor=C_MUTED,
                      fontName="Helvetica-Bold")
    sFindHead = style("sFindHead", fontSize=10, textColor=C_WHITE,
                      fontName="Helvetica-Bold")
    sFindBody = style("sFindBody", fontSize=9,  textColor=C_TEXT, leading=13)

    elements = []

    # ── HEADER BANNER ────────────────────────────────────────
    banner_data = [[
        Paragraph("SENTINEL", style("BannerBig", fontSize=28, textColor=C_ACCENT,
                                    fontName="Helvetica-Bold")),
        Paragraph("SECURITY AUDIT REPORT", style("BannerSub", fontSize=11,
                                                 textColor=C_WHITE,
                                                 fontName="Helvetica-Bold",
                                                 alignment=TA_RIGHT))
    ]]
    banner_tbl = Table(banner_data, colWidths=[W*0.5, W*0.5])
    banner_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_NAVY),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",  (0,0), (-1,-1), 16),
        ("RIGHTPADDING", (0,0), (-1,-1), 16),
        ("TOPPADDING",   (0,0), (-1,-1), 14),
        ("BOTTOMPADDING",(0,0), (-1,-1), 14),
        ("ROUNDEDCORNERS", (0,0), (-1,-1), [8,8,8,8]),
    ]))
    elements.append(banner_tbl)
    elements.append(Spacer(1, 6))

    # ── META ROW (URL + Date) ─────────────────────────────────
    meta_data = [[
        Paragraph(f"<b>Target:</b>  {summary['url'] or 'N/A'}", sSmall),
        Paragraph(f"<b>Generated:</b>  {time.strftime('%Y-%m-%d  %H:%M:%S')}", sSmall),
    ]]
    meta_tbl = Table(meta_data, colWidths=[W*0.6, W*0.4])
    meta_tbl.setStyle(TableStyle([
        ("ALIGN", (1,0), (1,0), "RIGHT"),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    elements.append(meta_tbl)
    elements.append(HRFlowable(width="100%", thickness=1,
                                color=C_BORDER, spaceAfter=10))

    # ── SCAN SUMMARY CARDS ────────────────────────────────────
    elements.append(_section_header("Scan Summary", W))

    cards = [
        ("Total Threats",       summary["total"],           C_HIGH),
        ("Duplicates Removed",  summary["duplicates"],      C_NAVY),
        ("Low-Confidence (FP)", summary["false_positives"], C_MED),
        ("FP Rate",             summary["fp_rate"],         C_MUTED),
        ("Scan Duration",       summary["scan_time"],       C_ACCENT),
    ]
    col_w = W / len(cards)
    card_cells = [[_stat_card(label, val, col, col_w) for label, val, col in cards]]
    card_tbl = Table(card_cells, colWidths=[col_w]*len(cards))
    card_tbl.setStyle(TableStyle([
        ("ALIGN",   (0,0), (-1,-1), "CENTER"),
        ("VALIGN",  (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",  (0,0), (-1,-1), 3),
        ("RIGHTPADDING", (0,0), (-1,-1), 3),
    ]))
    elements.append(card_tbl)
    elements.append(Spacer(1, 10))

    # ── OWASP BREAKDOWN TABLE ─────────────────────────────────
    if owasp_counts:
        elements.append(_section_header("OWASP Top 10 Breakdown", W))
        owasp_rows = [
            [Paragraph(f"<b>{k}</b>", sNormal),
             _severity_pill(v)]
            for k, v in sorted(owasp_counts.items())
        ]
        owasp_tbl = Table(
            [[ Paragraph("<b>Category</b>", sLabel),
               Paragraph("<b>Issues</b>", sLabel) ]] + owasp_rows,
            colWidths=[W*0.82, W*0.18]
        )
        owasp_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  C_NAVY),
            ("TEXTCOLOR",     (0,0), (-1,0),  C_WHITE),
            ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_WHITE, colors.HexColor("#f8fafc")]),
            ("GRID",          (0,0), (-1,-1), 0.5, C_BORDER),
            ("ALIGN",         (1,0), (1,-1),  "CENTER"),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0), (-1,-1), 7),
            ("BOTTOMPADDING", (0,0), (-1,-1), 7),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
            ("RIGHTPADDING",  (0,0), (-1,-1), 10),
        ]))
        elements.append(owasp_tbl)
        elements.append(Spacer(1, 10))

    # ── CHARTS ───────────────────────────────────────────────
    bar_img = _b64_to_image(bar_b64, W*0.50 - 8, 160)
    pie_img = _b64_to_image(pie_b64, W*0.50 - 8, 160)

    if bar_img or pie_img:
        elements.append(_section_header("Risk Distribution", W))
        chart_row = [[bar_img or "", pie_img or ""]]
        chart_tbl = Table(chart_row, colWidths=[W*0.50, W*0.50])
        chart_tbl.setStyle(TableStyle([
            ("ALIGN",   (0,0), (-1,-1), "CENTER"),
            ("VALIGN",  (0,0), (-1,-1), "MIDDLE"),
            ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ("BOX",     (0,0), (-1,-1), 0.5, C_BORDER),
            ("GRID",    (0,0), (-1,-1), 0.5, C_BORDER),
            ("TOPPADDING",    (0,0), (-1,-1), 10),
            ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ]))
        elements.append(chart_tbl)
        elements.append(Spacer(1, 12))

    # ── DETAILED FINDINGS ─────────────────────────────────────
    if findings:
        elements.append(_section_header("Detailed Security Findings", W))

        for f in findings:
            sev = f.get("severity", "LOW")
            bg, fg, pill_bg = _severity_colors(sev)

            # Finding card header row
            pill = _pill_text(sev, fg, pill_bg)
            header_row = [[
                Paragraph(f"<b>#{f['number']}  {f.get('Name','Unnamed Finding')}</b>",
                          sFindHead),
                pill
            ]]
            header_tbl = Table(header_row, colWidths=[W - 70, 60])
            header_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), bg),
                ("ALIGN",         (1,0), (1,0),   "RIGHT"),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
                ("LEFTPADDING",   (0,0), (-1,-1), 12),
                ("RIGHTPADDING",  (0,0), (-1,-1), 8),
                ("TOPPADDING",    (0,0), (-1,-1), 9),
                ("BOTTOMPADDING", (0,0), (-1,-1), 9),
            ]))

            # Finding detail rows
            detail_rows = [
                [Paragraph("<b>OWASP</b>",      sLabel), Paragraph(f.get("OWASP",""),      sFindBody)],
                [Paragraph("<b>Risk</b>",        sLabel), Paragraph(f.get("Risk",""),        sFindBody)],
                [Paragraph("<b>Resolution</b>",  sLabel), Paragraph(f.get("Resolution",""),  sFindBody)],
                [Paragraph("<b>Source</b>",      sLabel), Paragraph(f.get("Source",""),      sFindBody)],
            ]
            detail_tbl = Table(detail_rows, colWidths=[72, W - 72])
            detail_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), C_WHITE),
                ("GRID",          (0,0), (-1,-1), 0.4, C_BORDER),
                ("VALIGN",        (0,0), (-1,-1), "TOP"),
                ("TOPPADDING",    (0,0), (-1,-1), 6),
                ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                ("LEFTPADDING",   (0,0), (-1,-1), 10),
                ("RIGHTPADDING",  (0,0), (-1,-1), 10),
                ("LINEBELOW",     (0,-1), (-1,-1), 0.4, C_BORDER),
            ]))

            elements.append(KeepTogether([header_tbl, detail_tbl, Spacer(1, 8)]))

    # ── FOOTER ────────────────────────────────────────────────
    elements.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceBefore=12))
    elements.append(Paragraph(
        "Generated by Sentinel Security Scanner  •  Confidential — For Authorised Use Only",
        style("sFooter", fontSize=7.5, textColor=C_MUTED, alignment=TA_CENTER, spaceBefore=4)
    ))

    doc.build(elements)
    buf.seek(0)
    return send_file(
        buf,
        as_attachment=True,
        download_name="Sentinel_Security_Report.pdf",
        mimetype="application/pdf"
    )


# ══════════════════════════════════════════════════════════════
# PDF HELPERS
# ══════════════════════════════════════════════════════════════
def _section_header(title, width):
    """Dark navy section header bar."""
    tbl = Table([[Paragraph(title, ParagraphStyle(
        "SH", fontName="Helvetica-Bold", fontSize=10,
        textColor=colors.white
    ))]], colWidths=[width])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_NAVY),
        ("LEFTPADDING",   (0,0), (-1,-1), 14),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    return tbl


def _stat_card(label, value, accent_color, width):
    """Mini stat card for summary row."""
    inner = [
        [Paragraph(f"<b>{value}</b>", ParagraphStyle(
            "CV", fontName="Helvetica-Bold", fontSize=16,
            textColor=accent_color, alignment=TA_CENTER
        ))],
        [Paragraph(label, ParagraphStyle(
            "CL", fontSize=7.5, textColor=C_MUTED, alignment=TA_CENTER
        ))]
    ]
    t = Table(inner, colWidths=[width - 6])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ("BOX",           (0,0), (-1,-1), 0.5, C_BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
    ]))
    return t


def _severity_colors(sev):
    """Returns (header_bg, text_color, pill_bg) for a severity level."""
    return {
        "HIGH":   (C_HIGH,   C_WHITE, colors.HexColor("#dc2626")),
        "MEDIUM": (C_MED,    C_WHITE, colors.HexColor("#d97706")),
        "LOW":    (C_LOW,    C_WHITE, colors.HexColor("#059669")),
    }.get(sev, (C_NAVY, C_WHITE, C_MUTED))


def _pill_text(label, fg, bg):
    """Small coloured pill label for severity."""
    t = Table([[Paragraph(
        f"<b>{label}</b>",
        ParagraphStyle("Pill", fontSize=8, textColor=C_WHITE,
                       fontName="Helvetica-Bold", alignment=TA_CENTER)
    )]], colWidths=[54])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), bg),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
    ]))
    return t


def _severity_pill(count):
    """Coloured count pill for OWASP table."""
    col = C_HIGH if count >= 3 else (C_MED if count >= 2 else C_LOW)
    t = Table([[Paragraph(
        f"<b>{count}</b>",
        ParagraphStyle("P", fontSize=9, textColor=C_WHITE,
                       fontName="Helvetica-Bold", alignment=TA_CENTER)
    )]], colWidths=[36])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), col),
        ("TOPPADDING",    (0,0), (-1,-1), 3),
        ("BOTTOMPADDING", (0,0), (-1,-1), 3),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
    ]))
    return t


def _b64_to_image(b64_str, w, h):
    """Convert a base64 data URL to a ReportLab Image or None."""
    if not b64_str:
        return None
    try:
        # Strip data:image/png;base64, prefix
        raw = b64_str.split(",", 1)[-1]
        return Image(io.BytesIO(base64.b64decode(raw)), width=w, height=h)
    except Exception:
        return None


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)