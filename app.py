from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import io
import sys
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


# ✅ IMPORTANT: make sure scanner.py exists in SAME folder
import scanner  

app = Flask(__name__)
CORS(app)

# ==============================
# STORE LAST SCAN OUTPUT
# ==============================
LAST_REPORT = ""

# ==============================
# SCAN ENDPOINT
# ==============================
@app.route("/scan", methods=["POST"])
def scan():
    global LAST_REPORT

    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "URL missing"}), 400

    url = data["url"]

    buffer = io.StringIO()
    old_stdout = sys.stdout

    try:
        sys.stdout = buffer
        scanner.scan_website(url)
        LAST_REPORT = buffer.getvalue()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        sys.stdout = old_stdout   # ✅ ALWAYS restore stdout

    return jsonify({"report": LAST_REPORT})

# ==============================
# PDF DOWNLOAD ENDPOINT
# ==============================
@app.route("/download-pdf", methods=["GET"])
def download_pdf():
    if not LAST_REPORT:
        return jsonify({"error": "No scan data available"}), 400

    file_name = "scan_report.pdf"

    c = canvas.Canvas(file_name, pagesize=A4)
    text = c.beginText(40, 800)

    for line in LAST_REPORT.split("\n"):
        text.textLine(line)

    c.drawText(text)
    c.showPage()
    c.save()

    return send_file(file_name, as_attachment=True)

# ==============================
# RUN SERVER
# ==============================
if __name__ == "__main__":
   app.run(host="0.0.0.0", port=5001, debug=False)

