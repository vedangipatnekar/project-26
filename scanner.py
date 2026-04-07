import time
import os
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

# ======================================================
# OWASP TOP 10 (2021) MAPPING
# ======================================================
OWASP_MAP = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)"
}

# ======================================================
# GLOBAL COUNTERS & PATHS
# ======================================================
DUPLICATE_SUPPRESSED = 0
LIVE_VIEW_PATH = os.path.join("static", "live", "live_view.png")

# Ensure directories exist
os.makedirs(os.path.join("static", "history"), exist_ok=True)
os.makedirs(os.path.join("static", "live"), exist_ok=True)

# ======================================================
# HELPER FUNCTIONS
# ======================================================
def add_issue(issues, issue):
    global DUPLICATE_SUPPRESSED
    if not any(i["name"] == issue["name"] and i["source"] == issue["source"] for i in issues):
        issues.append(issue)
    else:
        DUPLICATE_SUPPRESSED += 1

def get_priority_symbol(confidence):
    return {
        "HIGH": "🔴",
        "MEDIUM": "🟠",
        "LOW": "🟢"
    }.get(confidence, "⚪")

def take_snapshot(page):
    """Takes a live screenshot for the frontend dashboard to display."""
    try:
        page.screenshot(path=LIVE_VIEW_PATH)
    except Exception:
        pass 

def show_hud(page, message):
    """
    Injects a visual overlay (HUD) into the DOM.
    Since headless browsers don't record the URL bar, this burns 
    the current action directly into the video recording.
    """
    safe_message = message.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')
    js_code = f"""
    (() => {{
        try {{
            let hud = document.getElementById('sentinel-hud');
            if (!hud) {{
                hud = document.createElement('div');
                hud.id = 'sentinel-hud';
                hud.style.cssText = 'position:fixed; top:20px; left:50%; transform:translateX(-50%); background:rgba(15, 23, 42, 0.95); color:#10b981; font-family:"Courier New", monospace; padding:16px 24px; z-index:2147483647; text-align:center; font-size:16px; border:2px solid #10b981; border-radius:12px; box-shadow:0 8px 32px rgba(0,0,0,0.8); pointer-events:none; max-width:90%; word-wrap:break-word; backdrop-filter:blur(4px);';
                document.body.appendChild(hud);
            }}
            hud.innerHTML = '🛡️ <b style="color:#fff;">SENTINEL ACTION LOG:</b><br><br><span style="color:#f59e0b;">' + '{safe_message}' + '</span>';
        }} catch(e) {{}}
    }})();
    """
    try:
        page.evaluate(js_code)
    except Exception:
        pass

# ======================================================
# 🧠 INTELLIGENT CONFIDENCE SCORING
# ======================================================
def intelligent_confidence_scoring(issue, url, html_content, headers):
    score = 0

    if issue["confidence"] == "HIGH": score += 3
    elif issue["confidence"] == "MEDIUM": score += 2
    else: score += 1

    if url.startswith("https://"): score += 1
    if "text/html" in headers.get("content-type", ""): score += 1

    if "XSS" in issue["name"] and "<script>" in html_content:
        score += 2

    if "Missing Security Header" in issue["name"]:
        score += 2

    if issue["source"] == "Static":
        score -= 1

    if score >= 5: issue["confidence"] = "HIGH"
    elif score >= 3: issue["confidence"] = "MEDIUM"
    else: issue["confidence"] = "LOW"

    return issue

# ======================================================
# 🔎 INJECTION TESTING MODULE (PLAYWRIGHT VISUAL)
# ======================================================
def injection_test(url, page):
    issues = []
    payloads = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "<script>alert(1)</script>",
        "`; ls`",
        "$(whoami)"
    ]

    for payload in payloads:
        try:
            print(f"[SYSTEM] Probing payload: {payload}")
            
            # Step 1: URL Injection
            test_url = url + "?test=" + payload
            page.goto(test_url, timeout=5000)
            
            # Show the HUD banner for the URL injection so it records in the video
            show_hud(page, f"https://en.wikipedia.org/wiki/Injection_%28medicine%29<br>Testing Parameter: ?test={payload}")
            take_snapshot(page)
            time.sleep(2) # Give the video time to record the banner clearly
            
            # Step 2: Visual UI Injection (Makes the bot type on screen)
            try:
                # Find input fields on the screen (search bars, text boxes)
                inputs = page.locator("input[type='text'], input[type='search'], input:not([type])").all()
                
                if inputs:
                    # Target the first visible input field
                    target_input = inputs[0]
                    target_input.highlight() 
                    
                    show_hud(page, f"[FORM INJECTION]<br>Targeting visible input field...")
                    take_snapshot(page)
                    time.sleep(1)
                    
                    # Literally type the payload so it shows in the video
                    target_input.fill(payload)
                    show_hud(page, f"[TYPING PAYLOAD]<br>{payload}")
                    take_snapshot(page)
                    time.sleep(1.5) 
                    
                    # Hit enter to submit the malicious form
                    show_hud(page, f"[SUBMITTING]<br>Executing attack payload...")
                    target_input.press("Enter")
                    time.sleep(1.5) 
            except Exception:
                pass # If no inputs are found, just continue
            
            # Take final snapshot of the result
            show_hud(page, f"[ANALYZING]<br>Evaluating server response...")
            take_snapshot(page)
            time.sleep(1)
            
            content = page.content()

            # Check if payload was reflected
            if payload in content:
                add_issue(issues, {
                    "name": "Improper Input Validation (Injection)",
                    "risk": "User input is reflected without sanitization",
                    "resolution": "Validate and sanitize all user inputs",
                    "confidence": "HIGH",
                    "owasp": "A03",
                    "source": "Dynamic"
                })
                break
        except PlaywrightTimeoutError:
            continue
        except Exception:
            continue
            
    return issues

# ======================================================
# STATIC ANALYSIS
# ======================================================
def static_scan(html):
    issues = []
    soup = BeautifulSoup(html, "html.parser")

    for form in soup.find_all("form"):
        method = form.get("method", "").lower()
        if method == "post" and not form.find("input", {"name": "csrf"}):
            add_issue(issues, {
                "name": "Missing CSRF Protection",
                "risk": "POST form without CSRF token",
                "resolution": "Implement CSRF tokens",
                "confidence": "MEDIUM",
                "owasp": "A01",
                "source": "Static"
            })

    for inp in soup.find_all("input"):
        if inp.get("type") in ["text", "search"] and not inp.get("pattern"):
            add_issue(issues, {
                "name": "Weak Input Validation",
                "risk": "User input not validated",
                "resolution": "Apply strict validation",
                "confidence": "LOW",
                "owasp": "A03",
                "source": "Static"
            })

    for script in soup.find_all("script"):
        if script.string and "function" in script.string:
            add_issue(issues, {
                "name": "Inline JavaScript Detected",
                "risk": "Increased XSS risk",
                "resolution": "Move scripts to external files",
                "confidence": "LOW",
                "owasp": "A03",
                "source": "Static"
            })
            break

    return issues

# ======================================================
# DYNAMIC ANALYSIS
# ======================================================
def dynamic_scan(url, headers):
    issues = []

    if not url.startswith("https://"):
        add_issue(issues, {
            "name": "Website not using HTTPS",
            "risk": "Sensitive data transmitted insecurely",
            "resolution": "Enable HTTPS",
            "confidence": "HIGH",
            "owasp": "A02",
            "source": "Dynamic"
        })

    content_type = headers.get("content-type", "")

    for header in ["content-security-policy", "x-frame-options", "x-content-type-options"]:
        if header not in headers and "text/html" in content_type:
            add_issue(issues, {
                "name": f"Missing Security Header: {header.upper()}",
                "risk": "Browser protections disabled",
                "resolution": f"Configure {header}",
                "confidence": "MEDIUM",
                "owasp": "A05",
                "source": "Dynamic"
            })

    if "server" in headers and len(headers["server"]) > 3:
        add_issue(issues, {
            "name": "Server Version Disclosure",
            "risk": "Technology fingerprinting",
            "resolution": "Hide server banner",
            "confidence": "LOW",
            "owasp": "A06",
            "source": "Dynamic"
        })

    cookies = headers.get("set-cookie", "")
    if cookies:
        if "HttpOnly" not in cookies:
            add_issue(issues, {
                "name": "Missing HttpOnly Cookie Flag",
                "risk": "Session accessible via JavaScript",
                "resolution": "Enable HttpOnly",
                "confidence": "MEDIUM",
                "owasp": "A07",
                "source": "Dynamic"
            })

    return issues

# ======================================================
# MAIN SCANNER ENGINE (PLAYWRIGHT UPGRADE)
# ======================================================
def scan_website(url, scan_id="manual"):
    global DUPLICATE_SUPPRESSED
    DUPLICATE_SUPPRESSED = 0

    print(f"\n🔍 Scanning: {url}")
    print("=" * 60)

    scan_start = time.time()
    all_issues = []
    video_filename = f"{scan_id}.webm"
    
    # ─── PLAYWRIGHT BROWSER AUTOMATION ───
    with sync_playwright() as p:
        print("[SYSTEM] Booting Headless Chromium Browser...")
        browser = p.chromium.launch(headless=True)
        
        context = browser.new_context(
            record_video_dir="static/history",
            record_video_size={"width": 1280, "height": 720}
        )
        page = context.new_page()

        captured_headers = {}
        def handle_response(response):
            if response.url == url:
                captured_headers.update(response.headers)
        
        page.on("response", handle_response)

        try:
            print(f"[SYSTEM] Navigating to {url}...")
            page.goto(url, timeout=15000)
            page.wait_for_load_state("networkidle", timeout=5000)
            
            show_hud(page, f"[INITIALIZING]<br>Connected to target: {url}")
            take_snapshot(page)
            time.sleep(2)
            
            html_content = page.content()
            
            print("[SYSTEM] Running Static Analysis on DOM...")
            static_issues = static_scan(html_content)
            
            print("[SYSTEM] Running Dynamic Analysis on Headers...")
            dynamic_issues = dynamic_scan(url, captured_headers)
            
            print("[SYSTEM] Executing Injection Payloads visually...")
            inj_issues = injection_test(url, page)
            
            show_hud(page, "[COMPLETED]<br>Scan finished. Generating report...")
            take_snapshot(page)
            time.sleep(1)
            
            all_issues = static_issues + dynamic_issues + inj_issues
            
            page.close()
            temp_video_path = page.video.path()
            context.close()
            browser.close()
            
            if temp_video_path and os.path.exists(temp_video_path):
                final_video_path = os.path.join("static", "history", video_filename)
                if os.path.exists(final_video_path):
                    os.remove(final_video_path)
                os.rename(temp_video_path, final_video_path)

        except Exception as e:
            print(f"❌ Connection Error: {str(e)}")
            context.close()
            browser.close()
            return None

    # ─── SCORING & REPORT GENERATION ───
    for issue in all_issues:
        intelligent_confidence_scoring(issue, url, html_content, captured_headers)
    
        # Delete low-level junk to fix the False Positive rate
        all_issues = [i for i in all_issues if not (i["confidence"] == "LOW" and i["source"] == "Static")]
    
    owasp_count = {}
    for issue in all_issues:
        owasp_id = issue["owasp"]
        owasp_count[owasp_id] = owasp_count.get(owasp_id, 0) + 1

    priority_order = {"HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_issues.sort(key=lambda x: priority_order.get(x["confidence"], 4))

    total = len(all_issues)
    false_positives = len([i for i in all_issues if i["confidence"] == "LOW"])
    false_positive_rate = (false_positives / total * 100) if total else 0

    print("HIGH : 🔴")
    print("MEDIUM : 🟠")
    print("LOW : 🟢")
    
    print("\n📊 SCAN SUMMARY")
    print("=" * 60)
    print(f"Total Threats Found        : {total}")
    print(f"Duplicate Risks Suppressed : {DUPLICATE_SUPPRESSED}")
    print(f"False Positives (LOW)      : {false_positives}")
    print(f"False Positive Rate        : {false_positive_rate:.2f}%")

    print("\n⏱️ SCAN PERFORMANCE METRICS")
    print("=" * 60)
    print(f"Total Scan Time            : {time.time() - scan_start:.2f} seconds")

    print("\n📚 OWASP TOP 10 SUMMARY")
    print("=" * 60)
    for owasp_id, count in sorted(owasp_count.items()):
        print(f"{owasp_id} - {OWASP_MAP.get(owasp_id)} : {count}")

    for i, issue in enumerate(all_issues, 1):
        symbol = get_priority_symbol(issue["confidence"])
        print(f"\n{symbol} Threat #{i}")
        print(f"Name       : {issue['name']}")
        print(f"OWASP      : {issue['owasp']} - {OWASP_MAP.get(issue['owasp'])}")
        print(f"Risk       : {issue['risk']}")
        print(f"Resolution : {issue['resolution']}")
        print(f"Source     : {issue['source']}")

    return video_filename

if __name__ == "__main__":
    target = input("Enter website URL (https://example.com): ")
    scan_website(target)