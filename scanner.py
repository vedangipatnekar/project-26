import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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
# GLOBAL COUNTERS
# ======================================================
DUPLICATE_SUPPRESSED = 0

# ======================================================
# HELPER FUNCTIONS
# ======================================================
def add_issue(issues, issue):
    global DUPLICATE_SUPPRESSED
    if issue not in issues:
        issues.append(issue)
    else:
        DUPLICATE_SUPPRESSED += 1

def get_priority_symbol(confidence):
    return {
        "HIGH": "🔴",
        "MEDIUM": "🟠",
        "LOW": "🟢"
    }.get(confidence, "⚪")

def create_session():
    """Creates a requests session with retry logic and browser-like headers."""
    session = requests.Session()
    
    # Set a real User-Agent to avoid being blocked by Heroku/Cloudflare
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })

    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

# ======================================================
# 🧠 INTELLIGENT CONFIDENCE SCORING
# ======================================================
def intelligent_confidence_scoring(issue, url, response):
    score = 0

    if issue["confidence"] == "HIGH":
        score += 3
    elif issue["confidence"] == "MEDIUM":
        score += 2
    else:
        score += 1

    if url.startswith("https://"):
        score += 1

    if "text/html" in response.headers.get("Content-Type", ""):
        score += 1

    if "XSS" in issue["name"] and "<script>" in response.text:
        score += 2

    if "Missing Security Header" in issue["name"]:
        score += 2

    if "Cookie" in issue["name"] and "Set-Cookie" in response.headers:
        score += 1

    if issue["source"] == "Static":
        score -= 1

    if score >= 6:
        issue["confidence"] = "HIGH"
    elif score >= 4:
        issue["confidence"] = "MEDIUM"
    else:
        issue["confidence"] = "LOW"

    return issue


"""
i am also add this code where it show low false positive,
if you want just remove the comment and delete the upper function [intelligent_confidence_scoring].

def intelligent_confidence_scoring(issue, url, response):
    score = 0

    # Base confidence from the test itself
    if issue["confidence"] == "HIGH":
        score += 2  # Reduced from 3
    elif issue["confidence"] == "MEDIUM":
        score += 1  # Reduced from 2

    # Environmental checks
    if url.startswith("https://"):
        score += 1

    # Specific vulnerability confirmation
    if "XSS" in issue["name"] and "<script>" in response.text:
        score += 2

    if "Missing Security Header" in issue["name"]:
        score += 1 # Reduced from 2

    # Penalty for Static analysis (often higher FP rate)
    if issue["source"] == "Static":
        score -= 2 # Increased penalty from -1

    # --- UPDATED THRESHOLDS ---
    # We increase the requirements so most items fall into "LOW"
    if score >= 8: # Was 6
        issue["confidence"] = "HIGH"
    elif score >= 6: # Was 4
        issue["confidence"] = "MEDIUM"
    else:
        issue["confidence"] = "LOW"

    return issue
"""

# ======================================================
# 🔎 INJECTION TESTING MODULE
# ======================================================
def injection_test(url, session):
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
            test_url = url + "?test=" + payload
            response = session.get(test_url, timeout=5)

            if payload in response.text:
                add_issue(issues, {
                    "name": "Improper Input Validation (Injection)",
                    "risk": "User input is reflected without sanitization",
                    "resolution": "Validate and sanitize all user inputs",
                    "confidence": "HIGH",
                    "owasp": "A03",
                    "source": "Dynamic"
                })
                break

            if response.status_code == 500:
                add_issue(issues, {
                    "name": "Possible Injection Vulnerability",
                    "risk": "Server error triggered by crafted input",
                    "resolution": "Use parameterized queries and strict validation",
                    "confidence": "MEDIUM",
                    "owasp": "A03",
                    "source": "Dynamic"
                })
                break
        except:
            continue
    return issues

# ======================================================
# STATIC ANALYSIS
# ======================================================
def static_scan(url, response):
    issues = []
    soup = BeautifulSoup(response.text, "html.parser")

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
def dynamic_scan(url, response, session):
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

    headers = response.headers
    content_type = headers.get("Content-Type", "")

    for header in ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]:
        if header not in headers and "text/html" in content_type:
            add_issue(issues, {
                "name": f"Missing Security Header: {header}",
                "risk": "Browser protections disabled",
                "resolution": f"Configure {header}",
                "confidence": "MEDIUM",
                "owasp": "A05",
                "source": "Dynamic"
            })

    if "Server" in headers and len(headers["Server"]) > 3:
        add_issue(issues, {
            "name": "Server Version Disclosure",
            "risk": "Technology fingerprinting",
            "resolution": "Hide server banner",
            "confidence": "LOW",
            "owasp": "A06",
            "source": "Dynamic"
        })

    # Basic XSS Reflector test
    try:
        payload = "<script>alert(1)</script>"
        test = session.get(url, params={"x": payload}, timeout=5)
        if payload in test.text and "text/html" in test.headers.get("Content-Type", ""):
            add_issue(issues, {
                "name": "Reflected XSS",
                "risk": "User input reflected",
                "resolution": "Encode output",
                "confidence": "HIGH",
                "owasp": "A03",
                "source": "Dynamic"
            })
    except:
        pass

    return issues

# ======================================================
# EXTENDED DYNAMIC ANALYSIS
# ======================================================
def extended_dynamic_scan(url, response):
    issues = []
    cookies = response.headers.get("Set-Cookie", "")
    
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

        if "Secure" not in cookies and url.startswith("https"):
            add_issue(issues, {
                "name": "Missing Secure Cookie Flag",
                "risk": "Cookies sent over insecure channel",
                "resolution": "Enable Secure flag",
                "confidence": "MEDIUM",
                "owasp": "A07",
                "source": "Dynamic"
            })

    if "Index of /" in response.text:
        add_issue(issues, {
            "name": "Directory Listing Enabled",
            "risk": "Sensitive files exposed",
            "resolution": "Disable directory listing",
            "confidence": "MEDIUM",
            "owasp": "A05",
            "source": "Dynamic"
        })

    return issues

# ======================================================
# MAIN SCANNER ENGINE
# ======================================================
def scan_website(url):
    global DUPLICATE_SUPPRESSED
    DUPLICATE_SUPPRESSED = 0

    print("\n🔍 Scanning:", url)
    print("=" * 60)

    scan_start = time.time()
    session = create_session()

    try:
        response = session.get(url, timeout=15)
        # Check if the site returned a 503 or other error
        if response.status_code == 503:
            print("❌ Error: Site returned 503 (Service Unavailable). The target is likely overloaded or blocking automated scans.")
            return
        response.raise_for_status()
    except Exception as e:
        print(f"❌ Connection Error: {str(e)}")
        print("\nTip: If you're scanning Juice Shop, it frequently goes down or blocks scripts. Try a local URL or testphp.vulnweb.com.")
        return

    # Phase 1: Static Scan
    static_issues = static_scan(url, response)
    
    # Phase 2: Dynamic Scan
    dynamic_issues = dynamic_scan(url, response, session)
    
    # Phase 3: Extended Dynamic
    extended_issues = extended_dynamic_scan(url, response)
    
    # Phase 4: Injection Testing
    inj_issues = injection_test(url, session)

    all_issues = static_issues + dynamic_issues + extended_issues + inj_issues

    # Phase 5: Scoring and Sorting
    for issue in all_issues:
        intelligent_confidence_scoring(issue, url, response)

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

if __name__ == "__main__":
    target = input("Enter website URL (https://example.com): ")
    scan_website(target)