# project-26

## Installation & Setup

### Step 1: Install Required Python Packages

```bash
pip install flask flask-cors reportlab playwright beautifulsoup4 python-dotenv
playwright install chromium
```

### Step 2: Configure `.env` File

A `.env` file has been created in the project root. Fill in your actual API keys:

```env
# .env file (fill in your actual values)
GROQ_API_KEY=your_groq_api_key_here
BREVO_API_KEY=your_brevo_api_key_here
BREVO_SENDER_EMAIL=verified-sender@yourdomain.com
BREVO_SENDER_NAME=Sentinel Scanner
```

### Step 3: Run the Application

```bash
python app.py
```

The app will run on `http://127.0.0.1:5001`

---

## How to Get API Keys

### Groq API Key:
1. Visit https://console.groq.com/keys
2. Sign up or log in
3. Create a new API key
4. Copy and paste into `.env` as `GROQ_API_KEY=`

### Brevo API Key:
1. Visit https://app.brevo.com/settings/account/api
2. Generate API key in SMTP/API section
3. Copy and paste into `.env` as `BREVO_API_KEY=`

### Brevo Verified Sender:
1. Visit https://app.brevo.com/senders
2. Verify a sender email address
3. Copy and paste into `.env` as `BREVO_SENDER_EMAIL=`

---

## Features

- **AI Help Button**: Click to get AI-powered vulnerability analysis and remediation guidance
- **3-Dot Share Menu**: Available on scanner and history pages
  - **Mail It**: Send report with attached PDF via email
  - **Download Log**: Save report as .txt file
  - **Share to WhatsApp**: Quick share via WhatsApp
  - **Other Share Options**: Use browser's native sharing
  - **Delete Record**: Remove scan from history

- **Security Scanning**: Comprehensive vulnerability detection with:
  - OWASP Top 10 analysis
  - Static and dynamic scanning
  - Injection payload testing with visual recording
  - Security header validation

---

## Email Sharing Workflow

1. Click "Mail It" from the 3-dot menu
2. Enter sender email (used as reply-to address)
3. Enter receiver email (destination)
4. System generates PDF report and sends via Brevo
5. Each sending can use different sender/receiver pairs

---

## Security Notes

- The `.env` file contains sensitive API keys
- It is added to `.gitignore` to prevent accidental commits
- **Never** share or upload your `.env` file
- **Never** commit `.env` to version control

---

## Troubleshooting

| Error | Solution |
|-------|----------|
| "GROQ_API_KEY is not configured" | Check `.env` file has correct GROQ_API_KEY value |
| "BREVO_API_KEY is not configured" | Check `.env` file has correct BREVO_API_KEY value |
| "BREVO_SENDER_EMAIL is required" | Verify sender email is added to `.env` and verified in Brevo |
| Email fails to send | Check BREVO_SENDER_EMAIL is a verified sender in Brevo account |
| App won't start | Ensure `python-dotenv` is installed: `pip install python-dotenv` |

---

## New Features Added

- `AI Help` button on scanner page:
	- Sends the generated scan report to Groq.
	- Returns vulnerability explanation + fix advice + priority order.

- 3-dot share menu on scanner and history cards:
	- Mail it to user (popup asks sender + receiver email, sends via Brevo API)
	- Mail now includes attached PDF report (not text-only)
	- Download log in system (`.txt`)
	- Share to WhatsApp
	- Other share options (Web Share API if browser supports it)