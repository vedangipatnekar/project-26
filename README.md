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
GMAIL_SENDER_EMAIL=your-gmail-address@gmail.com
GMAIL_APP_PASSWORD=your-google-app-password
GMAIL_SENDER_NAME=Sentinel Scanner
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

### Google App Password:
1. Enable **2-Step Verification** on your Google Account (Security settings).
2. Go to the **App passwords** section in your Google Account Security settings.
3. Generate a new app password (select 'Mail' or 'Other' and name it 'Sentinel').
4. Copy the generated 16-character password and paste it into `.env` as `GMAIL_APP_PASSWORD=`.
5. Enter your Gmail address in `.env` as `GMAIL_SENDER_EMAIL=`.

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
2. Enter receiver email (destination)
3. System generates PDF report and sends it using Gmail SMTP using the configured Google App Password
4. The scan details and the PDF attachment are delivered to the recipient

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
| "GMAIL_SENDER_EMAIL or GMAIL_APP_PASSWORD is not configured" | Check `.env` file has correct values |
| Email fails to send / SMTP error | Ensure GMAIL_APP_PASSWORD is correct and 2-Step Verification is enabled on the Gmail account |
| App won't start | Ensure `python-dotenv` is installed: `pip install python-dotenv` |

---

## New Features Added

- `AI Help` button on scanner page:
	- Sends the generated scan report to Groq.
	- Returns vulnerability explanation + fix advice + priority order.

- 3-dot share menu on scanner and history cards:
	- Mail it to user (popup asks receiver email, sends via Google App Password / SMTP)
	- Mail now includes attached PDF report (not text-only)
	- Download log in system (`.txt`)
	- Share to WhatsApp
	- Other share options (Web Share API if browser supports it)