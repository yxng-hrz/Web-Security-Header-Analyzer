# 🌐 Web Security Header Analyzer

A small command-line tool that analyzes **web security headers** for a given URL and produces a **security score** and a short report.

It checks for common security mechanisms such as:

- HTTPS usage  
- HSTS (Strict-Transport-Security)  
- Content-Security-Policy (CSP)  
- X-Frame-Options  
- X-Content-Type-Options  
- Referrer-Policy  
- Cookie security flags (Secure & HttpOnly)

This project is designed to showcase security awareness and governance skills for roles like **Security Engineer**, **RSSI/CISO**, or **IT Manager/DSI**.

---

## ✨ Features

- Analyze a single URL from the command line.
- Automatically normalizes URLs (adds `https://` if missing).
- Computes a **score (0–100)** and a **grade (A–E)** based on headers.
- Outputs either:
  - human-readable **text**, or
  - **Markdown** report for documentation / wiki / audit notes.

---

## 🛠️ Installation

### Requirements

- Python **3.8+**
- `requests` library

Install dependencies:

```bash
pip install requests
Clone the repository
git clone https://github.com/<your-username>/web-security-header-analyzer.git
cd web-security-header-analyzer
```

🚀 Usage
Show help:

```
python web_security_header_analyzer.py --help
Basic analysis (text output):

python web_security_header_analyzer.py https://example.com
Generate a Markdown report:

python web_security_header_analyzer.py https://example.com --format markdown
Save the report to a file:

python web_security_header_analyzer.py https://example.com --format markdown --output example_report.md
```

📌 Example (text output)
Web Security Header Analysis for: https://example.com
Final URL: https://example.com
HTTPS: YES
Score: 65 / 100 (grade C)

Findings:
  [OK ] WEB-HTTPS-01 - HTTPS enforced (HIGH)
      Final URL uses HTTPS: https://example.com
  [FAIL] WEB-HSTS-01 - HTTP Strict Transport Security (HSTS) (HIGH)
      HSTS header is missing. Browsers may access the site over plain HTTP after redirects.
  [FAIL] WEB-CSP-01 - Content Security Policy (CSP) (HIGH)
      CSP header is missing. This increases the risk of XSS and content injection.

🧩 How it works
The tool:

Fetches the target URL using requests.

Follows redirects and inspects the final URL and response headers.

Evaluates a set of governance-style checks (HTTPS, HSTS, CSP, cookies...).

Computes a numeric score and assigns a grade:

A: ≥ 90

B: ≥ 80

C: ≥ 65

D: ≥ 50

E: < 50
