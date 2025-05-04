# 🔍 Advanced XSS Scanner — Node.js

This is a high-performance, multi-threaded reflected XSS vulnerability scanner built with Node.js. It loads payloads from a file, injects them into target URLs, detects reflections, scores the severity using CVSS, and flags critical vulnerabilities.

## ✨ Features

- 🧠 Auto-generates payloads using templates
- 📄 Reads from `payloads.txt`
- ⚡ Scans URLs with concurrency
- 🔎 Detects reflections in body, attributes, or script tags
- 📊 CVSS severity scoring
- 🚨 Flags critical XSS and exits
- 📁 Saves detailed results in `scan_results.json`

## 🛠️ Installation

```bash
git clone [https://github.com/your-username/xss-scanner.git](https://github.com/KCGOODLY/XSSscanner)
cd xss-scanner
npm install

----------------------------------------

🧪 Usage
Edit Targets
Inside scanner.js, set your targets:

- const targetURLs = [
  "https://example.com/search?q=",
];

----------------------------------------

Create a payloads.txt File
-example:
<script>alert({n})</script>
<img src=x onerror=alert({n})>
"><svg/onload=alert({n})>

----------------------------------------

-Run the Scanner:
node scanner.js

----------------------------------------

📂 Output
scan_results.json: All findings

critical_results.json: Only critical issues (CVSS ≥ 8)

----------------------------------------

⚠️ Legal Warning
This tool is for educational purposes or authorized penetration testing. Do not use it on websites without explicit permission. Unauthorized scanning is illegal.

📧 Contact
Made by a young cybersecurity enthusiast. Contributions welcome!
