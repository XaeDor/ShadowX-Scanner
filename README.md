 🕷️ ShadowX-Scanner

ShadowX-Scanner is a modular web vulnerability scanner designed for learning, labs, CTFs, and bug bounty practice.
It combines static crawling, JavaScript-based crawling, forced endpoint discovery, and multiple vulnerability engines in a safe & controllable way.

⚠️ Educational & Authorized Use Only
Scan only owned targets, labs, or platforms that explicitly allow testing.

✨ Features

✔ Static HTML crawler
✔ JavaScript crawler (Playwright-powered)
✔ Forced endpoint discovery
✔ Vulnerability engines:

SQL Injection

XSS

LFI

SSRF

Open Redirect

IDOR

✔ Safe Mode (low & slow scanning)
✔ Aggressive Mode (labs / CTF only)
✔ CLI-controlled limits (URLs, delay, threads)
✔ Clean Ctrl+C handling
✔ Modular & extensible architecture

📁 Project Structure
ShadowX-Scanner/
│
├── main.py
├── crawler.py
├── js_crawler.py
├── context.py
├── output.py
│
├── engines/
│   ├── sqli.py
│   ├── xss.py
│   ├── lfi.py
│   ├── ssrf.py
│   ├── redirect.py
│   ├── idor.py
│   └── forced_endpoints.py
│
├── requirements.txt
└── README.md

🛠️ Installation
1️⃣ Clone Repository

git clone https://github.com/XaeDor/ShadowX-Scanner.git

cd ShadowX-Scanner

2️⃣ Install Python Dependencies

pip install -r requirements.txt

3️⃣ (Optional but Recommended) Install Playwright

Required for JavaScript-heavy websites.

pip install playwright
playwright install chromium


If Playwright is not installed, ShadowX will still work using static crawling.

🚀 Usage

Basic Scan
python3 main.py -d example.com

Limit URLs
python3 main.py -d example.com -u 20

Safe Mode (Recommended for real websites)
python3 main.py -d example.com --safe

Aggressive Mode (CTF / LAB ONLY)
python3 main.py -d testphp.vulnweb.com --aggressive

Delay Control
python3 main.py -d example.com --delay 2

🧾 CLI Options
Option	Description
-d, --domain	Target domain
-u, --max-urls	Max URLs to scan
-t, --threads	Concurrent threads
--delay	Delay between requests
--safe	Low & slow scanning
--aggressive	Labs / CTF only

Run:

python3 main.py -h

📊 Output

Live scan progress

Categorized vulnerabilities

Confidence levels (LOW / MEDIUM / HIGH)

Final scan summary

⚠️ Disclaimer

This tool is created strictly for educational purposes.
The author is not responsible for misuse or illegal activities.

👨‍💻 Author
(ShadowX aka XaeDor)
GitHub: https://github.com/XaeDor

⭐ Support

If you like this project:

⭐ Star the repo

🍴 Fork it

🐞 Open issues / PRs
