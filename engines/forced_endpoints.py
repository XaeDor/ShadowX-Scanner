from urllib.parse import urljoin
import re

# =========================================================
# MASSIVE REAL-WORLD ENDPOINT WORDLIST (CURATED)
# =========================================================

COMMON_ENDPOINTS = [

    # ---- Auth / User ----
    "login", "login.php", "login.html", "signin", "signup",
    "register", "register.php", "logout", "auth", "auth/login",
    "user/login", "user/register", "account", "myaccount",

    # ---- Admin / Panel ----
    "admin", "admin/", "admin.php", "admin.html",
    "administrator", "adminpanel", "admin-panel",
    "dashboard", "dashboard/", "panel", "panel/",
    "manage", "management", "controlpanel", "cpanel",
    "backend", "staff", "moderator",

    # ---- CMS / Frameworks ----
    "wp-admin", "wp-login.php", "wp-config.php",
    "phpmyadmin", "pma", "drupal", "joomla",
    "laravel.log", "storage/logs/laravel.log",

    # ---- API ----
    "api", "api/", "api/v1", "api/v2", "api/v3",
    "rest", "rest/v1", "graphql", "swagger",
    "swagger-ui", "v1/users", "v1/admin",

    # ---- Dev / Test / Stage ----
    "dev", "test", "testing", "stage", "staging",
    "uat", "debug", "debug.php", "phpinfo.php",

    # ---- Files / Uploads ----
    "uploads", "upload", "files", "docs",
    "documents", "private", "downloads",

    # ---- Sensitive ----
    ".env", ".env.local", ".env.prod",
    ".git/", ".git/config",
    "config.php", "config.old", "config.bak",
    "settings.php",

    # ---- Backups / Dumps ----
    "backup", "backup.zip", "backup.tar.gz",
    "site.zip", "www.zip", "public_html.zip",
    "db.sql", "database.sql", "dump.sql",

    # ---- Logs ----
    "error.log", "access.log", "debug.log",
    "logs", "log",

    # ---- Infra ----
    "server-status", "status", "health", "metrics",

    # ---- Documents (often exposed) ----
    "invoice.pdf", "report.pdf", "users.pdf",
    "data.pdf", "backup.pdf"
]

# =========================================================
# EXTENSIONS FOR BACKUP / LEAK PROBING
# =========================================================

BACKUP_EXTENSIONS = [
    ".bak", ".old", ".backup", ".zip", ".tar",
    ".tar.gz", ".7z", ".rar", "~"
]

# =========================================================
# CONTENT SIGNS
# =========================================================

LOGIN_SIGNS = ["login", "password", "username", "signin"]
ADMIN_SIGNS = ["admin", "dashboard", "control panel", "manage"]
SENSITIVE_SIGNS = ["db_", "password", "secret", "aws", "key"]

# =========================================================
# ENGINE
# =========================================================

def run(base_url, ctx):
    findings = []
    tested = set()

    print("\n[+] Forced Endpoint Discovery Started")
    print("[*] Probing sensitive & hidden endpoints...\n")

    # =========================
    # 1️⃣ Endpoint brute discovery
    # =========================
    for ep in COMMON_ENDPOINTS:
        url = urljoin(base_url.rstrip("/") + "/", ep)

        if url in tested:
            continue
        tested.add(url)

        r = ctx.get(url)
        if not r:
            continue

        if r.status_code in (200, 401, 403):
            body = r.text.lower() if r.text else ""
            confidence = "LOW"
            reason = f"Endpoint accessible (HTTP {r.status_code})"

            if any(x in body for x in LOGIN_SIGNS):
                confidence = "MEDIUM"
                reason = "Login interface detected"

            if any(x in body for x in ADMIN_SIGNS):
                confidence = "MEDIUM"
                reason = "Admin / Dashboard interface detected"

            if any(x in body for x in SENSITIVE_SIGNS):
                confidence = "HIGH"
                reason = "Sensitive keywords found in response"

            print(f"[FOUND] {url} → {r.status_code}")

            findings.append({
                "type": "Forced Endpoint",
                "confidence": confidence,
                "url": url,
                "param": "-",
                "reason": reason
            })

        # =========================
        # 2️⃣ Backup extension probing
        # =========================
        for ext in BACKUP_EXTENSIONS:
            b_url = url + ext
            if b_url in tested:
                continue
            tested.add(b_url)

            r2 = ctx.get(b_url)
            if r2 and r2.status_code == 200 and len(r2.text) > 50:
                print(f"[FOUND] {b_url} → 200 (backup)")

                findings.append({
                    "type": "Sensitive Backup File",
                    "confidence": "HIGH",
                    "url": b_url,
                    "param": "-",
                    "reason": "Backup / archived file publicly accessible"
                })

    # =========================
    # 3️⃣ robots.txt harvesting
    # =========================
    robots = urljoin(base_url.rstrip("/") + "/", "robots.txt")
    r = ctx.get(robots)

    if r and r.status_code == 200:
        paths = re.findall(r"Disallow:\s*(.*)", r.text, re.I)

        for p in paths:
            p = p.strip()
            if not p or p == "/":
                continue

            full = urljoin(base_url.rstrip("/") + "/", p.lstrip("/"))

            findings.append({
                "type": "Hidden Endpoint (robots.txt)",
                "confidence": "MEDIUM",
                "url": full,
                "param": "-",
                "reason": "Hidden path disclosed via robots.txt"
            })
            
    print("\n[+] Forced Endpoint Discovery Finished")
    print(f"    → Total Endpoints Found : {len(findings)}")
    print("-" * 55)


    return findings

