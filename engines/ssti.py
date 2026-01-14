from urllib.parse import urlparse, parse_qs, urlencode
from utils.diff import diff_ratio

# Known SSTI evaluation payloads (safe math-based)
SSTI_PAYLOADS = {
    "{{7*7}}": "49",                 # Jinja2 / Twig
    "${7*7}": "49",                  # Velocity
    "#{7*7}": "49",                  # Spring EL
    "<%= 7*7 %>": "49",              # ERB
    "${{7*7}}": "49"                 # Generic
}

# If these appear, it is NOT SSTI
BLOCKING_ERRORS = [
    "sql syntax",
    "mysql",
    "warning:",
    "odbc",
    "syntax error"
]

def run(url, ctx):
    results = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    base_resp = ctx.get(url)
    if not base_resp:
        return results

    for param in qs:
        for payload, expected in SSTI_PAYLOADS.items():
            q = qs.copy()
            q[param] = payload

            test_url = parsed._replace(
                query=urlencode(q, doseq=True)
            ).geturl()

            r = ctx.get(test_url)
            if not r:
                continue

            body = r.text.lower()

            # ❌ SQL / backend error → not SSTI
            if any(err in body for err in BLOCKING_ERRORS):
                continue

            # ❌ Raw payload reflected → not evaluated
            if payload.lower() in body:
                continue

            # ✅ Template evaluated
            if expected in r.text:
                ratio = diff_ratio(base_resp.text, r.text)

                results.append({
                    "type": "Server-Side Template Injection (SSTI)",
                    "confidence": "CONFIRMED",
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "evidence": f"Template expression evaluated to {expected}",
                    "diff": f"{ratio:.2f}",
                    "impact": [
                        "Remote code execution (depending on template engine)",
                        "Sensitive data exposure"
                    ],
                    "severity": "High",
                    "curl": f'curl "{test_url}"'
                })
                break

    return results

