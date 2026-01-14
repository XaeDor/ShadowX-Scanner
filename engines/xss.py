from urllib.parse import urlparse, parse_qs, urlencode

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert(1)</script>',
    "'><svg/onload=alert(1)>"
]

HTML_TYPES = ["text/html", "application/xhtml+xml"]


def run(url, ctx, base_resp=None):
    results = []

    # base_resp agar diya gaya hai to hi HTML validate karo
    if base_resp:
        ctype = base_resp.headers.get("Content-Type", "").lower()
        if not any(t in ctype for t in HTML_TYPES):
            return results

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    for param in qs:
        for payload in XSS_PAYLOADS:
            q = qs.copy()
            q[param] = payload

            test_url = parsed._replace(
                query=urlencode(q, doseq=True)
            ).geturl()

            r = ctx.get(test_url)
            if not r:
                continue

            r_ctype = r.headers.get("Content-Type", "").lower()
            if not any(t in r_ctype for t in HTML_TYPES):
                continue

            body = r.text.lower()

            # ❌ file handling warnings = NOT XSS
            if "failed to open stream" in body or "fopen(" in body:
                continue

            if payload.lower() in body:
                results.append({
                    "type": "Cross Site Scripting (XSS)",
                    "confidence": "CONFIRMED",
                    "severity": "High",
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "reason": "Payload reflected in HTML response",

                    "verify": f'curl "{test_url}"',

                    "impact": [
                        "Session hijacking",
                        "Account takeover",
                        "Client-side code execution"
                    ]
                })
                break

    return results

