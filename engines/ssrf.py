# engines/ssrf.py (FIXED)

from urllib.parse import urlparse, parse_qs, urlencode
from utils.payloads import SSRF

SSRF_SIGNS = [
    "root:x:",
    "metadata",
    "instance-id",
    "cpu cores",
    "localhost services"
]

def run(url, ctx):
    results = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    for p in qs:
        for payload in SSRF:
            q = qs.copy()
            q[p] = payload
            test = parsed._replace(query=urlencode(q, doseq=True)).geturl()
            r = ctx.get(test)

            if not r:
                continue

            body = r.text.lower()

            # ❌ SQL error → NOT SSRF
            if "sql syntax" in body or "mysql" in body:
                continue

            if any(sig in body for sig in SSRF_SIGNS):
                results.append({
                    "type": "SSRF",
                    "confidence": "POSSIBLE",
                    "url": url,
                    "param": p,
                    "payload": payload,
                    "reason": "Internal service response observed",
                    "verify": f'curl "{test}"'
                })
                break

    return results

