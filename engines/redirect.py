# engines/redirect.py (FIXED)

from urllib.parse import urlparse, parse_qs, urlencode
from utils.payloads import REDIRECT

def run(url, ctx):
    results = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    for p in qs:
        for payload in REDIRECT:
            q = qs.copy()
            q[p] = payload
            test = parsed._replace(query=urlencode(q, doseq=True)).geturl()
            r = ctx.get(test)

            if not r:
                continue

            # ✅ STRICT redirect check
            if r.status_code in (301, 302, 307, 308):
                location = r.headers.get("Location", "")
                if location.startswith("http") and "evil.com" in location:
                    results.append({
                        "type": "Open Redirect",
                        "confidence": "CONFIRMED",
                        "url": url,
                        "param": p,
                        "payload": payload,
                        "reason": "External redirect via Location header",
                        "verify": f'curl -I "{test}"'
                    })
                    break

    return results

