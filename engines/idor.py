from urllib.parse import urlparse, parse_qs, urlencode
from utils.diff import diff_ratio

def run(url, ctx):
    results = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    for param in qs:
        val = qs[param][0]

        if not val.isdigit():
            continue

        q = qs.copy()
        q[param] = str(int(val) + 1)

        test_url = parsed._replace(
            query=urlencode(q, doseq=True)
        ).geturl()

        r1 = ctx.get(url)
        r2 = ctx.get(test_url)

        if not r1 or not r2:
            continue

        similarity = diff_ratio(r1.text, r2.text)

        # very similar content = possible unauthorized access
        if similarity > 0.75:
            results.append({
                "type": "IDOR",
                "confidence": "POSSIBLE",
                "severity": "High",
                "url": url,
                "param": param,
                "payload": q[param],
                "reason": "Object ID changed but response remained similar",
                "verify": f'curl "{test_url}"',
                "impact": [
                    "Unauthorized data access",
                    "Horizontal privilege escalation"
                ]
            })

    return results

