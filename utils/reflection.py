def is_reflected(payload, response):
    if not response:
        return False

    body = response.lower()
    p = payload.lower()

    # direct reflection
    if p in body:
        return True

    # decoded reflection (basic)
    try:
        from html import unescape
        if unescape(p) in unescape(body):
            return True
    except:
        pass

    return False

