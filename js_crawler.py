from playwright.sync_api import sync_playwright
from urllib.parse import urlparse

def js_crawl(base, limit=40):
    discovered = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        try:
            page.goto(base, wait_until="networkidle", timeout=20000)
            links = page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => e.href)"
            )

            for link in links:
                if urlparse(link).netloc == urlparse(base).netloc:
                    discovered.add(link)
                if len(discovered) >= limit:
                    break
        except:
            pass

        browser.close()

    return list(discovered)

