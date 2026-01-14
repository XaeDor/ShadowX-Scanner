import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl(base, limit=40):
    visited = set()
    queue = [base]

    print(f"[+] Crawling {base}\n")

    while queue and len(visited) < limit:
        url = queue.pop(0)
        if url in visited:
            continue

        visited.add(url)
        print("[CRAWL]", url)

        try:
            r = requests.get(url, timeout=10, verify=True)
            soup = BeautifulSoup(r.text, "html.parser")

            for a in soup.find_all("a", href=True):
                link = urljoin(base, a["href"])
                if urlparse(link).netloc == urlparse(base).netloc:
                    if link not in visited:
                        queue.append(link)
                        
        except KeyboardInterrupt:
            raise
        except Exception:
            continue


    return list(visited)

