import argparse
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from crawler import crawl
from context import Context
from output import Reporter
from js_crawler import js_crawl
from engines import sqli, xss, lfi, ssrf, redirect, idor, forced_endpoints

def check_playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[!] Playwright not installed")
        print("    → JS-heavy websites may not be fully crawled")
        print("    → Optional install:")
        print("       pip install playwright")
        print("       playwright install chromium\n")
        return False

    try:
        with sync_playwright() as p:
            _ = p.chromium
        print("[+] Playwright detected (Chromium available)\n")
        return True
    except Exception:
        print("[!] Playwright installed but browser not found")
        print("    → Run: playwright install chromium\n")
        return False



# ===============================
# CTRL + C GLOBAL HANDLER (ADDED)
# ===============================
def handle_ctrl_c(sig, frame):
    print("\n\n[!] Ctrl + C detected → Stopping scanner completely")
    print("[!] Exiting cleanly...\n")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_ctrl_c)

BANNER = r"""
███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██╗  ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║╚██╗██╔╝
███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║ ╚███╔╝ 
╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║ ██╔██╗ 
███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██╔╝ ██╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝

        ShadowX Web Vulnerability Scanner
        Mode : Learning / Lab / Bug Bounty
"""


# ===============================
# FINAL SCAN SUMMARY
# ===============================
def scan_summary(findings):
    high = sum(1 for f in findings if f["confidence"] == "HIGH")
    medium = sum(1 for f in findings if f["confidence"] == "MEDIUM")
    low = sum(1 for f in findings if f["confidence"] == "LOW")

    print("\n" + "=" * 55)
    print("[✓] SCAN COMPLETE")
    print(f"    → Total Findings : {len(findings)}")
    print(f"    → HIGH           : {high}")
    print(f"    → MEDIUM         : {medium}")
    print(f"    → LOW            : {low}")

    if high > 0:
        print("\n[!] Potential vulnerabilities detected")
        print("    → Manual verification REQUIRED")
    else:
        print("\n[+] No high‑risk issues detected")

    print("=" * 55 + "\n")



def main():
    # ===============================
    # ARGUMENT PARSER (EXTENDED)
    # ===============================
    parser = argparse.ArgumentParser(
        description="ShadowX Web Vulnerability Scanner"
    )

    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Target domain (example: example.com)"
    )

    parser.add_argument(
        "-u", "--max-urls",
        type=int,
        default=40,
        help="Maximum number of URLs to scan (default: 40)"
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=3,
        help="Number of concurrent threads (default: 3)"
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay between requests in seconds (default: 1.0)"
    )

    parser.add_argument(
        "--safe",
        action="store_true",
        help="Enable SAFE mode (slow scan, low traffic)"
    )

    parser.add_argument(
        "--aggressive",
        action="store_true",
        help="Aggressive mode (LAB / CTF ONLY)"
    )

    args = parser.parse_args()

    # ===============================
    # SAFE MODE OVERRIDES
    # ===============================
    if args.safe:
        args.threads = 1
        args.delay = 2.0
        print("[+] SAFE mode enabled (low & slow scan)\n")

    if args.aggressive:
        print("[!] Aggressive mode enabled (use only on labs / owned targets)\n")

    base = args.domain
    if not base.startswith("http"):
        base = "http://" + base

    print(BANNER)
    print(f"[+] Target : {base}")
    print(f"[+] Max URLs : {args.max_urls}")
    print(f"[+] Threads  : {args.threads}")
    print(f"[+] Delay    : {args.delay}s\n")


   # ===============================
    # Playwright Capability Check (ADDED)
    # ===============================
    JS_AVAILABLE = check_playwright()

    ctx = Context(base)
    reporter = Reporter()

    static_urls = crawl(base)

    # ===============================
    # JS Crawl (SAFE ADD)
    # ===============================
    if JS_AVAILABLE:
        js_urls = js_crawl(base)
    else:
        js_urls = []

    urls = list(set(static_urls + js_urls))
    total = len(urls)


    print(f"\n[+] URLs discovered : {total}\n")

    # ===============================
    # Forced Endpoint Discovery
    # ===============================
    print("\n[+] Forced Endpoint Discovery Started\n")

    try:
        forced_results = forced_endpoints.run(base, ctx)
        reporter.collect_endpoints(forced_results)
    except Exception as e:
        print(f"[!] Forced endpoint module error → {e}\n")

    # ===============================
    # Main Scan Loop
    # ===============================
    for i, url in enumerate(urls, 1):
        print(f"[SCAN] ({i}/{total}) {url}")

        try:
            base_resp = ctx.get(url)

            reporter.collect_vulns(sqli.run(url, ctx, base_resp))
            reporter.collect_vulns(xss.run(url, ctx))
            reporter.collect_vulns(lfi.run(url, ctx, base_resp))
            reporter.collect_vulns(ssrf.run(url, ctx))
            reporter.collect_vulns(redirect.run(url, ctx))
            reporter.collect_vulns(idor.run(url, ctx))
            
            time.sleep(args.delay)

        except Exception as e:
            print(f"[!] Error while scanning {url} → {e}")

    reporter.show()
    scan_summary(reporter.findings)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user (Ctrl + C)")
        print("[!] Exiting cleanly...\n")
        exit(0)


