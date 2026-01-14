class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"


class Reporter:
    def __init__(self):   
        self.findings = []        # vulnerabilities (existing)
        self.endpoints = []       # forced endpoints (NEW)

    # =========================
    # EXISTING (unchanged)
    # =========================
    def collect(self, results):
        if results:
            self.findings.extend(results)
     # =========================       
     # ✅ ADD THIS (FIX)
     # =========================
    def collect_vulns(self, results):
        self.collect(results)
        
    # =========================
    # ADD: endpoint collector
    # =========================
    def collect_endpoints(self, results):
        if results:
            self.endpoints.extend(results)

    def show(self):

        # ===============================
        # 1️⃣ FORCED ENDPOINTS (NEW)
        # ===============================
        if self.endpoints:
            print(f"\n{Colors.CYAN}======= DISCOVERED ENDPOINTS ======={Colors.RESET}\n")
            print(f"    → Total Endpoints Found : {len(self.endpoints)}\n")

            for e in self.endpoints:
                print(f"[+] {e['url']} ({e['confidence']})")

            print("-" * 60)

        # ===============================
        # 2️⃣ EXISTING FINDINGS (UNCHANGED)
        # ===============================
        if not self.findings:
            print(f"\n{Colors.GREEN}[+] Scan completed – No confirmed issues{Colors.RESET}\n")
            return

        print(f"\n{Colors.RED}======= FINDINGS ======={Colors.RESET}\n")

        for f in self.findings:
            print(f"{Colors.YELLOW}[!] {f['type']} ({f['confidence']}){Colors.RESET}")
            print(f"    URL     : {f['url']}")
            print(f"    Param   : {f['param']}")

            if "payload" in f:
                print(f"    Payload : {f['payload']}")

            print(f"    Reason  : {f['reason']}")

            if "evidence" in f:
                print("\n    Evidence:")
                for e in f["evidence"]:
                    print(f"      - {e}")

            if "allowed_paths" in f and f["allowed_paths"]:
                print("\n    Allowed Paths:")
                for p in f["allowed_paths"]:
                    print(f"      - {p}")

            if "readable_files" in f and f["readable_files"]:
                print("\n    Readable Files:")
                for r in f["readable_files"]:
                    print(f"      - {r}")

            if "verify" in f:
                print("\n    Manual Verification:")
                if isinstance(f["verify"], dict):
                    for k, v in f["verify"].items():
                        if isinstance(v, list):
                            for c in v:
                                print(f"      {Colors.CYAN}{c}{Colors.RESET}")
                        else:
                            print(f"      {Colors.CYAN}{v}{Colors.RESET}")
                else:
                    print(f"      {Colors.CYAN}{f['verify']}{Colors.RESET}")

            if "impact" in f:
                print("\n    Impact:")
                for i in f["impact"]:
                    print(f"      - {i}")

            print(f"\n    → Manual verification recommended")
            print("-" * 60)

