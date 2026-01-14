import requests

class Context:
    def __init__(self, base):
        self.base = base
        self.session = requests.Session()

    def get(self, url):
        try:
            return self.session.get(url, timeout=10, verify=True)

        except KeyboardInterrupt:
            raise   # ⬅️ MUST

        except Exception:
            return None

