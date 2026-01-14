from difflib import SequenceMatcher

def diff_ratio(a, b):
    if not a or not b:
        return 1.0
    return SequenceMatcher(None, a, b).ratio()

