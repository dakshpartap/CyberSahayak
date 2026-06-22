from pathlib import Path

OPENPHISH_FILE = Path(__file__).parent / "openphish.txt"

_openphish_urls = set()


def load_openphish():
    global _openphish_urls

    if _openphish_urls:
        return

    if not OPENPHISH_FILE.exists():
        return

    with open(OPENPHISH_FILE, "r", encoding="utf-8") as f:
        _openphish_urls = {
            line.strip().lower()
            for line in f
            if line.strip()
        }


def check_openphish(url: str):
    load_openphish()

    return url.lower().strip() in _openphish_urls