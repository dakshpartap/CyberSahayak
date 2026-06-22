from pathlib import Path

URLHAUS_FILE = Path(__file__).parent / "urlhaus.txt"

_urls = set()


def load_urlhaus():
    global _urls

    if _urls:
        return

    if not URLHAUS_FILE.exists():
        return

    with open(URLHAUS_FILE, "r", encoding="utf-8") as f:
        _urls = {
            line.strip().lower()
            for line in f
            if line.strip()
        }


def check_urlhaus(url: str):
    load_urlhaus()

    return url.lower().strip() in _urls


def get_stats():
    load_urlhaus()

    return {
        "loaded": True,
        "entries": len(_urls)
    }