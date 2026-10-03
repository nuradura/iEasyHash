import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get("WIFI_DATA_DIR", "/var/lib/wifi-audit"))
DB = DATA / "library.sqlite3"
SECRET = os.environ.get("WIFI_SESSION_SECRET", "")
USERNAME = os.environ.get("WIFI_ADMIN_USER", "admin")
PASSWORD_HASH = os.environ.get("WIFI_ADMIN_PASSWORD_HASH", "")
PUBLIC_URL = os.environ.get("WIFI_PUBLIC_URL", "http://localhost:8787").rstrip("/")
COOKIE_SECURE = os.environ.get("WIFI_COOKIE_SECURE", "1") == "1"
MAX_CAPTURE = 64 * 1024 * 1024
MAX_WORDLIST = 2 * 1024 * 1024 * 1024
MAX_HASHES = 5000
HASHCAT = os.environ.get("WIFI_HASHCAT", "/usr/bin/hashcat")
CONVERTER = os.environ.get("WIFI_CONVERTER", "/usr/bin/hcxpcapngtool")


def ensure_data():
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in ("wordlists", "captures", "runs", "tmp"):
        (DATA / name).mkdir(exist_ok=True, mode=0o700)
