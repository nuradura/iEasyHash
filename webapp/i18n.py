"""Shared English message IDs, Russian aliases and Simplified Chinese translations."""
import json
import re
from . import config

CATALOG = json.loads((config.ROOT / "static/locales.json").read_text(encoding="utf-8"))
LANGUAGES = CATALOG["languages"]
MESSAGES = CATALOG["messages"]
ALIASES = CATALOG["aliases"]
COOKIE = "ieasyhash_lang"


def language(request):
    value = request.cookies.get(COOKIE, "en")
    return value if value in LANGUAGES else "en"


def translate(message, lang="en"):
    if not isinstance(message, str):
        return message
    lang = lang if lang in LANGUAGES else "en"
    key = ALIASES.get(message, message)
    entry = MESSAGES.get(key)
    if entry:
        return entry.get(lang) or entry["en"]
    # Old workers may have persisted this diagnostic before localization existed.
    match = re.fullmatch(r"Ошибка worker: ([A-Za-z0-9_]+)\. Проверьте доступность файлов и журнал службы\.", message)
    if match:
        key = "Worker error: {error}. Check file availability and service logs."
        return translate(key, lang).replace("{error}", match[1])
    return message


def context(request):
    selected = language(request)
    return {
        "language": selected,
        "lang": LANGUAGES[selected]["html"],
        "languages": {key: value["name"] for key, value in LANGUAGES.items()},
        "t": lambda message: translate(message, selected),
    }
