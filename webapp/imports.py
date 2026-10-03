import hashlib
import re
import subprocess
import time
from pathlib import Path
from . import config
from .db import connect, idle, uid

HEX = re.compile(r"^[0-9a-fA-F]+$")


def parse_wpa(text):
    output = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("*")
        if len(parts) != 9 or parts[0] != "WPA" or parts[1] not in ("01", "02"):
            raise ValueError("Ожидается файл WPA в формате Hashcat 22000. Другие типы хешей не поддерживаются.")
        for i, n in ((2, 32), (3, 12), (4, 12)):
            if len(parts[i]) != n or not HEX.fullmatch(parts[i]):
                raise ValueError("Некорректная WPA-запись: неверная длина хеша или MAC.")
        if not 2 <= len(parts[5]) <= 64 or len(parts[5]) % 2 or not HEX.fullmatch(parts[5]):
            raise ValueError("Некорректный SSID в WPA-записи.")
        if parts[1] == "01" and (parts[6] or parts[7] or (parts[8] and (len(parts[8])!=2 or not HEX.fullmatch(parts[8])))):
            raise ValueError("Некорректная PMKID-запись.")
        if parts[1] == "02":
            if len(parts[6]) != 64 or not HEX.fullmatch(parts[6]):
                raise ValueError("Некорректный ANonce в handshake.")
            if not 198 <= len(parts[7]) <= 512 or len(parts[7]) % 2 or not HEX.fullmatch(parts[7]):
                raise ValueError("Некорректный EAPOL в handshake.")
            if len(parts[8]) != 2 or not HEX.fullmatch(parts[8]):
                raise ValueError("Некорректная пара сообщений EAPOL.")
        normalized = "*".join(p.lower() if i > 1 else p for i, p in enumerate(parts))
        ssid = bytes.fromhex(parts[5]).decode("utf-8", "replace")
        output[normalized] = ssid
    if not output:
        raise ValueError("В файле нет пригодных записей WPA.")
    if len(output) > config.MAX_HASHES:
        raise ValueError("За один импорт допускается до 5000 записей.")
    return output


def import_capture(path, name):
    extension = Path(name).suffix.lower()
    if extension in (".pcap", ".pcapng", ".cap"):
        output = config.DATA / "tmp" / f"{uid()}.22000"
        try:
            result = subprocess.run([config.CONVERTER, "-o", str(output), str(path)],
                                    capture_output=True, timeout=45)
            if result.returncode != 0 or not output.exists():
                raise ValueError("Не удалось извлечь WPA-handshake. Проверьте исходный захват.")
            text = output.read_text(encoding="utf-8")
        finally:
            output.unlink(missing_ok=True)
    elif extension in (".22000", ".hc22000", ".txt"):
        text = path.read_text(encoding="utf-8-sig")
    else:
        raise ValueError("Поддерживаются PCAP, PCAPNG, CAP, 22000, HC22000 и TXT.")
    entries = parse_wpa(text)
    with connect(True) as db:
        idle(db)
        existing = db.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
        novel = [(h, s) for h, s in entries.items() if not db.execute("SELECT 1 FROM hashes WHERE hash=?", (h,)).fetchone()]
        if existing + len(novel) > config.MAX_HASHES:
            raise ValueError("В рабочей области допускается до 5000 записей.")
        for h, ssid in novel:
            db.execute("INSERT INTO hashes(id,hash,ssid,source,created) VALUES (?,?,?,?,?)",
                       (uid(), h, ssid, name, time.time()))
    return {"added": len(novel), "duplicates": len(entries) - len(novel), "total": len(entries)}


def wordlist_metadata(path):
    digest = hashlib.sha256()
    lines = 0
    last = b""
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            if b"\x00" in chunk:
                raise ValueError("Словарь должен быть текстовым файлом без нулевых байтов.")
            digest.update(chunk)
            lines += chunk.count(b"\n")
            last = chunk[-1:]
    size = path.stat().st_size
    if size == 0:
        raise ValueError("Словарь пуст.")
    if last != b"\n":
        lines += 1
    return size, lines, digest.hexdigest()


def import_wordlist(path, name, source="Загружен вручную"):
    size, lines, sha = wordlist_metadata(path)
    identity = uid()
    relative = f"wordlists/{identity}.txt"
    target = config.DATA / relative
    with connect(True) as db:
        duplicate = db.execute("SELECT id FROM wordlists WHERE sha256=?", (sha,)).fetchone()
        if duplicate:
            path.unlink(missing_ok=True)
            return {"id": duplicate["id"], "duplicate": True}
        path.replace(target)
        target.chmod(0o600)
        try:
            db.execute("INSERT INTO wordlists VALUES (?,?,?,?,?,?,?,?,?)",
                       (identity, name, relative, source, size, lines, sha, None, time.time()))
        except Exception:
            target.unlink(missing_ok=True)
            raise
    return {"id": identity, "duplicate": False}
