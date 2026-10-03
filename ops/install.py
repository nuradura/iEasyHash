#!/usr/bin/env python3
"""Install iEasyHash services on a fresh Debian host."""
import argparse
import grp
import os
from pathlib import Path
import pwd
import secrets
import shutil
import subprocess
from urllib.parse import urlsplit

SOURCE = Path(__file__).resolve().parents[1]
DEST = Path("/opt/wifi-audit")
ENV_FILE = Path("/etc/wifi-audit.env")


def run(*args):
    subprocess.run(args, check=True)


def private_write(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-url", default="http://localhost:8787")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo.")
    url = urlsplit(args.public_url)
    local = url.hostname in ("localhost", "127.0.0.1")
    if (url.scheme not in ("http", "https") or not url.hostname or url.username
            or url.password or url.path not in ("", "/") or url.query or url.fragment
            or (url.scheme == "http" and not local) or any(c.isspace() for c in args.public_url)):
        raise SystemExit("Use an HTTPS origin, or http://localhost:8787 for an SSH tunnel.")
    if ENV_FILE.exists():
        raise SystemExit("Already installed. Follow the upgrade section in docs/INSTALL.md.")
    try:
        account = pwd.getpwnam("wifi-audit")
    except KeyError:
        run("useradd", "--system", "--home-dir", "/var/lib/wifi-audit",
            "--shell", "/usr/sbin/nologin", "--user-group", "wifi-audit")
        account = pwd.getpwnam("wifi-audit")
    groups = []
    for name in ("video", "render"):
        try:
            grp.getgrnam(name)
            groups.append(name)
        except KeyError:
            pass
    if groups:
        run("usermod", "-a", "-G", ",".join(groups), "wifi-audit")
    DEST.mkdir(exist_ok=True, mode=0o755)
    shutil.copytree(SOURCE / "webapp", DEST / "webapp", dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(SOURCE / "requirements.lock", DEST / "requirements.lock")
    if not (DEST / ".venv/bin/python").exists():
        run("python3", "-m", "venv", str(DEST / ".venv"))
    run(str(DEST / ".venv/bin/python"), "-m", "pip", "install", "-r", str(DEST / "requirements.lock"))
    password = secrets.token_urlsafe(20)
    result = subprocess.run(
        [str(DEST / ".venv/bin/python"), "-c",
         "from argon2 import PasswordHasher;import sys;print(PasswordHasher().hash(sys.stdin.read()))"],
        input=password, text=True, capture_output=True, check=True)
    public_url = args.public_url.rstrip("/")
    hosts = ",".join(dict.fromkeys((url.hostname, "localhost", "127.0.0.1")))
    private_write(ENV_FILE, "WIFI_DATA_DIR=/var/lib/wifi-audit\n"
                  + "WIFI_SESSION_SECRET=" + secrets.token_urlsafe(48) + "\n"
                  + "WIFI_ADMIN_USER=admin\nWIFI_ADMIN_PASSWORD_HASH=" + result.stdout.strip() + "\n"
                  + "WIFI_PUBLIC_URL=" + public_url + "\n"
                  + "WIFI_COOKIE_SECURE=" + ("1" if url.scheme == "https" else "0") + "\n"
                  + "WIFI_ALLOWED_HOSTS=" + hosts + "\n")
    first = SOURCE / "FIRST_LOGIN.md"
    private_write(first, "# Private first login\n\nUsername: admin\n\nPassword: " + password
                  + "\n\nURL: " + public_url + "\n\nKeep this file out of Git. Change the password in the application.\n")
    owner = pwd.getpwnam(os.environ.get("SUDO_USER", "root"))
    os.chown(first, owner.pw_uid, owner.pw_gid)
    data = Path("/var/lib/wifi-audit")
    data.mkdir(exist_ok=True, mode=0o700)
    os.chown(data, account.pw_uid, account.pw_gid)
    run("/usr/sbin/modprobe", "nvidia-uvm")
    Path("/etc/modules-load.d/wifi-audit.conf").write_text("nvidia\nnvidia-uvm\n")
    for name in ("web", "worker"):
        shutil.copy2(SOURCE / "ops" / f"wifi-audit-{name}.service",
                     Path("/etc/systemd/system") / f"wifi-audit-{name}.service")
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "--now", "wifi-audit-web.service", "wifi-audit-worker.service")
    print("Installed iEasyHash on loopback port 8787. Read FIRST_LOGIN.md privately.")


if __name__ == "__main__":
    main()
