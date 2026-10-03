"""Check responsive UI and generate portfolio screenshots using synthetic data only."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.request

from argon2 import PasswordHasher
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
URL = "http://127.0.0.1:18787"


def main():
    screenshots = ROOT / "docs/images"
    screenshots.mkdir(parents=True, exist_ok=True)
    password = secrets.token_urlsafe(24)
    now = time.time()
    hashes = [
        dict(id=f"demo-{i}", ssid=name, source="demo-capture.pcapng", preview="WPA*01*DEMO",
             created=now, recovered=int(i == 0), passes=2, elapsed=120)
        for i, name in enumerate(("Home Lab", "Guest Network", "Studio Wi-Fi"))
    ]
    words = [
        dict(id=f"word-{i}", name=name, position=i+1, source="Synthetic demonstration",
             bytes=size, lines=lines, created=now)
        for i, (name, size, lines) in enumerate((
            ("common-passwords.txt", 139921497, 14344391),
            ("passphrases.txt", 540848587, 25958122),
            ("custom-dictionary.txt", 28400, 1800)))
    ]
    state = dict(hashes=hashes, wordlists=words, jobs=[], attempts=[],
                 worker_online=True, total_jobs=12)
    system = dict(gpu=dict(available=True, name="NVIDIA GeForce GTX 1070", temperature=42,
                          utilization=0, memory_used=64, memory_total=8192,
                          power=18, driver="550.163.01"),
                  disk=dict(free=180*1024**3, total=240*1024**3),
                  worker_online=True, engine={}, load=0.12, cpu_threads=8)
    with tempfile.TemporaryDirectory(prefix="ieasyhash-ui-") as data:
        env = dict(os.environ, WIFI_DATA_DIR=data, WIFI_SESSION_SECRET=secrets.token_urlsafe(48),
                   WIFI_ADMIN_PASSWORD_HASH=PasswordHasher().hash(password),
                   WIFI_PUBLIC_URL=URL, WIFI_COOKIE_SECURE="0",
                   WIFI_ALLOWED_HOSTS="localhost,127.0.0.1")
        server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "webapp.app:app", "--host", "127.0.0.1",
             "--port", "18787", "--no-access-log"], cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError("Isolated preview server exited")
                try:
                    with urllib.request.urlopen(URL + "/healthz", timeout=1):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("Preview server did not start")
            errors = []
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
                context = browser.new_context(viewport={"width":1440,"height":1050})
                context.route("**/api/state", lambda r: r.fulfill(json=state))
                context.route("**/api/system", lambda r: r.fulfill(json=system))
                page = context.new_page()
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(URL + "/login", wait_until="networkidle")
                assert page.title() == "Вход · iEasyHash"
                page.screenshot(path=str(screenshots / "login.png"), full_page=True)
                page.get_by_label("Логин", exact=True).fill("admin")
                page.get_by_label("Пароль", exact=True).fill(password)
                page.get_by_role("button", name="Войти в кабинет").click()
                page.wait_for_url(URL + "/")
                expect(page.locator("#networks-count")).to_have_text("3")
                assert "Вычисления остаются на сервере" not in page.locator("body").inner_text()
                assert "PRIVATE NETWORK LAB" not in page.locator("body").inner_text()
                assert page.locator(".app-footer a").get_attribute("href") == "https://github.com/nuradura"
                assert page.locator(".brand img").evaluate("(img) => img.complete && img.naturalWidth > 0")
                page.locator(".private-label").evaluate("(el) => el.textContent = 'DEMO · SYNTHETIC DATA'")
                page.screenshot(path=str(screenshots / "dashboard.png"), full_page=True)
                for name in ("dashboard","networks","wordlists","history","system"):
                    page.locator(f'[data-page="{name}"]').click()
                    assert page.locator(f"#page-{name}").is_visible()
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                page.locator('[data-page="dashboard"]').click()
                page.locator("#start-job").click()
                assert page.locator("#start-form").is_visible()
                page.locator("#close-modal").click()
                page.locator("#account").click()
                assert page.locator("#password-form").is_visible()
                page.locator("#close-modal").click()
                page.set_viewport_size({"width":390,"height":844})
                page.goto(URL + "/", wait_until="networkidle")
                expect(page.locator("#networks-count")).to_have_text("3")
                page.locator(".private-label").evaluate("(el) => el.textContent = 'DEMO'")
                page.screenshot(path=str(screenshots / "mobile.png"), full_page=True)
                for name in ("dashboard","networks","wordlists","history","system"):
                    page.locator(f'[data-page="{name}"]').click()
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), name
                page.locator("#account").click()
                page.locator("#account-logout").click()
                page.wait_for_url(URL + "/login")
                assert context.request.get(URL + "/api/state").status == 401
                browser.close()
            assert not errors, errors
            print("UI PASS: desktop, mobile, branding, navigation, dialogs, authentication and logout.")
        finally:
            server.terminate()
            server.wait(timeout=10)


if __name__ == "__main__":
    main()
