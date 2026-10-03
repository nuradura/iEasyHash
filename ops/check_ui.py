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
                context.route("**/api/progress", lambda r: r.fulfill(json={"job": state['jobs'][0] if state['jobs'] else None, "worker_online": True}))
                page = context.new_page()
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(URL + "/login", wait_until="domcontentloaded")
                assert page.title() == "Sign in · iEasyHash"
                page.wait_for_function("document.querySelector('.frog-footnote img').complete && document.querySelector('.frog-footnote img').naturalWidth > 0")
                page.evaluate('document.fonts.ready')
                assert page.locator('.radar-sweep').evaluate('el => getComputedStyle(el).animationName') == 'radar-scan'
                assert page.locator('.access-badge').count() == 0
                assert page.locator('.login-foot').count() == 0
                assert page.locator('.meme-asterisk').count() == 0
                assert page.locator('#language-select').evaluate('el => getComputedStyle(el).appearance') == 'none'
                expect(page.locator('.login-bottom')).to_contain_text('WPA × NVIDIA')
                assert page.locator('.frog-footnote img').evaluate('img => img.complete && img.naturalWidth > 0')
                page.emulate_media(reduced_motion='reduce')
                assert page.locator('.radar-sweep').evaluate('el => getComputedStyle(el).animationName') == 'none'
                page.emulate_media(reduced_motion='no-preference')
                page.screenshot(path=str(screenshots / "login.png"), full_page=True)
                page.locator('#username').fill("admin")
                page.locator('#password').fill(password)
                page.locator('#login-form button[type="submit"]').click()
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
                page.goto(URL + "/", wait_until="domcontentloaded")
                expect(page.locator("#networks-count")).to_have_text("3")
                page.locator(".private-label").evaluate("(el) => el.textContent = 'DEMO'")
                page.screenshot(path=str(screenshots / "mobile.png"), full_page=True)
                for name in ("dashboard","networks","wordlists","history","system"):
                    page.locator(f'[data-page="{name}"]').click()
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), name
                for language, html in (("en", "en"), ("ru", "ru"), ("zh", "zh-Hans")):
                    for width in (1440, 390):
                        page.set_viewport_size({"width": width, "height": 1050 if width == 1440 else 844})
                        with page.expect_navigation(wait_until='domcontentloaded'):
                            page.locator('#language-select').select_option(language)
                        expect(page.locator('html')).to_have_attribute('lang', html)
                        expect(page.locator('#networks-count')).to_have_text('3')
                        page.reload(wait_until='domcontentloaded')
                        expect(page.locator('#language-select')).to_have_value(language)
                        for name in ('dashboard', 'networks', 'wordlists', 'history', 'system'):
                            page.locator(f'[data-page="{name}"]').click()
                            assert page.locator(f'#page-{name}').is_visible()
                            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), (language, width, name)
                        page.locator('[data-page="wordlists"]').click()
                        expect(page.locator('body')).to_contain_text('custom-dictionary.txt')
                        page.locator('[data-page="dashboard"]').click()
                        page.locator('#start-job').click()
                        assert page.locator('#start-form').is_visible()
                        page.locator('#close-modal').click()
                        page.locator('#account').click()
                        assert page.locator('#password-form').is_visible()
                        page.locator('#close-modal').click()
                        if width == 1440 and language != 'en':
                            page.locator('.private-label').evaluate("(el) => el.textContent = 'DEMO · SYNTHETIC DATA'")
                            page.screenshot(path=str(screenshots / f'dashboard-{language}.png'), full_page=True)
                    page.locator('#account').click()
                    page.locator('#account-logout').click()
                    page.wait_for_url(URL + '/login')
                    expect(page.locator('#language-select')).to_have_value(language)
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), language
                    expect(page.locator('.radar-sweep')).to_be_visible()
                    expect(page.locator('.frog-footnote')).to_be_visible()
                    assert context.request.get(URL + '/api/state').status == 401
                    page.locator('#username').fill('admin')
                    page.locator('#password').fill(password)
                    page.locator('#login-form button[type="submit"]').click()
                    page.wait_for_url(URL + '/')
                # Measured progress eases to each sample, never predicts beyond it.
                with page.expect_navigation(wait_until='domcontentloaded'):
                    page.locator('#language-select').select_option('en')
                expect(page.locator('#networks-count')).to_have_text('3')
                state['jobs'] = [dict(id='synthetic-run', name='Demo audit', status='running',
                    created=now, started=now, finished=None, next_index=0,
                    hash_ids=['demo-1'], wordlists=words, error=None, runtime=0, workload=2,
                    progress=dict(percent=20, speed=200000, pass_index=1, wordlist='common-passwords.txt'))]
                expect(page.locator('.run-panel')).to_have_class('panel run-panel is-running')
                assert page.locator('.run-panel').evaluate("el => getComputedStyle(el, '::before').animationName") == 'run-waves'
                assert page.locator('.run-panel').evaluate("el => getComputedStyle(el, '::after').animationDelay") == '-3.2s'
                expect(page.locator('.run-progress')).to_have_attribute('aria-valuenow', '20.0')
                page.locator('.run-progress').evaluate("el => el.dataset.identity = 'persistent'")
                page.locator('[data-job-action="pause"]').focus()
                state['jobs'][0]['progress']['percent'] = 40
                expect(page.locator('.run-progress')).to_have_attribute('aria-valuenow', '40.0')
                value = float(page.locator('.run-percent-value').inner_text())
                assert 20 <= value < 40, value
                expect(page.locator('.run-percent-value')).to_have_text('40.0')
                assert page.locator('.run-progress').get_attribute('data-identity') == 'persistent'
                assert page.locator('[data-job-action="pause"]').evaluate('el => el === document.activeElement')
                state['jobs'][0]['progress'].update(percent=5, pass_index=2, wordlist='passphrases.txt')
                expect(page.locator('.run-percent-value')).to_have_text('5.0')
                page.emulate_media(reduced_motion='reduce')
                state['jobs'][0]['progress']['percent'] = 30
                expect(page.locator('.run-percent-value')).to_have_text('30.0')
                assert page.locator('.run-panel').evaluate("el => getComputedStyle(el, '::before').animationName") == 'none'
                state['jobs'][0]['status'] = 'paused'
                expect(page.locator('.run-panel')).not_to_have_class('panel run-panel is-running')
                state['jobs'][0].update(status='completed', finished=time.time())
                state['jobs'][0]['progress']['percent'] = 100
                expect(page.locator('.run-percent-value')).to_have_text('100.0')
                browser.close()
            assert not errors, errors
            print("UI PASS: English, Russian and Chinese; desktop/mobile, language persistence, navigation, dialogs and authentication.")
        finally:
            server.terminate()
            server.wait(timeout=10)


if __name__ == "__main__":
    main()
