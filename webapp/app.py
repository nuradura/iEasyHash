import asyncio
import csv
import hmac
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time
from urllib.parse import quote, urlparse

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import httpx

from . import config
from .db import connect, init, uid, audit, idle, public_job
from .imports import import_capture, import_wordlist
from .i18n import context as language_context, language, translate

if len(config.SECRET) < 32 or not config.PASSWORD_HASH:
    raise RuntimeError("Configure WIFI_SESSION_SECRET and WIFI_ADMIN_PASSWORD_HASH before starting")
init()
with connect(True) as _db:
    _db.execute("INSERT OR IGNORE INTO meta VALUES ('admin_password_hash',?)", (config.PASSWORD_HASH,))
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory=config.ROOT / "templates")
signer = URLSafeTimedSerializer(config.SECRET, salt="wifi-audit-v1")
hasher = PasswordHasher()
app.mount("/static", StaticFiles(directory=config.ROOT / "static"), name="static")
SAFE = {"GET", "HEAD", "OPTIONS"}
VALID_HOSTS = set(os.environ.get("WIFI_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(","))


def client_ip(request):
    host = request.client.host if request.client else "unknown"
    if host in ("127.0.0.1", "::1") and request.headers.get("cf-connecting-ip"):
        try:
            return str(ipaddress.ip_address(request.headers["cf-connecting-ip"]))
        except ValueError:
            pass
    return host


def origin_ok(request):
    origin = request.headers.get("origin")
    allowed = {config.PUBLIC_URL, f"{request.url.scheme}://{request.headers.get('host', '')}"}
    return not origin or origin.rstrip("/") in allowed


async def payload_json(request):
    content=bytearray()
    limit=8192 if request.url.path=="/login" else 65536
    async for chunk in request.stream():
        content.extend(chunk)
        if len(content)>limit:
            raise ValueError("Слишком большой запрос.")
    try:
        value=json.loads(content)
    except (json.JSONDecodeError,UnicodeDecodeError):
        raise ValueError("Некорректный JSON-запрос.")
    if not isinstance(value,dict):
        raise ValueError("Ожидается JSON-объект.")
    return value


@app.middleware("http")
async def guard(request, call_next):
    host = request.headers.get("host", "").split(":")[0].lower()
    response = None
    if host not in VALID_HOSTS:
        response = Response("Invalid host", status_code=400)
    length = request.headers.get("content-length")
    if response is None and length:
        try:
            if int(length) < 0 or int(length) > config.MAX_WORDLIST + 4 * 1024 * 1024:
                response = JSONResponse({"detail": translate("Слишком большой запрос.", language(request))}, status_code=413)
        except ValueError:
            response = Response(status_code=400)
    request.state.session = None
    token = request.cookies.get("wifi_session")
    if token and response is None:
        try:
            sid = signer.loads(token, max_age=12 * 3600)
            with connect() as db:
                row = db.execute("SELECT * FROM sessions WHERE id=? AND expires>?", (sid, time.time())).fetchone()
            if row:
                request.state.session = dict(row)
        except (BadSignature, SignatureExpired, TypeError):
            pass
    path = request.url.path
    public = path in ("/login", "/robots.txt", "/favicon.ico", "/healthz") or path.startswith("/static/")
    if response is None and not public and not request.state.session:
        response = JSONResponse({"detail": translate("Требуется вход.", language(request))}, status_code=401) if path.startswith("/api/") else RedirectResponse("/login", status_code=303)
    if response is None and request.method not in SAFE:
        if not origin_ok(request):
            response = JSONResponse({"detail": translate("Недопустимый источник запроса.", language(request))}, status_code=403)
        elif path != "/login":
            session = request.state.session
            supplied = request.headers.get("x-csrf-token", "")
            if not session or not hmac.compare_digest(supplied, session["csrf"]):
                response = JSONResponse({"detail": translate("Обновите страницу и повторите действие.", language(request))}, status_code=403)
    if response is None:
        response = await call_next(request)
    response.headers["Content-Language"] = language_context(request)["lang"]
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive, nosnippet"
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    if config.COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.exception_handler(ValueError)
async def invalid(request, exc):
    return JSONResponse({"detail": translate(str(exc), language(request))}, status_code=400)


@app.exception_handler(subprocess.TimeoutExpired)
async def timed_out(request, exc):
    return JSONResponse({"detail": translate("Операция превысила допустимое время.", language(request))}, status_code=408)


@app.exception_handler(httpx.HTTPError)
async def upstream_error(request,exc):
    return JSONResponse({"detail":translate("Внешний сервис недоступен. Повторите позже.", language(request))},status_code=502)


@app.get("/healthz")
def health():
    return {"status": "ok"}


@app.get("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /\n", media_type="text/plain")


@app.get("/favicon.ico")
def favicon():
    return FileResponse(config.ROOT / "static" / "mark.png", media_type="image/png")


@app.get("/login", response_class=HTMLResponse)
def login_screen(request: Request):
    if request.state.session:
        return RedirectResponse("/", status_code=303)
    nonce = secrets.token_urlsafe(24)
    response = templates.TemplateResponse(request=request, name="login.html", context={"nonce": nonce, **language_context(request)})
    response.set_cookie("wifi_login", signer.dumps(nonce), httponly=True, secure=config.COOKIE_SECURE,
                        samesite="strict", max_age=600, path="/login")
    return response


@app.post("/login")
async def login(request: Request):
    payload = await payload_json(request)
    try:
        nonce = signer.loads(request.cookies.get("wifi_login", ""), max_age=600)
        if not hmac.compare_digest(nonce, str(payload.get("nonce", ""))):
            raise BadSignature("nonce")
    except (BadSignature, SignatureExpired, TypeError):
        return JSONResponse({"detail": translate("Обновите страницу входа.", language(request))}, status_code=403)
    ip, now = client_ip(request), time.time()
    with connect(True) as db:
        db.execute("DELETE FROM sessions WHERE expires<?", (now,))
        for key, limit in ((ip, 6), ("__global__", 30)):
            row = db.execute("SELECT * FROM login_limits WHERE ip=?", (key,)).fetchone()
            if row and row["blocked_until"] > now:
                return JSONResponse({"detail": translate("Слишком много попыток. Повторите через 15 минут.", language(request))}, status_code=429)
            count = row["failures"] + 1 if row and now - row["window"] < 900 else 1
            window = row["window"] if row and now - row["window"] < 900 else now
            blocked = now + 900 if count > limit else 0
            db.execute("INSERT OR REPLACE INTO login_limits VALUES (?,?,?,?)", (key, count, window, blocked))
            if blocked:
                return JSONResponse({"detail": translate("Слишком много попыток. Повторите через 15 минут.", language(request))}, status_code=429)
    password = payload.get("password", "")
    user = payload.get("username", "")
    if not isinstance(password, str) or not isinstance(user, str) or len(password) > 1024 or len(user) > 100:
        return JSONResponse({"detail": translate("Неверный логин или пароль.", language(request))}, status_code=401)
    try:
        with connect() as db:
            stored_hash = db.execute("SELECT value FROM meta WHERE key='admin_password_hash'").fetchone()[0]
        correct_password = await asyncio.to_thread(hasher.verify, stored_hash, password)
    except (VerificationError, InvalidHashError):
        correct_password = False
    if not correct_password or not hmac.compare_digest(user.encode(), config.USERNAME.encode()):
        audit("login_failed", ip)
        return JSONResponse({"detail": translate("Неверный логин или пароль.", language(request))}, status_code=401)
    sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    with connect(True) as db:
        db.execute("DELETE FROM login_limits WHERE ip=?", (ip,))
        db.execute("INSERT INTO sessions VALUES (?,?,?,?)", (sid, csrf, now + 43200, now))
    response = JSONResponse({"ok": True})
    response.set_cookie("wifi_session", signer.dumps(sid), max_age=43200, secure=config.COOKIE_SECURE,
                        httponly=True, samesite="strict", path="/")
    response.delete_cookie("wifi_login", path="/login")
    audit("login", ip)
    return response


@app.post("/api/profile/password")
async def change_password(request: Request):
    payload = await payload_json(request)
    current, new = payload.get("current", ""), payload.get("new", "")
    if not isinstance(current,str) or not isinstance(new,str) or len(current)>1024 or not 14<=len(new)<=200:
        raise ValueError("Новый пароль должен содержать от 14 до 200 символов.")
    with connect() as db:
        stored = db.execute("SELECT value FROM meta WHERE key='admin_password_hash'").fetchone()[0]
    try:
        await asyncio.to_thread(hasher.verify, stored, current)
    except (VerificationError,InvalidHashError):
        raise ValueError("Текущий пароль неверен.")
    updated = await asyncio.to_thread(hasher.hash,new)
    with connect(True) as db:
        db.execute("UPDATE meta SET value=? WHERE key='admin_password_hash'",(updated,))
        db.execute("DELETE FROM sessions")
    audit("password_changed")
    response=JSONResponse({"ok":True})
    response.delete_cookie("wifi_session",path="/")
    return response


@app.post("/api/logout")
def logout(request: Request):
    with connect(True) as db:
        db.execute("DELETE FROM sessions WHERE id=?", (request.state.session["id"],))
    response = JSONResponse({"ok": True})
    response.delete_cookie("wifi_session", path="/")
    return response


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={"csrf": request.state.session["csrf"], "username": config.USERNAME, **language_context(request)})


@app.get("/api/state")
def state():
    with connect() as db:
        hashes = [dict(r) for r in db.execute("""SELECT h.id,h.ssid,h.source,h.created,h.recovered_at,
          h.password_hex IS NOT NULL AS recovered,substr(h.hash,1,28) AS preview,
          (SELECT count(*) FROM hash_passes p WHERE p.hash_id=h.id) AS passes,
          (SELECT coalesce(sum(a.finished-a.started),0) FROM hash_passes p JOIN attempts a ON a.id=p.attempt_id WHERE p.hash_id=h.id AND a.finished IS NOT NULL) AS elapsed
          FROM hashes h ORDER BY h.created""")]
        wordlists = [dict(r) for r in db.execute("SELECT id,name,source,bytes,lines,sha256,position,created FROM wordlists ORDER BY position IS NULL,position,name")]
        jobs = [public_job(r) for r in db.execute("SELECT * FROM jobs ORDER BY created DESC LIMIT 100")]
        total_jobs = db.execute("SELECT count(*) FROM jobs").fetchone()[0]
        attempts = [dict(r) for r in db.execute("SELECT id,job_id,pass_index,wordlist_name,started,finished,outcome,exit_code,recovered FROM attempts ORDER BY started DESC LIMIT 100")]
        worker = db.execute("SELECT value FROM meta WHERE key='worker_heartbeat'").fetchone()
    return {"hashes": hashes, "wordlists": wordlists, "jobs": jobs, "attempts": attempts,
            "total_jobs": total_jobs, "worker_online": bool(worker and time.time()-float(worker[0]) < 15), "server_time": time.time()}


@app.get("/api/progress")
def progress():
    # Lightweight telemetry polling avoids repeatedly reading the whole workspace.
    with connect() as db:
        row = db.execute("SELECT * FROM jobs ORDER BY created DESC LIMIT 1").fetchone()
        worker = db.execute("SELECT value FROM meta WHERE key='worker_heartbeat'").fetchone()
    return {"job": public_job(row) if row else None,
            "worker_online": bool(worker and time.time()-float(worker[0]) < 15)}


@app.get("/api/hashes/{identity}")
def hash_detail(identity: str, request: Request):
    with connect() as db:
        row = db.execute("SELECT id,hash,ssid,source,created,recovered_at,password_hex IS NOT NULL AS recovered FROM hashes WHERE id=?", (identity,)).fetchone()
        if not row:
            return JSONResponse({"detail": translate("Запись не найдена.", language(request))}, status_code=404)
        passes = [dict(r) for r in db.execute("SELECT a.id,a.job_id,a.wordlist_name,a.started,a.finished,p.outcome FROM hash_passes p JOIN attempts a ON a.id=p.attempt_id WHERE p.hash_id=? ORDER BY a.started", (identity,))]
    return {**dict(row), "passes": passes}


@app.get("/api/hashes/{identity}/password")
def reveal(identity: str, request: Request):
    with connect() as db:
        row = db.execute("SELECT password_hex FROM hashes WHERE id=?", (identity,)).fetchone()
    if not row or row[0] is None:
        return JSONResponse({"detail": translate("Пароль ещё не найден.", language(request))}, status_code=404)
    raw = bytes.fromhex(row[0])
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        value = "$HEX[" + raw.hex() + "]"
    audit("password_view", identity)
    return {"password": value, "length": len(raw)}


async def save_upload(file, limit):
    target = config.DATA / "tmp" / uid()
    size = 0
    try:
        with target.open("xb") as out:
            target.chmod(0o600)
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > limit:
                    raise ValueError("Файл превышает допустимый размер.")
                await asyncio.to_thread(out.write, chunk)
        if not size:
            raise ValueError("Файл пуст.")
        return target
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    finally:
        await file.close()


def safe_name(value):
    return Path((value or "file").replace("\\", "/")).name[:180]


@app.post("/api/captures")
async def upload_capture(file: UploadFile = File(...)):
    with connect() as db:
        idle(db)
    name = safe_name(file.filename)
    target = await save_upload(file, config.MAX_CAPTURE)
    try:
        result = await asyncio.to_thread(import_capture, target, name)
        if result["added"]:
            target.replace(config.DATA / "captures" / f"{uid()}{Path(name).suffix.lower()}")
        audit("capture_import", str(result["added"]))
        return result
    except UnicodeDecodeError:
        raise ValueError("Текстовый файл должен быть в UTF-8.")
    finally:
        target.unlink(missing_ok=True)


@app.post("/api/wordlists")
async def upload_wordlist(file: UploadFile = File(...)):
    name = safe_name(file.filename)
    target = await save_upload(file, config.MAX_WORDLIST)
    try:
        result = await asyncio.to_thread(import_wordlist, target, name)
        audit("wordlist_import", result["id"])
        return result
    finally:
        target.unlink(missing_ok=True)


@app.put("/api/queue")
async def selection(request: Request):
    payload = await payload_json(request)
    ids = payload.get("ids")
    if not isinstance(ids, list) or len(ids)>100 or any(not isinstance(x,str) for x in ids) or len(set(ids))!=len(ids):
        raise ValueError("Некорректная очередь словарей.")
    with connect(True) as db:
        idle(db)
        for identity in ids:
            if not db.execute("SELECT 1 FROM wordlists WHERE id=?", (identity,)).fetchone():
                raise ValueError("Словарь не найден.")
        db.execute("UPDATE wordlists SET position=NULL")
        for pos, identity in enumerate(ids, 1):
            db.execute("UPDATE wordlists SET position=? WHERE id=?", (pos, identity))
    return {"ok": True}


@app.delete("/api/wordlists/{identity}")
def delete_wordlist(identity: str):
    with connect(True) as db:
        idle(db)
        row = db.execute("SELECT path FROM wordlists WHERE id=?", (identity,)).fetchone()
        if not row:
            raise ValueError("Словарь не найден.")
        db.execute("DELETE FROM wordlists WHERE id=?", (identity,))
        selected = [r[0] for r in db.execute("SELECT id FROM wordlists WHERE position IS NOT NULL ORDER BY position")]
        db.execute("UPDATE wordlists SET position=NULL")
        for pos, wid in enumerate(selected,1):
            db.execute("UPDATE wordlists SET position=? WHERE id=?", (pos,wid))
    (config.DATA / row[0]).unlink(missing_ok=True)
    return {"ok": True}


@app.post("/api/jobs")
async def start_job(request: Request):
    payload = await payload_json(request)
    runtime = payload.get("runtime", 0)
    workload = payload.get("workload", 2)
    if type(runtime) is not int or not 0 <= runtime <= 86400 or type(workload) is not int or workload not in (1,2,3):
        raise ValueError("Некорректное ограничение времени или нагрузка.")
    with connect(True) as db:
        idle(db)
        heartbeat = db.execute("SELECT value FROM meta WHERE key='worker_heartbeat'").fetchone()
        if not heartbeat or time.time()-float(heartbeat[0]) > 15:
            raise ValueError("Worker недоступен. Проверьте раздел «Сервер».")
        ids = payload.get("hash_ids")
        all_ids = {r[0] for r in db.execute("SELECT id FROM hashes WHERE password_hex IS NULL")}
        if ids is None:
            ids = sorted(all_ids)
        if not isinstance(ids,list) or not ids or any(not isinstance(x,str) or x not in all_ids for x in ids) or len(set(ids))!=len(ids):
            raise ValueError("Выберите сети, для которых пароль ещё не найден.")
        wordlists = [dict(r) for r in db.execute("SELECT id,name,path,bytes,lines FROM wordlists WHERE position IS NOT NULL ORDER BY position")]
        if not wordlists:
            raise ValueError("Добавьте хотя бы один словарь в очередь.")
        for word in wordlists:
            if not (config.DATA / word["path"]).is_file():
                raise ValueError("Один из файлов словарей недоступен.")
        name = str(payload.get("name", "Wi-Fi audit")).strip()[:100] or "Wi-Fi audit"
        identity = uid()
        db.execute("INSERT INTO jobs(id,name,status,created,hash_ids,wordlists,runtime,workload) VALUES (?,?,?,?,?,?,?,?)",
                   (identity,name,"queued",time.time(),json.dumps(ids),json.dumps(wordlists),runtime,workload))
    audit("job_queued", identity)
    return {"id": identity}


@app.post("/api/jobs/{identity}/{action}")
def job_action(identity: str, action: str):
    with connect(True) as db:
        job = db.execute("SELECT * FROM jobs WHERE id=?", (identity,)).fetchone()
        if not job:
            raise ValueError("Задача не найдена.")
        status = job["status"]
        if action == "resume" and status in ("paused","interrupted"):
            if db.execute("SELECT 1 FROM jobs WHERE status IN ('queued','running','pausing','stopping')").fetchone():
                raise ValueError("Другая задача уже выполняется.")
            db.execute("UPDATE jobs SET status='queued',action=NULL,error=NULL,finished=NULL WHERE id=?", (identity,))
        elif action == "pause" and status == "running":
            db.execute("UPDATE jobs SET action='pause',status='pausing' WHERE id=?", (identity,))
        elif action == "stop" and status in ("queued","paused","interrupted"):
            db.execute("UPDATE jobs SET status='stopped',action=NULL,finished=? WHERE id=?", (time.time(),identity))
        elif action in ("stop", "skip") and status == "running":
            db.execute("UPDATE jobs SET action=?,status=? WHERE id=?", (action,"stopping" if action=="stop" else "running",identity))
        else:
            raise ValueError("Действие недоступно в текущем состоянии задачи.")
    audit("job_"+action, identity)
    return {"ok": True}


@app.post("/api/reset")
async def reset(request: Request):
    if (await payload_json(request)).get("confirmation") not in ("CLEAR", "ОЧИСТИТЬ"):
        raise ValueError("Для подтверждения введите ОЧИСТИТЬ.")
    with connect(True) as db:
        idle(db)
        db.execute("DELETE FROM jobs")
        db.execute("DELETE FROM hashes")
    for folder in ("runs","captures"):
        for path in (config.DATA/folder).iterdir():
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
    (config.DATA/"hashcat.potfile").unlink(missing_ok=True)
    audit("workspace_reset")
    return {"ok": True}


@app.get("/api/export")
def export(request: Request):
    tr = lambda message: translate(message, language(request))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([tr(message) for message in ["SSID","Source","Result","Password","Recovered UTC"]])
    with connect() as db:
        for row in db.execute("SELECT * FROM hashes ORDER BY created"):
            password = bytes.fromhex(row["password_hex"]).decode("utf-8","replace") if row["password_hex"] is not None else ""
            cells = [row["ssid"],row["source"],tr("Recovered") if row["password_hex"] is not None else tr("Not recovered"),password,str(row["recovered_at"] or "")]
            # Avoid spreadsheet formulas in arbitrary SSIDs or passwords.
            writer.writerow(["'"+c if c.startswith(("=","+","-","@","\t","\r")) else c for c in cells])
    audit("export_results")
    return Response("\ufeff"+output.getvalue(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="wifi-audit-results.csv"'})


@app.get("/api/attempts/{identity}/log")
def pass_log(identity: str, request: Request):
    with connect() as db:
        row = db.execute("SELECT log_path FROM attempts WHERE id=?", (identity,)).fetchone()
    if not row or not (config.DATA/row[0]).is_file():
        return JSONResponse({"detail":translate("Журнал не найден.", language(request))}, status_code=404)
    path = config.DATA/row[0]
    with path.open("rb") as file:
        file.seek(max(0,path.stat().st_size-128000))
        value = file.read().decode("utf-8","replace")
    return {"text": value}


def gpu_info():
    try:
        run = subprocess.run(["nvidia-smi","--query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,driver_version","--format=csv,noheader,nounits"], capture_output=True,text=True,timeout=5)
        if run.returncode:
            return {"available":False}
        parts = [v.strip() for v in run.stdout.splitlines()[0].split(",")]
        return {"available":True,"name":parts[0],"temperature":float(parts[1]),"utilization":float(parts[2]),"memory_used":float(parts[3]),"memory_total":float(parts[4]),"power":float(parts[5]),"driver":parts[6]}
    except (OSError,subprocess.TimeoutExpired,ValueError,IndexError):
        return {"available":False}


@app.get("/api/system")
def system():
    gpu = gpu_info()
    disk = shutil.disk_usage(config.DATA)
    with connect() as db:
        worker = db.execute("SELECT value FROM meta WHERE key='worker_heartbeat'").fetchone()
        engine = db.execute("SELECT value FROM meta WHERE key='engine_info'").fetchone()
    return {"gpu":gpu,"disk":{"free":disk.free,"total":disk.total},"worker_online":bool(worker and time.time()-float(worker[0])<15),"engine":json.loads(engine[0]) if engine else {},"load":os.getloadavg()[0],"cpu_threads":os.cpu_count()}


def parse_repo(value):
    if not isinstance(value,str):
        raise ValueError("Укажите публичный репозиторий GitHub.")
    value = value.strip()
    if value.startswith("https://github.com/"):
        value = urlparse(value).path.strip("/")
    match = re.fullmatch(r"([A-Za-z0-9_-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?",value)
    if not match or ".." in match[2]:
        raise ValueError("Используйте owner/repo или https://github.com/owner/repo.")
    return match[1],match[2]


async def github_get(client,url):
    response = await client.get(url)
    if response.status_code in (403,429):
        raise ValueError("GitHub ограничил запросы. Повторите позже.")
    if response.status_code != 200:
        raise ValueError("Публичный репозиторий или файл GitHub не найден.")
    return response.json()


@app.post("/api/github/catalog")
async def github_catalog(request: Request):
    owner,repo = parse_repo((await payload_json(request)).get("repository"))
    async with httpx.AsyncClient(timeout=30,follow_redirects=False,headers={"Accept":"application/vnd.github+json","User-Agent":"wifi-audit/1.0"}) as client:
        info = await github_get(client,f"https://api.github.com/repos/{owner}/{repo}")
        commit = await github_get(client,f"https://api.github.com/repos/{owner}/{repo}/commits/{quote(info['default_branch'],safe='')}")
        sha = commit["sha"]
        tree = await github_get(client,f"https://api.github.com/repos/{owner}/{repo}/git/trees/{sha}?recursive=1")
    files = [{"path":r["path"],"bytes":r.get("size",0)} for r in tree.get("tree",[]) if r.get("type")=="blob" and 0<r.get("size",0)<=config.MAX_GITHUB_WORDLIST and Path(r["path"]).suffix.lower() in (".txt",".lst",".dic",".wordlist")]
    stamp = signer.dumps({"owner":owner,"repo":repo,"commit":sha})
    # Keep relevant dictionaries visible when large repositories exceed the display cap.
    priority=lambda r:(not any(term in r["path"].lower() for term in ("password","wordlist","dictionary","common-credentials")),r["path"])
    return {"files":sorted(files,key=priority)[:1500],"truncated":tree.get("truncated",False) or len(files)>1500,"stamp":stamp,"commit":sha}


@app.post("/api/github/import")
async def github_import(request: Request):
    payload = await payload_json(request)
    try:
        entry = signer.loads(payload.get("stamp",""),max_age=3600)
    except (BadSignature,SignatureExpired):
        raise ValueError("Обновите каталог GitHub.")
    path = payload.get("path","")
    if not isinstance(path,str) or len(path)>500 or path.startswith("/") or any(v in (".","..") for v in path.split("/")) or Path(path).suffix.lower() not in (".txt",".lst",".dic",".wordlist"):
        raise ValueError("Некорректный путь словаря.")
    url = f"https://raw.githubusercontent.com/{entry['owner']}/{entry['repo']}/{entry['commit']}/{quote(path,safe='/')}"
    target = config.DATA/"tmp"/uid()
    size = 0
    try:
        async with httpx.AsyncClient(timeout=60,follow_redirects=False) as client:
            async with client.stream("GET",url) as response:
                if response.status_code != 200:
                    raise ValueError("Не удалось скачать файл из GitHub.")
                with target.open("xb") as out:
                    target.chmod(0o600)
                    async for chunk in response.aiter_bytes(1024*1024):
                        size+=len(chunk)
                        if size>config.MAX_GITHUB_WORDLIST:
                            raise ValueError("GitHub dictionary limit is 1.5 GB.")
                        await asyncio.to_thread(out.write,chunk)
        result=await asyncio.to_thread(import_wordlist,target,safe_name(path),f"GitHub · {entry['owner']}/{entry['repo']} @ {entry['commit'][:8]}")
        audit("github_import",result["id"])
        return result
    except httpx.HTTPError:
        raise ValueError("Ошибка соединения с GitHub. Повторите позже.")
    finally:
        target.unlink(missing_ok=True)
