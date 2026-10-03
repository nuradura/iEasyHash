from contextlib import contextmanager
import json
import sqlite3
import time
import uuid
from . import config


def uid():
    return uuid.uuid4().hex


@contextmanager
def connect(write=False):
    db = sqlite3.connect(config.DB, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=15000")
    try:
        if write:
            db.execute("BEGIN IMMEDIATE")
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def init():
    config.ensure_data()
    with connect() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS hashes (
          id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, ssid TEXT NOT NULL,
          source TEXT NOT NULL, created REAL NOT NULL, password_hex TEXT,
          recovered_at REAL, recovered_job TEXT);
        CREATE TABLE IF NOT EXISTS wordlists (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, path TEXT NOT NULL UNIQUE,
          source TEXT NOT NULL, bytes INTEGER NOT NULL, lines INTEGER NOT NULL,
          sha256 TEXT NOT NULL UNIQUE, position INTEGER UNIQUE, created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS jobs (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL,
          created REAL NOT NULL, started REAL, finished REAL, hash_ids TEXT NOT NULL,
          wordlists TEXT NOT NULL, next_index INTEGER NOT NULL DEFAULT 0,
          action TEXT, progress TEXT NOT NULL DEFAULT '{}', error TEXT,
          runtime INTEGER NOT NULL DEFAULT 0, workload INTEGER NOT NULL DEFAULT 2,
          heartbeat REAL, pid INTEGER);
        CREATE TABLE IF NOT EXISTS attempts (
          id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
          pass_index INTEGER NOT NULL, wordlist_id TEXT NOT NULL, wordlist_name TEXT NOT NULL,
          started REAL NOT NULL, finished REAL, outcome TEXT NOT NULL,
          exit_code INTEGER, recovered INTEGER NOT NULL DEFAULT 0,
          participants TEXT NOT NULL, log_path TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS hash_passes (
          hash_id TEXT NOT NULL REFERENCES hashes(id) ON DELETE CASCADE,
          attempt_id TEXT NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
          outcome TEXT NOT NULL, PRIMARY KEY(hash_id,attempt_id));
        CREATE TABLE IF NOT EXISTS sessions (
          id TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires REAL NOT NULL,
          created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS login_limits (
          ip TEXT PRIMARY KEY, failures INTEGER NOT NULL, window REAL NOT NULL,
          blocked_until REAL NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL,
          event TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');
        INSERT OR IGNORE INTO meta VALUES ('schema','1');
        """)


def audit(event, detail=""):
    with connect(True) as db:
        db.execute("INSERT INTO audit(at,event,detail) VALUES (?,?,?)", (time.time(), event, detail[:300]))


def active(db):
    return db.execute("SELECT id FROM jobs WHERE status IN ('queued','running','pausing','stopping') LIMIT 1").fetchone()


def idle(db):
    # Paused jobs retain a snapshot; changing hashes or deleting files is also forbidden.
    if db.execute("SELECT id FROM jobs WHERE status IN ('queued','running','pausing','stopping','paused','interrupted') LIMIT 1").fetchone():
        raise ValueError("Сначала завершите или остановите сохранённую задачу.")


def public_job(row):
    result = dict(row)
    result["hash_ids"] = json.loads(result["hash_ids"])
    result["wordlists"] = [{k: w[k] for k in ("id", "name", "bytes", "lines")} for w in json.loads(result["wordlists"])]
    result["progress"] = json.loads(result["progress"])
    result.pop("pid", None)
    return result
