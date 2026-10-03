import os
import tempfile
from pathlib import Path
import time

import pytest
from argon2 import PasswordHasher

TEST_PASSWORD='test-owner-password-2026'
_initial=tempfile.TemporaryDirectory(prefix='wifi-api-tests-')
os.environ.update(WIFI_DATA_DIR=_initial.name,WIFI_SESSION_SECRET='test-only-session-secret-'*3,
                  WIFI_ADMIN_PASSWORD_HASH=PasswordHasher().hash(TEST_PASSWORD),WIFI_COOKIE_SECURE='0',
                  WIFI_PUBLIC_URL='http://testserver')
from webapp import config
from webapp.db import connect,init
from webapp.app import app
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setattr(config,'DATA',tmp_path)
    monkeypatch.setattr(config,'DB',tmp_path/'library.sqlite3')
    init()
    with connect(True) as db:
        db.execute("INSERT OR REPLACE INTO meta VALUES ('admin_password_hash',?)",(PasswordHasher().hash(TEST_PASSWORD),))
        db.execute("INSERT OR REPLACE INTO meta VALUES ('worker_heartbeat',?)",(str(time.time()),))
    with TestClient(app) as c:
        yield c


def login(client,password=TEST_PASSWORD):
    import re
    response=client.get('/login')
    nonce=re.search('name="login-nonce" content="([^"]+)"',response.text)[1]
    response=client.post('/login',json={'username':'admin','password':password,'nonce':nonce})
    assert response.status_code==200,response.text
    page=client.get('/')
    token=re.search('name="csrf-token" content="([^"]+)"',page.text)[1]
    client.headers.update({'X-CSRF-Token':token})
    return token


def synthetic(ssid=b'Setup Network',password=b'synthetic-owner-password'):
    import hashlib,hmac
    ap=bytes.fromhex('020000000001');station=bytes.fromhex('020000000002')
    pmk=hashlib.pbkdf2_hmac('sha1',password,ssid,4096,32)
    pmkid=hmac.new(pmk,b'PMK Name'+ap+station,hashlib.sha1).digest()[:16]
    return f'WPA*01*{pmkid.hex()}*{ap.hex()}*{station.hex()}*{ssid.hex()}***\n'
