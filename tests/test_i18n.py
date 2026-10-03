import csv
import io

import pytest

from conftest import login, synthetic
from webapp.db import connect
from webapp.i18n import MESSAGES, translate


@pytest.mark.parametrize('language,html,title', [
    ('en', 'en', 'Sign in'), ('ru', 'ru', 'Вход'), ('zh', 'zh-Hans', '登录'),
])
def test_language_pages_errors_and_csv(client, language, html, title):
    client.cookies.set('ieasyhash_lang', language)
    response = client.get('/login')
    assert f'<html lang="{html}">' in response.text
    assert title in response.text
    assert response.headers['content-language'] == html
    assert client.get('/api/state').json()['detail'] == translate('Требуется вход.', language)
    login(client)
    assert f'<html lang="{html}">' in client.get('/').text
    error = client.put('/api/queue', json={'ids': ['missing']})
    assert error.json()['detail'] == translate('Словарь не найден.', language)
    csrf = client.post('/api/reset', headers={'X-CSRF-Token': ''}, json={})
    assert csrf.status_code == 403
    assert csrf.json()['detail'] == translate('Обновите страницу и повторите действие.', language)
    ssid, password = 'Тест 测试', 'пример 示例'
    assert client.post('/api/captures', files={'file': ('demo.22000', synthetic(ssid.encode()), 'text/plain')}).status_code == 200
    with connect(True) as db:
        db.execute('UPDATE hashes SET password_hex=?', (password.encode().hex(),))
    rows = list(csv.reader(io.StringIO(client.get('/api/export').text.lstrip('\ufeff'))))
    assert rows[0][1] == translate('Source', language)
    assert rows[1][0] == ssid and rows[1][3] == password
    assert rows[1][2] == translate('Recovered', language)
    assert client.post('/api/reset', json={'confirmation': 'CLEAR'}).status_code == 200


@pytest.mark.parametrize('cookie', [None, 'unknown', '../../ru'])
def test_english_default_and_invalid_cookie(client, cookie):
    if cookie:
        client.cookies.set('ieasyhash_lang', cookie)
    response = client.get('/login', headers={'Accept-Language': 'ru,zh;q=0.9'})
    assert '<html lang="en">' in response.text
    assert response.headers['content-language'] == 'en'


def test_catalog_complete_and_unknown_user_data_preserved():
    for key, entry in MESSAGES.items():
        assert set(entry) == {'en', 'ru', 'zh'}, key
        assert all(isinstance(value, str) and value for value in entry.values()), key
    assert translate('Словарь не найден.', 'en') == 'Dictionary not found.'
    assert translate('My сеть 网络', 'zh') == 'My сеть 网络'
