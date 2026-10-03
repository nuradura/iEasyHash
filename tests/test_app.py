import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from conftest import login,synthetic,TEST_PASSWORD
from webapp.db import connect


def upload_network(client):
    result=client.post('/api/captures',files={'file':('own.22000',synthetic(),'text/plain')})
    assert result.status_code==200,result.text
    return client.get('/api/state').json()['hashes'][0]['id']


def upload_word(client,name='own.txt',text=b'wrong-candidate\n'):
    result=client.post('/api/wordlists',files={'file':(name,text,'text/plain')})
    assert result.status_code==200,result.text
    return result.json()['id']


def test_authentication_and_crawler_headers(client):
    for path in ['/api/state','/api/export','/api/system','/api/hashes/unknown/password','/api/attempts/unknown/log']:
        response=client.get(path)
        assert response.status_code==401
        assert response.headers['x-robots-tag'].startswith('noindex')
        assert 'no-store' in response.headers['cache-control']
    assert client.get('/',follow_redirects=False).status_code==303
    assert client.get('/robots.txt').text=='User-agent: *\nDisallow: /\n'
    assert client.get('/docs',follow_redirects=False).status_code==303
    assert client.get('/',headers={'Host':'attacker.example'}).status_code==400
    login(client)
    assert client.get('/api/state').status_code==200
    assert 'frame-ancestors' in client.get('/').headers['content-security-policy']


def test_csrf_and_cross_origin(client):
    login(client)
    assert client.post('/api/jobs',headers={'X-CSRF-Token':''},json={}).status_code==403
    assert client.post('/api/jobs',headers={'Origin':'https://evil.example'},json={}).status_code==403


def test_validation_and_deduplication(client):
    login(client)
    result=client.post('/api/captures',files={'file':('x.txt','not a WPA hash','text/plain')})
    assert result.status_code==400
    upload_network(client)
    duplicate=client.post('/api/captures',files={'file':('own.22000',synthetic(),'text/plain')})
    assert duplicate.json()['added']==0 and duplicate.json()['duplicates']==1
    one=upload_word(client)
    assert upload_word(client,'duplicate.txt')==one
    binary=client.post('/api/wordlists',files={'file':('invalid.txt',b'\x00','text/plain')})
    assert binary.status_code==400
    traversal=upload_word(client,'../../untrusted.txt',b'other-candidate\n')
    row=next(r for r in client.get('/api/state').json()['wordlists'] if r['id']==traversal)
    assert row['name']=='untrusted.txt'


def test_queue_snapshot_double_start_and_mutation_lock(client):
    login(client)
    hash_id=upload_network(client)
    first=upload_word(client)
    second=upload_word(client,'second.txt',b'other-candidate\n')
    assert client.put('/api/queue',json={'ids':[second,first]}).status_code==200
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses=list(pool.map(lambda _:client.post('/api/jobs',json={'name':'Own networks'}),range(2)))
    assert sorted(r.status_code for r in responses)==[200,400]
    snapshot=client.get('/api/state').json()
    job=snapshot['jobs'][0]
    assert job['hash_ids']==[hash_id]
    assert [w['id'] for w in job['wordlists']]==[second,first]
    assert 'path' not in job['wordlists'][0]
    assert client.put('/api/queue',json={'ids':[]}).status_code==400
    assert client.post('/api/captures',files={'file':('own.22000',synthetic(),'text/plain')}).status_code==400
    assert client.post('/api/jobs/'+job['id']+'/stop').status_code==200
    assert client.put('/api/queue',json={'ids':[]}).status_code==200


def test_results_are_hidden_in_state_and_csv_is_safe(client):
    login(client)
    response=client.post('/api/captures',files={'file':('own.22000',synthetic(b'=FORMULA'),'text/plain')})
    assert response.status_code==200
    hash_id=client.get('/api/state').json()['hashes'][0]['id']
    with connect(True) as db:
        db.execute('UPDATE hashes SET password_hex=? WHERE id=?',(b'=private-result'.hex(),hash_id))
    state=client.get('/api/state')
    assert 'private-result' not in state.text and 'password_hex' not in state.text
    assert client.get('/api/hashes/'+hash_id+'/password').json()['password']=='=private-result'
    exported=client.get('/api/export').text
    assert "'=FORMULA" in exported and "'=private-result" in exported


def test_login_throttling_and_forged_cookie(client):
    page=client.get('/login')
    nonce=re.search('name="login-nonce" content="([^"]+)"',page.text)[1]
    for i in range(6):
        assert client.post('/login',json={'username':'admin','password':'wrong','nonce':nonce}).status_code==401
    assert client.post('/login',json={'username':'admin','password':'wrong','nonce':nonce}).status_code==429
    client.cookies.set('wifi_session','forged')
    assert client.get('/api/state').status_code==401


def test_password_change_revokes_sessions(client):
    login(client)
    wrong=client.post('/api/profile/password',json={'current':'wrong','new':'new-long-test-password'})
    assert wrong.status_code==400
    assert client.post('/api/profile/password',json={'current':TEST_PASSWORD,'new':'new-long-test-password'}).status_code==200
    assert client.get('/api/state').status_code==401
    login(client,'new-long-test-password')


def test_reset_preserves_dictionary_order(client):
    login(client)
    upload_network(client)
    word=upload_word(client)
    client.put('/api/queue',json={'ids':[word]})
    assert client.post('/api/reset',json={'confirmation':'NO'}).status_code==400
    assert client.post('/api/reset',json={'confirmation':'ОЧИСТИТЬ'}).status_code==200
    result=client.get('/api/state').json()
    assert result['hashes']==[] and result['jobs']==[]
    assert result['wordlists'][0]['position']==1


def test_capture_conversion(client, monkeypatch):
    from types import SimpleNamespace
    from webapp import imports
    def converter(args, **kwargs):
        assert args[0] == imports.config.CONVERTER
        assert args[1] == '-o'
        assert Path(args[3]).read_bytes() == b'synthetic-capture'
        Path(args[2]).write_text(synthetic(ssid=b'Demo One') + synthetic(ssid=b'Demo Two'))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(imports.subprocess, 'run', converter)
    login(client)
    result=client.post('/api/captures',files={'file':('demo.pcap',b'synthetic-capture','application/octet-stream')})
    assert result.status_code==200,result.text
    assert result.json()['added']==2


def test_worker_crash_preserves_per_hash_history(client):
    import json
    from webapp.worker import reconcile
    login(client)
    identity=upload_network(client)
    word=upload_word(client)
    client.put('/api/queue',json={'ids':[word]})
    job=client.post('/api/jobs',json={}).json()['id']
    with connect(True) as db:
        db.execute("UPDATE jobs SET status='running' WHERE id=?",(job,))
        db.execute("INSERT INTO attempts(id,job_id,pass_index,wordlist_id,wordlist_name,started,outcome,participants,log_path) VALUES ('crash',?,0,?,'crash test',?,'running',?,'unused')",(job,word,time.time(),json.dumps([identity])))
    reconcile()
    result=client.get('/api/state').json()
    assert result['jobs'][0]['status']=='interrupted'
    assert result['attempts'][0]['outcome']=='interrupted'
    assert client.get('/api/hashes/'+identity).json()['passes'][0]['outcome']=='interrupted'
    assert client.post('/api/captures',files={'file':('own.22000',synthetic(),'text/plain')}).status_code==400


def test_malformed_login_request_is_bounded(client):
    assert client.post('/login',json=[]).status_code==400
    assert client.post('/login',content='x'*9000,headers={'Content-Type':'application/json'}).status_code==400


def test_progress_is_private_and_matches_measured_job(client):
    assert client.get('/api/progress').status_code == 401
    login(client)
    assert client.get('/api/progress').json()['job'] is None
    upload_network(client)
    word = upload_word(client)
    client.put('/api/queue', json={'ids': [word]})
    identity = client.post('/api/jobs', json={}).json()['id']
    with connect(True) as db:
        db.execute('UPDATE jobs SET progress=? WHERE id=?', ('{"percent":37.25,"pass_index":1}', identity))
    response = client.get('/api/progress')
    job = response.json()['job']
    assert job['id'] == identity and job['progress']['percent'] == 37.25
    assert 'pid' not in job and 'path' not in job['wordlists'][0]


def test_github_catalog_accepts_large_dictionaries(client, monkeypatch):
    import importlib
    from types import SimpleNamespace
    module = importlib.import_module('webapp.app')
    limit = module.config.MAX_GITHUB_WORDLIST
    assert limit == 1_500_000_000
    sizes = [50_000_001, 550_000_000, limit, limit + 1]
    class GitHubClient:
        def __init__(self, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url):
            if '/git/trees/' in url:
                data = {'tree': [dict(type='blob', path=f'dictionary-{i}.txt', size=size)
                                 for i, size in enumerate(sizes)], 'truncated': False}
            elif '/commits/' in url:
                data = {'sha': 'a' * 40}
            else:
                data = {'default_branch': 'main'}
            return SimpleNamespace(status_code=200, json=lambda: data)
    monkeypatch.setattr(module.httpx, 'AsyncClient', GitHubClient)
    login(client)
    result = client.post('/api/github/catalog', json={'repository': 'demo/dictionaries'})
    assert result.status_code == 200
    assert [file['bytes'] for file in result.json()['files']] == sizes[:3]


def test_github_stream_limit_and_cleanup(client, monkeypatch):
    import importlib
    module = importlib.import_module('webapp.app')
    # Scale the boundary down, exercising the same byte-counting code without
    # allocating or downloading a gigabyte-sized test fixture.
    monkeypatch.setattr(module.config, 'MAX_GITHUB_WORDLIST', 8)
    chunks = [b'one\n', b'two\n']
    closed = []
    class Stream:
        status_code = 200
        async def __aenter__(self): return self
        async def __aexit__(self, *args): closed.append(True)
        async def aiter_bytes(self, size):
            assert size == 1024 * 1024
            for chunk in chunks:
                yield chunk
    class GitHubClient:
        def __init__(self, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        def stream(self, method, url): return Stream()
    monkeypatch.setattr(module.httpx, 'AsyncClient', GitHubClient)
    login(client)
    payload = {'stamp': module.signer.dumps({'owner': 'demo', 'repo': 'dictionaries',
                'commit': 'a' * 40}), 'path': 'test.txt'}
    result = client.post('/api/github/import', json=payload)
    assert result.status_code == 200
    with connect() as db:
        word = db.execute('SELECT bytes,lines FROM wordlists').fetchone()
    assert tuple(word) == (8, 2)
    chunks.append(b'x')
    for language in ('en', 'ru', 'zh'):
        client.cookies.set('ieasyhash_lang', language)
        result = client.post('/api/github/import', json=payload)
        assert result.status_code == 400
        from webapp.i18n import translate
        assert result.json()['detail'] == translate('GitHub dictionary limit is 1.5 GB.', language)
        assert list((module.config.DATA / 'tmp').iterdir()) == []
    assert len(closed) == 4
    with connect() as db:
        assert db.execute('SELECT count(*) FROM wordlists').fetchone()[0] == 1
