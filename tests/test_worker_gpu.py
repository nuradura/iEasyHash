"""Integration tests use synthetic hashes only, never the owner's networks."""
import os
import pytest
from pathlib import Path
import subprocess
import sys
import time

from conftest import login,synthetic
from webapp import config
from webapp.db import connect
from test_app import upload_word

pytestmark = pytest.mark.gpu


def wait_for(predicate,timeout=120):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        value=predicate()
        if value:
            return value
        time.sleep(.4)
    raise AssertionError('Timed out waiting for worker')


def start_worker():
    env=dict(os.environ,WIFI_DATA_DIR=str(config.DATA),HOME=str(config.DATA),XDG_CACHE_HOME=str(config.DATA/'cache'))
    return subprocess.Popen([sys.executable,'-m','webapp.worker'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)


def test_gpu_queue_result_and_early_completion(client):
    login(client)
    client.post('/api/captures',files={'file':('test.22000',synthetic(),'text/plain')})
    first=upload_word(client,'first.txt',b'wrong-candidate\n')
    second=upload_word(client,'second.txt',b'synthetic-owner-password\n')
    third=upload_word(client,'unused.txt',b'never-tried-password\n')
    client.put('/api/queue',json={'ids':[first,second,third]})
    job=client.post('/api/jobs',json={'name':'Synthetic GPU integration'}).json()['id']
    worker=start_worker()
    try:
        def terminal():
            value=client.get('/api/state').json()['jobs'][0]
            return value if value['status'] in ('completed','failed') else None
        value=wait_for(terminal)
        assert value['status']=='completed',value
        result=client.get('/api/state').json()
        assert result['hashes'][0]['recovered']==1,result
        assert len(result['attempts'])==2,result['attempts']
        assert {a['outcome'] for a in result['attempts']}=={'exhausted','recovered'}
        identity=result['hashes'][0]['id']
        assert client.get('/api/hashes/'+identity+'/password').json()['password']=='synthetic-owner-password'
        for attempt in result['attempts']:
            text=client.get('/api/attempts/'+attempt['id']+'/log').json()['text']
            assert 'synthetic-owner-password' not in text
    finally:
        worker.terminate()
        worker.wait(timeout=30)
        stdout,stderr=worker.communicate()
        assert worker.returncode==0,(stdout.decode(),stderr.decode())


def test_gpu_pause_restart_resume_and_stop(client):
    login(client)
    # 300k wrong candidates give time to write a restore checkpoint on this GPU.
    client.post('/api/captures',files={'file':('test.22000',synthetic(password=b'not-in-the-wordlist'),'text/plain')})
    word=upload_word(client,'pause.txt',b''.join(f'wrong-candidate-{i:08d}\n'.encode() for i in range(300000)))
    client.put('/api/queue',json={'ids':[word]})
    identity=client.post('/api/jobs',json={'name':'Synthetic pause'}).json()['id']
    worker=start_worker()
    try:
        wait_for(lambda:client.get('/api/state').json()['jobs'][0]['status']=='running')
        wait_for(lambda:client.get('/api/state').json()['jobs'][0]['progress'].get('checked',0)>0)
        assert client.post('/api/jobs/'+identity+'/pause').status_code==200
        wait_for(lambda:client.get('/api/state').json()['jobs'][0]['status']=='paused')
        worker.terminate();worker.wait(timeout=30)
        worker=start_worker()
        assert client.post('/api/jobs/'+identity+'/resume').status_code==200
        wait_for(lambda:client.get('/api/state').json()['jobs'][0]['status']=='running')
        assert client.post('/api/jobs/'+identity+'/stop').status_code==200
        wait_for(lambda:client.get('/api/state').json()['jobs'][0]['status']=='stopped')
        result=client.get('/api/state').json()
        assert not result['hashes'][0]['recovered']
        assert len(result['attempts'])==2
    finally:
        if worker.poll() is None:
            worker.terminate();worker.wait(timeout=30)
