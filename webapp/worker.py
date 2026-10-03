"""Persistent single-GPU wordlist worker. Never accepts shell commands."""
import fcntl
import json
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import threading
import time

from . import config
from .db import connect, init, uid

shutdown = threading.Event()
current_process = None


def update_job(identity, **fields):
    if not fields:
        return
    with connect(True) as db:
        db.execute("UPDATE jobs SET " + ",".join(k+"=?" for k in fields) + " WHERE id=?", (*fields.values(),identity))


def heartbeat():
    with connect(True) as db:
        db.execute("INSERT OR REPLACE INTO meta VALUES ('worker_heartbeat',?)",(str(time.time()),))


def sync_results(hashes_file, job_id=None):
    result = subprocess.run([config.HASHCAT,"-m","22000","--show",str(hashes_file),
                             "--potfile-path",str(config.DATA/"hashcat.potfile"),
                             "--outfile-format","1,3","--quiet"],capture_output=True,timeout=30)
    if result.returncode not in (0,1):
        raise RuntimeError("Hashcat не смог прочитать сохранённые результаты.")
    found = []
    for line in result.stdout.splitlines():
        if b":" not in line:
            continue
        value, password = line.rsplit(b":",1)
        if not re.fullmatch(rb"(?:[0-9a-fA-F]{2})*",password):
            continue
        fields=value.split(b":",3)
        if len(fields)!=4:
            continue
        ssid=fields[3]
        if ssid.startswith(b"$HEX[") and ssid.endswith(b"]"):
            try:
                ssid=bytes.fromhex(ssid[5:-1].decode('ascii'))
            except ValueError:
                continue
        found.append(((fields[0].lower(),fields[1].lower(),fields[2].lower(),ssid),password.decode('ascii').lower()))
    count = 0
    with connect(True) as db:
        lookup={}
        for row in db.execute("SELECT id,hash FROM hashes WHERE password_hex IS NULL"):
            parts=row['hash'].split('*')
            key=(parts[2].lower().encode(),parts[3].lower().encode(),parts[4].lower().encode(),bytes.fromhex(parts[5]))
            lookup.setdefault(key,[]).append(row['id'])
        for key,password in found:
            # Mode 22000 emits MIC/PMKID:AP:STA:ESSID, not the full WPA line.
            for identity in lookup.get(key,[]):
                cursor = db.execute("UPDATE hashes SET password_hex=?,recovered_at=?,recovered_job=? WHERE id=? AND password_hex IS NULL",
                                    (password,time.time(),job_id,identity))
                count += cursor.rowcount
    return count


def consume(stream, target):
    try:
        for line in iter(stream.readline,""):
            target.put(line)
    finally:
        stream.close()
        target.put(None)


def redacted(line):
    if "WPA*" in line or re.match(r"^[a-fA-F0-9]{32}[:*]",line.strip()):
        return "[Результат скрыт; доступен в карточке сети]\n"
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]","",line)[:4000]


def stop_process(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid,signal.SIGINT)
        except ProcessLookupError:
            pass


def run_pass(job, words, index, hashes_file):
    global current_process
    run_dir = config.DATA/"runs"/job["id"]
    run_dir.mkdir(exist_ok=True,mode=0o700)
    restore = run_dir/f"pass-{index}.restore"
    attempt = uid()
    log_relative = f"runs/{job['id']}/{attempt}.log"
    with connect(True) as db:
        participants=[r["id"] for r in db.execute("SELECT id FROM hashes WHERE password_hex IS NULL") if r["id"] in json.loads(job["hash_ids"])]
        db.execute("INSERT INTO attempts(id,job_id,pass_index,wordlist_id,wordlist_name,started,outcome,participants,log_path) VALUES (?,?,?,?,?,?,?,?,?)",
                   (attempt,job["id"],index,words["id"],words["name"],time.time(),"running",json.dumps(participants),log_relative))
    progress = {"percent":0,"speed":0,"pass_index":index+1,"wordlist":words["name"],"restored":restore.exists()}
    update_job(job["id"],progress=json.dumps(progress),heartbeat=time.time())
    if restore.exists():
        command=[config.HASHCAT,"--restore","--restore-file-path",str(restore)]
    else:
        command=[config.HASHCAT,"-m","22000","-a","0",str(hashes_file),str(config.DATA/words["path"]),
                 "-D","2","--backend-ignore-cuda","-w",str(job["workload"]),
                 "--session",f"wifi-{job['id']}-{index}","--restore-file-path",str(restore),
                 "--potfile-path",str(config.DATA/"hashcat.potfile"),
                 "--outfile",str(run_dir/f"pass-{index}.results"),"--outfile-format","1,3",
                 "--status","--status-json","--status-timer","1","--hwmon-temp-abort","85","--logfile-disable"]
        if job["runtime"]:
            command += ["--runtime",str(job["runtime"])]
    process = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL,text=True,errors="replace",bufsize=1,
                               cwd=run_dir,start_new_session=True)
    current_process = process
    update_job(job["id"],pid=process.pid)
    output=queue.Queue()
    reader=threading.Thread(target=consume,args=(process.stdout,output),daemon=True)
    reader.start()
    action=None
    signaled_at=None
    last_poll=0
    last_sync=0
    error_tail=[]
    reached_eof=False
    with (config.DATA/log_relative).open("w") as log:
        while not reached_eof or process.poll() is None:
            now=time.monotonic()
            if now-last_poll>0.5:
                with connect() as db:
                    row=db.execute("SELECT action FROM jobs WHERE id=?",(job["id"],)).fetchone()
                action=row[0] if row else "stop"
                if shutdown.is_set():
                    action="pause"
                if action in ("pause","stop","skip") and signaled_at is None:
                    stop_process(process)
                    signaled_at=now
                if signaled_at and now-signaled_at>20 and process.poll() is None:
                    os.killpg(process.pid,signal.SIGKILL)
                heartbeat()
                update_job(job["id"],heartbeat=time.time())
                last_poll=now
            if now-last_sync>10:
                sync_results(hashes_file,job["id"])
                last_sync=now
            try:
                line=output.get(timeout=0.2)
            except queue.Empty:
                if process.poll() is not None and not reader.is_alive() and output.empty():
                    break
                continue
            if line is None:
                reached_eof=True
                continue
            cleaned=redacted(line)
            if log.tell()<10*1024*1024:
                log.write(cleaned)
                log.flush()
            try:
                status=json.loads(line.strip())
            except (json.JSONDecodeError,ValueError):
                if cleaned.strip():
                    error_tail.append(cleaned.strip())
                    error_tail=error_tail[-8:]
                continue
            if not isinstance(status,dict) or "progress" not in status:
                continue
            values=status.get("progress",[0,0])
            devices=status.get("devices",[])
            if not isinstance(values,list) or len(values)!=2:
                continue
            progress.update({"percent":min(100,100*values[0]/values[1]) if values[1] else 0,
                             "checked":values[0],"total":values[1],
                             "speed":sum(d.get("speed",0) for d in devices),
                             "eta":status.get("estimated_stop"),
                             "engine_status":status.get("status"),
                             "rejected":status.get("rejected",0)})
            update_job(job["id"],progress=json.dumps(progress))
    code=process.wait()
    current_process = None
    sync_results(hashes_file,job["id"])
    now=time.time()
    with connect(True) as db:
        requested=db.execute("SELECT action FROM jobs WHERE id=?",(job["id"],)).fetchone()
        if requested and requested[0]:
            action=requested[0]
        if shutdown.is_set():
            action="pause"
        recovered_ids={r[0] for r in db.execute("SELECT id FROM hashes WHERE password_hex IS NOT NULL")}
        new_count=sum(p in recovered_ids for p in participants)
        if action=="skip":
            outcome="skipped"
        elif action=="stop":
            outcome="stopped"
        elif action=="pause" or code in (2,3,4):
            outcome="paused"
        elif code==0:
            outcome="recovered"
        elif code==1:
            outcome="exhausted"
        else:
            outcome="failed"
        db.execute("UPDATE attempts SET finished=?,outcome=?,exit_code=?,recovered=? WHERE id=?",(now,outcome,code,new_count,attempt))
        for identity in participants:
            result="recovered" if identity in recovered_ids else ("no_match" if code in (0,1) and not action else outcome)
            db.execute("INSERT INTO hash_passes VALUES (?,?,?)",(identity,attempt,result))
    update_job(job["id"],pid=None)
    if action=="skip":
        restore.unlink(missing_ok=True)
    return outcome,"\n".join(error_tail)


def run_job(job):
    identity=job["id"]
    words=json.loads(job["wordlists"])
    ids=json.loads(job["hash_ids"])
    folder=config.DATA/"runs"/identity
    folder.mkdir(exist_ok=True,mode=0o700)
    hashes_file=folder/"hashes.22000"
    # Preserve this snapshot for Hashcat restore; imports cannot modify it.
    if not hashes_file.exists():
        with connect() as db:
            hashes=[r["hash"] for r in db.execute("SELECT id,hash FROM hashes") if r["id"] in ids]
        hashes_file.write_text("\n".join(hashes)+"\n")
    sync_results(hashes_file,identity)
    for index in range(job["next_index"],len(words)):
        with connect() as db:
            unresolved={r[0] for r in db.execute("SELECT id FROM hashes WHERE password_hex IS NULL")}
            row=db.execute("SELECT action,status FROM jobs WHERE id=?",(identity,)).fetchone()
        if row and (row[0]=="stop" or row[1]=="stopping"):
            update_job(identity,status="stopped",action=None,finished=time.time())
            return
        if shutdown.is_set() or (row and row[0]=="pause"):
            update_job(identity,status="paused",action=None)
            return
        if not unresolved.intersection(ids):
            break
        outcome,tail=run_pass(job,words[index],index,hashes_file)
        if outcome=="stopped":
            update_job(identity,status="stopped",action=None,finished=time.time())
            return
        if outcome=="paused":
            update_job(identity,status="paused",action=None)
            return
        if outcome=="failed":
            update_job(identity,status="failed",action=None,finished=time.time(),error=tail or "Ошибка Hashcat. Откройте журнал прохода.")
            return
        update_job(identity,next_index=index+1)
        if outcome=="skipped":
            update_job(identity,action=None)
    with connect(True) as db:
        known={r[0] for r in db.execute("SELECT id FROM hashes WHERE password_hex IS NOT NULL")}
        row=db.execute("SELECT action FROM jobs WHERE id=?",(identity,)).fetchone()
        action=row[0] if row else None
        if action=="pause" or shutdown.is_set():
            db.execute("UPDATE jobs SET status='paused',action=NULL WHERE id=?",(identity,))
        elif action=="stop":
            db.execute("UPDATE jobs SET status='stopped',action=NULL,finished=? WHERE id=?",(time.time(),identity))
        else:
            db.execute("UPDATE jobs SET status='completed',finished=?,action=NULL,progress=? WHERE id=?",(time.time(),json.dumps({"percent":100,"recovered":len(known.intersection(ids)),"target_count":len(ids)}),identity))


def reconcile():
    with connect(True) as db:
        jobs=list(db.execute("SELECT id,status FROM jobs WHERE status IN ('running','pausing','stopping')"))
        for job in jobs:
            if job['status']=='stopping':
                db.execute("UPDATE jobs SET status='stopped',pid=NULL,action=NULL,finished=? WHERE id=?",(time.time(),job['id']))
            else:
                db.execute("UPDATE jobs SET status='interrupted',pid=NULL,action=NULL,error=? WHERE id=?",("Worker был перезапущен. Продолжите задачу; сохранённый checkpoint будет использован, если доступен.",job['id']))
        unfinished=list(db.execute("SELECT id,participants FROM attempts WHERE finished IS NULL"))
        recovered={r[0] for r in db.execute("SELECT id FROM hashes WHERE password_hex IS NOT NULL")}
        for attempt in unfinished:
            db.execute("UPDATE attempts SET finished=?,outcome='interrupted' WHERE id=?",(time.time(),attempt['id']))
            for identity in json.loads(attempt['participants']):
                db.execute("INSERT OR IGNORE INTO hash_passes VALUES (?,?,?)",(identity,attempt['id'],'recovered' if identity in recovered else 'interrupted'))


def main():
    os.umask(0o077)
    init()
    lock=(config.DATA/"worker.lock").open("a+")
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    signal.signal(signal.SIGTERM,lambda *_:shutdown.set())
    signal.signal(signal.SIGINT,lambda *_:shutdown.set())
    reconcile()
    info={"hashcat":subprocess.run([config.HASHCAT,"--version"],capture_output=True,text=True,timeout=10).stdout.strip(),
          "converter":subprocess.run([config.CONVERTER,"--version"],capture_output=True,text=True,timeout=10).stdout.strip()}
    with connect(True) as db:
        db.execute("INSERT OR REPLACE INTO meta VALUES ('engine_info',?)",(json.dumps(info),))
    # Reconcile results imported from the previous local CLI work.
    with connect() as db:
        hashes=[r[0] for r in db.execute("SELECT hash FROM hashes")]
    if hashes:
        temporary=config.DATA/"tmp"/"sync.22000"
        temporary.write_text("\n".join(hashes)+"\n")
        try:
            sync_results(temporary)
        finally:
            temporary.unlink(missing_ok=True)
    while not shutdown.is_set():
        heartbeat()
        with connect(True) as db:
            row=db.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
            if row:
                db.execute("UPDATE jobs SET status='running',started=coalesce(started,?),heartbeat=? WHERE id=?",(time.time(),time.time(),row["id"]))
                job=dict(row)
            else:
                job=None
        if job:
            try:
                run_job(job)
            except Exception as exc:
                # System errors only; output containing results is never used here.
                if current_process is not None and current_process.poll() is None:
                    stop_process(current_process)
                    try:
                        current_process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        os.killpg(current_process.pid,signal.SIGKILL)
                        current_process.wait(timeout=5)
                with connect(True) as db:
                    unfinished=list(db.execute("SELECT id,participants FROM attempts WHERE job_id=? AND finished IS NULL",(job["id"],)))
                    for attempt in unfinished:
                        db.execute("UPDATE attempts SET finished=?,outcome='failed' WHERE id=?",(time.time(),attempt["id"]))
                        for participant in json.loads(attempt["participants"]):
                            db.execute("INSERT OR IGNORE INTO hash_passes VALUES (?,?,'failed')",(participant,attempt["id"]))
                update_job(job["id"],status="failed",finished=time.time(),pid=None,error=f"Ошибка worker: {type(exc).__name__}. Проверьте доступность файлов и журнал службы.")
        else:
            shutdown.wait(1)
    with connect(True) as db:
        db.execute("DELETE FROM meta WHERE key='worker_heartbeat'")


if __name__=="__main__":
    main()
