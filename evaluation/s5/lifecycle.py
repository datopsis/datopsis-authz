#!/usr/bin/env python3
"""S5 trusted Docker supervisor. Run on the host; no Docker socket in Sail.

stdin is private JSON; JWTs never appear in argv, env, or output. The deployment
config and runtime root are administrator-owned. This is evaluation tooling.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(os.environ['S5_RUNTIME'])
CONFIG = Path(os.environ['S5_CONFIG'])
PYTHON = '/usr/bin/python3.12'
NAME = re.compile(r's5-[0-9a-f]{32}\Z')


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, check=True, **kwargs)


def valid(name):
    assert NAME.fullmatch(name), 'Invalid instance name'
    return name


def stop(name):
    started = time.monotonic()
    valid(name)
    inspected = subprocess.run(['docker', 'inspect', name], capture_output=True)
    if inspected.returncode == 0:
        obj = json.loads(inspected.stdout)[0]
        assert obj['Config']['Labels'].get('datopsis.s5') == str(ROOT)
        run('docker', 'rm', '-f', name)
    shutil.rmtree(ROOT/name, ignore_errors=False) if (ROOT/name).exists() else None
    event(dict(event='stop', name=name, seconds=time.monotonic()-started))


def event(value):
    with (ROOT.parent/'lifecycle.jsonl').open('a') as f:
        f.write(json.dumps(value)+'\n')


def ensure(name, token):
    assert token and '\n' not in token
    config = json.loads(CONFIG.read_text())
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    assert ROOT.stat().st_mode & 0o777 == 0o700
    if name:
        valid(name)
        obj = subprocess.run(['docker', 'inspect', name], capture_output=True)
        if obj.returncode == 0 and json.loads(obj.stdout)[0]['State']['Running']:
            # Directory bind observes atomic refresh; no partially written JWT.
            # The trusted gateway serializes updates and verifies the subject.
            path = ROOT/name/'secrets'/'token'
            updated = path.with_name('next')
            updated.write_text(token)
            updated.chmod(0o400)
            os.chown(updated, 10001, 10001)
            updated.replace(path)
            return dict(name=name, reused=True)
        stop(name)
    name = 's5-' + uuid.uuid4().hex
    directory = ROOT/name
    directory.mkdir(mode=0o700)
    started = time.monotonic()
    try:
        secrets_dir = directory/'secrets'
        secrets_dir.mkdir(mode=0o500)
        os.chown(secrets_dir, 10001, 10001)
        token_file = secrets_dir/'token'
        token_file.write_text(token)
        token_file.chmod(0o400)
        os.chown(token_file, 10001, 10001)
        server = directory/'config.json'
        server.write_text(json.dumps(dict(bind='127.0.0.1', port=50052, allow_unauthenticated_remote=False)))
        server.chmod(0o444)
        env = directory/'env'
        env.write_text(''.join(f'{k}={v}\n' for k, v in config['env'].items()))
        env.chmod(0o600)
        run('docker', 'run', '-d', '--name', name, '--label', 'datopsis.idp-bakeoff=true',
            '--label', 'datopsis.s5='+str(ROOT), '--network', config['network'],
            '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--pids-limit=128', '--memory='+config.get('memory', '512m'),
            '--memory-swap='+config.get('memory', '512m'), '--cpus='+config.get('cpus', '1'),
            '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=128m,uid=10001,gid=10001,mode=0700',
            '--tmpfs', '/var/lib/sail:rw,noexec,nosuid,nodev,size=128m,uid=10001,gid=10001,mode=0700',
            '--env-file', env, '-v', f'{secrets_dir}:/run/user-catalog:ro',
            '-v', f'{server}:/etc/sail/config.json:ro', '-v', f'{config["ca"]}:/ca/ca.pem:ro',
            config['image'])
        deadline = time.monotonic()+60
        while time.monotonic() < deadline:
            result = subprocess.run(['docker', 'exec', name, PYTHON, '-c',
                "import socket; socket.create_connection(('127.0.0.1',50052),timeout=0.2).close()"], capture_output=True)
            if result.returncode == 0:
                value = dict(name=name, reused=False, ready_seconds=time.monotonic()-started)
                event(dict(event='ready', **value))
                return value
            time.sleep(0.02)
        raise RuntimeError('Sail readiness timeout')
    except BaseException:
        stop(name)
        raise


# Unbuffered duplex HTTP/2 transport inside this instance's private network ns.
# No listening TCP proxy or published port is created on the host or bridge.
RELAY = '''import os,socket,threading
s=socket.create_connection(('127.0.0.1',50052))
def upstream():
 try:
  while True:
   b=os.read(0,65536)
   if not b: break
   s.sendall(b)
 finally:
  s.shutdown(socket.SHUT_WR)
threading.Thread(target=upstream,daemon=True).start()
while True:
 b=s.recv(65536)
 if not b: break
 while b:
  n=os.write(1,b); b=b[n:]
'''

if __name__ == '__main__':
    if sys.argv[1:2] == ['relay']:
        name = valid(sys.argv[2])
        os.execvp('docker', ['docker', 'exec', '-i', name, PYTHON, '-u', '-c', RELAY])
    request = json.load(sys.stdin)
    if request['op'] == 'ensure':
        print(json.dumps(ensure(request.get('name'), request['token'])))
    elif request['op'] == 'stop':
        stop(request['name'])
        print('{}')
    else:
        raise ValueError('Unsupported lifecycle operation')
