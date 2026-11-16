"""S3 native container evidence using immutable owner fixtures; never patch sources."""
import importlib.util
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INTEGRATION = ROOT / '.sources/lakehouse-integration'
PIN = 'e8379a528bf413c05aad49e56bc8cd507b5e077a'
SAIL_PIN = 'e96e068f926b8fecb3939e953389685ee4780032'
assert subprocess.check_output(['git', '-C', str(INTEGRATION), 'rev-parse', 'HEAD'], text=True).strip() == PIN
sys.path.extend([str(INTEGRATION/'evaluation/authz'), str(INTEGRATION/'evaluation/idp'), str(INTEGRATION/'integration')])
import common
common.OUT = ROOT/'reports/s3'
common.WORK = ROOT/'.runtime/s3'
from common import run, save, secret, wait, write, decode, WORK, NETWORK
from fixture import container, database, leaf, BACKEND_NETWORK, transport
from rauthy import Rauthy

ARCH = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
assert ARCH == os.environ['INTEGRATION_ARCH']
SAIL = INTEGRATION/'.sources/sail-ubi'
PYTHON = INTEGRATION/'.sources/sail-venv/bin/python'
CASES = ('valid', 'missing', 'wrong_audience', 'denied_user', 'wrong_key', 'expiry_before',
         'expired', 'expiry_fresh', 'tls_plaintext', 'backend_isolation', 'paced_stream', 'revoked_user')
RESULTS = dict(architecture=ARCH, machine=platform.machine(), run=os.environ.get('RUN_URL'),
               integration=PIN, sail=SAIL_PIN, source=run('git', 'rev-parse', 'HEAD'), cases={name: dict(status='BLOCKED', reason='Runtime prerequisites not completed') for name in CASES})


def case(name, fn):
    try:
        value = fn()
        RESULTS['cases'][name] = dict(status='PASS', evidence=value)
    except Exception as error:
        RESULTS['cases'][name] = dict(status='FAIL', error=str(error))
    save('results.json', RESULTS)
    print(json.dumps(dict(case=name, **RESULTS['cases'][name])), flush=True)


def build():
    import build as owner
    results = {}
    for repo in ('postgresql-lakekeeper-ubi', 'sail-ubi'):
        results[repo] = owner.build(repo, owner.PINS[repo], ARCH)
        assert results[repo]['status'] == 'pass', results[repo]
        save('builds.json', results)
    from rauthy import build as rauthy_build
    results['rauthy-ubi'] = rauthy_build(ARCH, owner)
    save('builds.json', results)
    assert run('git', '-C', SAIL, 'rev-parse', 'HEAD') == SAIL_PIN


def token_file(name, token):
    path = WORK/(name+'.jwt')
    write(path, secret(token))
    return path


def probe(name, token, code):
    result = run(PYTHON, ROOT/'evaluation/s3/client.py', 'sail:50051', token, code,
                 env=dict(os.environ, GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=str(WORK/'ca/ca.pem')))
    return json.loads(result)


def evaluate():
    save('plan-inventory.json', json.loads(run(PYTHON, ROOT/'evaluation/s3/plan_inventory.py')))
    ca = common.pki()
    run('docker', 'network', 'create', '--internal', NETWORK)
    run('docker', 'network', 'create', '--internal', BACKEND_NETWORK)
    database(ca)  # Owner PostgreSQL TLS setup, including Rauthy's database.
    provider = Rauthy('rauthy', ca)
    provider.start(ARCH)
    service_key = secret()
    write(WORK/'cedar-key', service_key)
    run('sudo', 'chown', 'root:root', WORK/'cedar-key')
    run('sudo', 'chmod', '0440', WORK/'cedar-key')
    restricted = ['--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                  '--pids-limit=256', '--memory=512m', '--cpus=2']
    container('cedar', 'localhost/authz-serve:s3', ['serve'],
              env=dict(AUTHZ_TLS_CERT='/tls/cert.pem', AUTHZ_TLS_KEY='/tls/key.pem', AUTHZ_KEY_FILE='/run/key'),
              mounts=[(leaf('cedar'), '/tls'), (WORK/'cedar-key', '/run/key')], extra=restricted)
    headers = {'Authorization': 'Bearer '+service_key}
    wait(lambda: provider.http.request('POST', 'https://cedar:8443/decide', headers=headers, json=[]).status_code == 200)
    tokens = {name: provider.token(name) for name in ('lakekeeper', 'operator', 'expiry', 'wrong-audience')}
    for name in ('lakekeeper', 'expiry'):
        provider.http.request('POST', 'https://cedar:8443/mutate', headers=headers, json=dict(
            op='grant', remove=False, grant=dict(subject=dict(kind='User', id='oidc~'+decode(tokens[name])[1]['sub']),
                                               resource=dict(kind='Server', id='sail'), access='owner'))).raise_for_status()
    write(WORK/'sail.json', json.dumps(dict(bind='127.0.0.1', port=50052, allow_unauthenticated_remote=False)))
    (WORK/'sail.json').chmod(0o644)
    container('sail', 'localhost/sail-ubi:integration', mounts=[(WORK/'sail.json', '/etc/sail/config.json')],
              extra=[a if a != '--memory=512m' else '--memory=2g' for a in restricted] + ['--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777'])
    container('gateway', 'localhost/authz-serve:s3', ['sail-gateway'],
              env=dict(AUTHZ_TLS_CERT='/tls/cert.pem', AUTHZ_TLS_KEY='/tls/key.pem', AUTHZ_KEY_FILE='/run/key',
                       AUTHZ_CA_FILE='/ca.pem', AUTHZ_ENDPOINT='https://cedar:8443',
                       SAIL_JWKS_URL=provider.discovery['jwks_uri'], SAIL_ISSUER=provider.issuer,
                       SAIL_AUDIENCE='lakekeeper,expiry,operator', AUTHZ_LISTEN='0.0.0.0:50051'),
              mounts=[(leaf('sail'), '/tls'), (ca, '/ca.pem'), (WORK/'cedar-key', '/run/key')],
              extra=restricted, network='container:sail')
    wait(lambda: transport('sail', 50051, ca))
    wait(lambda: run('docker', 'exec', 'sail', '/usr/bin/python3.12', '-c',
                     "import socket; socket.create_connection(('127.0.0.1',50052),timeout=1).close(); print('ready')"))
    paths = {name: token_file(name, token) for name, token in tokens.items()}
    case('valid', lambda: probe('valid', paths['lakekeeper'], 'OK'))
    case('missing', lambda: probe('missing', '-', 'UNAUTHENTICATED'))
    case('wrong_audience', lambda: probe('aud', paths['wrong-audience'], 'UNAUTHENTICATED'))
    case('denied_user', lambda: probe('denied', paths['operator'], 'PERMISSION_DENIED'))
    provider.human_token = tokens['lakekeeper']  # bad_token uses only this token's header/claims.
    from catalog import bad_token
    wrong = token_file('wrong-key', bad_token(provider, 'different_key'))
    case('wrong_key', lambda: probe('key', wrong, 'UNAUTHENTICATED'))
    case('expiry_before', lambda: probe('expiry-before', paths['expiry'], 'OK'))
    deadline = decode(tokens['expiry'])[1]['exp'] + 1
    while time.time() <= deadline:
        time.sleep(min(1, deadline-time.time()+0.1))
    case('expired', lambda: probe('expired', paths['expiry'], 'UNAUTHENTICATED'))
    paths['expiry'] = token_file('expiry-fresh', provider.token('expiry'))
    case('expiry_fresh', lambda: probe('expiry-fresh', paths['expiry'], 'OK'))
    case('tls_plaintext', lambda: transport('sail', 50051, ca))

    def isolation():
        obj = json.loads(run('docker', 'inspect', 'sail'))[0]
        address = obj['NetworkSettings']['Networks'][NETWORK]['IPAddress']
        script = ('import socket,json; out={}; '
                  f'\nfor port in (50051,50052):\n s=socket.socket(); s.settimeout(3); out[port]=s.connect_ex(({address!r},port)); s.close()'
                  '\nassert out[50051]==0 and out[50052]!=0, out\nprint(json.dumps(out))')
        output = run('docker', 'run', '--rm', '--label', 'datopsis.idp-bakeoff=true', '--network', NETWORK,
                     '--entrypoint', '/usr/bin/python3.12', 'localhost/sail-ubi:integration', '-c', script)
        return json.loads(output)
    case('backend_isolation', isolation)
    case('paced_stream', lambda: stream(ca, paths['lakekeeper']))
    # Revoke the authenticated principal. No token or identity header changes.
    provider.http.request('POST', 'https://cedar:8443/mutate', headers=headers, json=dict(
        op='grant', remove=True, grant=dict(subject=dict(kind='User', id='oidc~'+decode(tokens['lakekeeper'])[1]['sub']),
                                          resource=dict(kind='Server', id='sail'), access='owner'))).raise_for_status()
    case('revoked_user', lambda: probe('revoked', paths['lakekeeper'], 'PERMISSION_DENIED'))
    assert all(c['status'] == 'PASS' for c in RESULTS['cases'].values()), 'S3 failures; see results.json'


def stream(ca, path):
    # Unmodified owner-paced client and passive control-frame observer.
    obj = json.loads(run('docker', 'inspect', 'sail'))[0]
    trace = common.OUT/'paced-h2.jsonl'
    with trace.open('w') as output:
        observer = subprocess.Popen(['sudo', 'nsenter', '-t', str(obj['State']['Pid']), '-n',
                                     '/usr/bin/python3', '-u', str(SAIL/'tests/h2_trace.py')], stdout=output, stderr=subprocess.STDOUT)
        pid = None
        try:
            def ready():
                nonlocal pid
                lines = trace.read_text().splitlines()
                if lines:
                    event = json.loads(lines[0]); assert event['event'] == 'ready'
                    pid = event['pid']; return True
            wait(ready, 10)
            result = subprocess.run([str(PYTHON), str(SAIL/'tests/stream_probe.py'),
                                     'sc://sail:50051/;use_ssl=true;token='+path.read_text().strip(),
                                     '1000000', '5', '16', 'none'], capture_output=True, text=True, timeout=240,
                                    env=dict(os.environ, GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=str(ca)))
            events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
            save('paced-client.json', dict(returncode=result.returncode, events=events,
                                           log=result.stdout+result.stderr))
        finally:
            if pid: run('sudo', 'kill', '-TERM', str(pid))
            assert observer.wait(timeout=10) == 0, 'Invalid packet capture'
    frames = [json.loads(line) for line in trace.read_text().splitlines()]
    logs = run('docker', 'logs', 'gateway')
    stalls = [json.loads(line) for line in logs.splitlines() if line.startswith('{') and 'downstream_backpressure' in line]
    save('paced-backpressure.json', stalls)
    pairs = []
    for ping in frames:
        if ping.get('frame') == 'PING' and not ping['ack'] and ping['ports'][0] == 50052 and ping['seconds'] >= 50:
            ack = next(e for e in frames if e.get('frame') == 'PING' and e['ack'] and e['opaque'] == ping['opaque']
                       and e['ports'] == ping['ports'][::-1] and e['seconds'] >= ping['seconds'])
            pairs.append(dict(ping_seconds=ping['seconds'], ack_ms=(ack['seconds']-ping['seconds'])*1000,
                              during_downstream_wait=any(s['start_unix'] <= ping['unix_time'] <= s['start_unix']+s['duration_seconds'] for s in stalls)))
    complete = [e for e in events if e['event'] == 'workload_complete']
    if result.returncode == 0:
        assert pairs and all(p['ack_ms'] < 10000 for p in pairs), pairs
        assert any(p['during_downstream_wait'] for p in pairs), ('No PING observed during downstream wait', pairs, stalls)
        calls = [e for e in events if e['event'] == 'rpc_start']
        done = [e for e in events if e['event'] == 'rpc_done']
        assert len(calls) == len(done) == 1 and calls[0]['method'].endswith('/ExecutePlan'), (calls, done)
        assert done[0]['code'] == 'OK' and done[0]['seconds'] - calls[0]['seconds'] >= 70, done
        assert len(complete) == 1
        end = complete[0]
        assert (end['rows'], end['unique_ids'], end['payload_hashes_verified'], end['total']) == (1000000,1000000,1000000,499999500000)
        assert end['elapsed'] >= 75 and end['batches'] >= 16
        return dict(outcome='COMPLETE', result=end, pings=pairs)
    # Preserve the exact historical failure oracle; other errors fail S3.
    sys.path.insert(0, str(SAIL/'tests'))
    from stream_contract import RESET_DETAILS
    errors = [e for e in events if e['event'] == 'workload_error']
    assert len(errors) == 1 and RESET_DETAILS in errors[0]['details'] and 70 <= errors[0]['elapsed'] <= 90
    calls = [e for e in events if e['event'] == 'rpc_start']
    done = [e for e in events if e['event'] == 'rpc_done']
    assert len(calls) == len(done) == 1 and calls[0]['method'].endswith('/ExecutePlan'), (calls, done)
    assert (done[0]['code'], done[0]['code_number'], done[0]['details']) == ('INTERNAL', 13, RESET_DETAILS), done
    raise AssertionError(dict(outcome='HISTORICAL_RESET', result=errors[0], pings=pairs))


if __name__ == '__main__':
    if sys.argv[1:] == ['initialize']:
        save('results.json', RESULTS)
    elif sys.argv[1:] == ['build']:
        build()
    elif sys.argv[1:] == ['cleanup']:
        common.cleanup()
        if run('docker', 'network', 'ls', '-q', '--filter', 'name=^authz-backend$'):
            run('docker', 'network', 'rm', BACKEND_NETWORK)
    else:
        save('results.json', RESULTS)
        evaluate()
