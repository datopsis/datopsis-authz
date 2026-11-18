"""S5 native runtime measurements. No mocks qualify as measurements or isolation."""
import json
import os
import platform
import statistics
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT/'.sources/lakehouse-integration'
PIN = 'e8379a528bf413c05aad49e56bc8cd507b5e077a'
assert subprocess.check_output(['git', '-C', str(SOURCE), 'rev-parse', 'HEAD'], text=True).strip() == PIN
sys.path.extend([str(ROOT/'evaluation/s1'), str(SOURCE/'evaluation/authz'), str(SOURCE/'evaluation/idp')])
import common
common.WORK = ROOT/'.runtime/s5'
common.OUT = ROOT/'reports/s5'
from common import WORK, run, save, secret, write, wait, decode
from s1_fixture import setup, grant
from rauthy import Rauthy

ARCH = {'aarch64':'arm64', 'x86_64':'amd64'}[platform.machine()]
assert ARCH == os.environ['INTEGRATION_ARCH']
HELPER = ROOT/'evaluation/s5/lifecycle.py'
PYTHON = SOURCE/'.sources/sail-venv/bin/python'
RUNTIME = WORK/'instances'
RESULTS = dict(architecture=ARCH, machine=platform.machine(), source=run('git', 'rev-parse', 'HEAD'),
    run=os.environ.get('RUN_URL'), sail='e96e068f926b8fecb3939e953389685ee4780032',
    rauthy='1e114b84b01988bf15306b110b040378878488d3', cases={},
    host=dict(logical_cpus=os.cpu_count(), kernel=platform.release(),
        mem_total_bytes=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:')))*1024))


def record(name, fn, required=False):
    try:
        value = fn()
        RESULTS['cases'][name] = dict(status='PASS', evidence=value)
    except Exception as exc:
        RESULTS['cases'][name] = dict(status='FAIL', error=str(exc))
        save('results.json', RESULTS)
        if required:
            raise
    save('results.json', RESULTS)
    print(json.dumps(dict(case=name, **RESULTS['cases'][name])), flush=True)
    return RESULTS['cases'][name]


def lifecycle(request):
    return json.loads(run('sudo', '-E', HELPER, input=json.dumps(request)))


def names():
    return run('docker', 'ps', '-aq', '--filter', 'label=datopsis.s5='+str(RUNTIME)).split()


def objects():
    ids = names()
    return json.loads(run('docker', 'inspect', *ids)) if ids else []


def stop_all():
    for obj in objects():
        lifecycle(dict(op='stop', name=obj['Name'].lstrip('/')))


def client(token, sql='SELECT 42 AS answer', session=None, expected=None):
    return json.loads(run(PYTHON, ROOT/'evaluation/s5/client.py', input=json.dumps(dict(
        token=token, sql=sql, session=session, expected=expected)), env=dict(os.environ,
        GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=str(WORK/'ca/ca.pem'))))


def ok(*args, **kwargs):
    result = client(*args, **kwargs)
    assert result['status'] == 'OK', result
    return result


def denied(token, sql, session=None):
    result = client(token, sql, session)
    assert result['status'] in ('INTERNAL', 'UNKNOWN', 'INVALID_ARGUMENT'), result
    text = result.get('detail', '')
    assert any(s in text for s in ('403 Forbidden', '404 Not Found', 'CannotSee', 'does not exist', 'not found')), result
    assert not any(s in text for s in ('401 Unauthorized', 'Connection refused', 'TLS', 'Syntax error')), result
    return result


def memory():
    rows = []
    for obj in objects():
        pid = obj['State']['Pid']
        if not pid:
            continue
        # Sail wheel entrypoint is PID 1 (verified by cmdline); record actual RSS.
        status = run('sudo', 'cat', f'/proc/{pid}/status')
        rss = next(int(line.split()[1])*1024 for line in status.splitlines() if line.startswith('VmRSS:'))
        cgroup = run('sudo', 'cat', f'/proc/{pid}/cgroup').strip().split('::', 1)[1]
        current = int(run('sudo', 'cat', '/sys/fs/cgroup'+cgroup+'/memory.current'))
        peak = int(run('sudo', 'cat', '/sys/fs/cgroup'+cgroup+'/memory.peak'))
        rows.append(dict(name=obj['Name'], pid=pid, rss_bytes=rss, cgroup_bytes=current, cgroup_peak_bytes=peak,
                         cmdline=run('sudo', 'cat', f'/proc/{pid}/comm')))
    gateway_rss = None
    if (WORK/'gateway.actual-pid').exists():
        gateway_pid = int((WORK/'gateway.actual-pid').read_text())
        status = run('sudo','cat',f'/proc/{gateway_pid}/status')
        gateway_rss = next(int(line.split()[1])*1024 for line in status.splitlines() if line.startswith('VmRSS:'))
    return dict(instances=rows, total_rss_bytes=sum(r['rss_bytes'] for r in rows),
                total_cgroup_bytes=sum(r['cgroup_bytes'] for r in rows), gateway_rss_bytes=gateway_rss)


def launch_gateway(catalog, key):
    from fixture import leaf
    tls = leaf('sail')
    env = dict(os.environ, AUTHZ_TLS_CERT=str(tls/'cert.pem'), AUTHZ_TLS_KEY=str(tls/'key.pem'),
        AUTHZ_KEY_FILE=str(WORK/'cedar-key'), AUTHZ_CA_FILE=str(catalog.provider.ca),
        AUTHZ_ENDPOINT='https://cedar:8443', SAIL_JWKS_URL=catalog.provider.discovery['jwks_uri'],
        SAIL_ISSUER=catalog.provider.issuer, SAIL_AUDIENCE='lakekeeper', AUTHZ_LISTEN='127.0.0.1:50051',
        SAIL_LIFECYCLE_HELPER=str(HELPER), SAIL_IDLE_SECONDS='15', TOKIO_WORKER_THREADS='2')
    config = dict(image='localhost/sail-ubi:integration', network=common.NETWORK,
        ca=str(catalog.provider.ca), memory='512m', cpus='1', env={
            'SAIL_CATALOG__LIST': '[{type="iceberg-rest", name="bakeoff", uri="'+catalog.base+'/catalog", warehouse="bakeoff", bearer_access_token_file="/run/user-catalog/token"}]',
            'SSL_CERT_FILE':'/ca/ca.pem', 'AWS_ACCESS_KEY_ID':catalog.storage.access,
            'AWS_SECRET_ACCESS_KEY':catalog.storage.password, 'AWS_ENDPOINT':catalog.storage.endpoint,
            'AWS_REGION':'local', 'AWS_ALLOW_HTTP':'false', 'AWS_VIRTUAL_HOSTED_STYLE_REQUEST':'false',
            'TOKIO_WORKER_THREADS':'2'})
    write(WORK/'supervisor.json', config)
    run('sudo', 'chown', 'root:root', WORK/'supervisor.json')
    os.environ.update(S5_RUNTIME=str(RUNTIME), S5_CONFIG=str(WORK/'supervisor.json'))
    env.update(S5_RUNTIME=str(RUNTIME), S5_CONFIG=str(WORK/'supervisor.json'))
    run('sudo', 'mkdir', '-m', '0700', '-p', RUNTIME)
    run('sudo', 'tee', '/etc/hosts', input=Path('/etc/hosts').read_text()+'127.0.0.1 sail # idp-bakeoff\n')
    log = (common.OUT/'gateway.log').open('w')
    # Direct root process: test fixture is already a Docker administrator.
    proc = subprocess.Popen(['sudo', '-E', str(ROOT/'target/debug/authz-serve'), 'sail-gateway'], env=env, stdout=log, stderr=log)
    write(WORK/'gateway.pid', str(proc.pid))
    import socket
    def ready():
        with socket.create_connection(('127.0.0.1', 50051), timeout=1):
            return True
    wait(ready)
    event = next(json.loads(line) for line in (common.OUT/'gateway.log').read_text().splitlines() if 'gateway_ready' in line)
    write(WORK/'gateway.actual-pid', str(event['pid']))
    return proc, log, config


def single(token):
    started = time.monotonic()
    instance = lifecycle(dict(op='ensure', token=token))
    elapsed = time.monotonic()-started
    idle = memory()
    name = instance['name']
    # Representative finite SQL aggregate scans a million generated rows;
    # polling captures current RSS; cgroup memory.peak catches between polls.
    samples = []
    done = threading.Event()
    def sample():
        while not done.is_set():
            samples.append(memory())
            done.wait(0.05)
    thread = threading.Thread(target=sample)
    thread.start()
    # Direct namespace transport to separate engine cost from gateway.
    tunnel = subprocess.Popen(['sudo', '-E', 'socat',
        'TCP4-LISTEN:50053,bind=127.0.0.1,reuseaddr,fork',
        'EXEC:'+str(HELPER)+' relay '+name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def direct(sql):
        value = json.loads(run(PYTHON, ROOT/'evaluation/s5/client.py', input=json.dumps(dict(
            token='', sql=sql, endpoint='127.0.0.1:50053', tls=False))))
        assert value['status']=='OK', value
        return value
    try:
        import socket
        def ready():
            with socket.create_connection(('127.0.0.1',50053),timeout=1): return True
        wait(ready,10)
        first = direct('SELECT 42 AS answer')
        later = [direct('SELECT 42 AS answer') for _ in range(5)]
        result = direct('SELECT sum(id) AS total, count(DISTINCT id) AS distinct_ids FROM range(1000000)')
        assert result['rows']==[{'total':499999500000,'distinct_ids':1000000}],result
    finally:
        done.set(); thread.join()
        run('sudo','kill','-TERM',str(tunnel.pid))
        tunnel.wait(timeout=10)
    under = memory()
    stopped = time.monotonic()
    lifecycle(dict(op='stop', name=name))
    return dict(ready=instance, cold_to_ready_seconds=elapsed, idle=idle, after_query=under,
        peak_sampled_rss_bytes=max(s['total_rss_bytes'] for s in samples), query=result, direct_first=first, direct_later=later,
        stop_seconds=time.monotonic()-stopped)


def evaluate():
    passwords = {}
    original = Rauthy.config_rauthy
    def provision(self):
        original(self)
        path = self.path/'bootstrap/users.json'
        users = json.loads(path.read_text())
        for i in range(20):
            email = f'scale-{i:02}@idp.test'
            passwords[email] = secret()
            users.append({**users[0], 'email':email, 'given_name':f'Scale{i}',
                          'password':{'Plain':passwords[email]}})
        write(path, users)
    Rauthy.config_rauthy = provision
    catalog, operator, key = setup(ARCH, record)
    RESULTS['provenance'] = {}
    for image in ('localhost/sail-ubi:integration','localhost/rauthy-ubi:authz'):
        obj = json.loads(run('docker','image','inspect',image))[0]
        assert obj['Architecture']==ARCH
        revision = RESULTS['sail'] if 'sail-ubi' in image else RESULTS['rauthy']
        assert obj['Config']['Labels']['org.opencontainers.image.revision']==revision
        RESULTS['provenance'][image] = dict(image_id=obj['Id'], architecture=obj['Architecture'],labels=obj['Config']['Labels'])
    provider = catalog.provider
    users = [secret(provider.human()['access_token']),
             secret(provider.human(email='bob@idp.test', password=provider.bob_password)['access_token'])]
    scale = [secret(provider.human(email=email, password=password)['access_token']) for email, password in passwords.items()]
    admin = catalog.pyiceberg(operator)
    import pyarrow as pa
    for label in ('alice', 'bob'):
        admin.create_namespace(label)
        for table in ('sample', 'sibling'):
            t = admin.create_table(label+'.'+table, schema=pa.schema([pa.field('id', pa.int64())]))
            t.append(pa.Table.from_pylist([{'id':11 if label == 'alice' else 22}]))
    for token, label in zip(users, ('alice', 'bob')):
        identity = 'user:oidc~'+decode(token)[1]['sub']
        namespace = 'namespace:'+admin.load_namespace_properties(label)['namespace_id']
        grant(catalog, key, identity, 'select', namespace)
    headers = {'Authorization':'Bearer '+key}
    for token in users+scale:
        provider.http.request('POST', 'https://cedar:8443/mutate', headers=headers, json=dict(op='grant',
            remove=False, grant=dict(subject=dict(kind='User', id='oidc~'+decode(token)[1]['sub']),
            resource=dict(kind='Server', id='sail'), access='owner'))).raise_for_status()
    proc, log, config = launch_gateway(catalog, key)
    try:
        def admission():
            missing = client('')
            machine = client(provider.token('lakekeeper'))
            assert missing['status']=='UNAUTHENTICATED' and machine['status']=='PERMISSION_DENIED',(missing,machine)
            assert not names()
            return dict(missing=missing,denied_machine=machine,no_instances=True)
        record('admission_before_start',admission)
        record('single', lambda: single(users[0]))
        stop_all()
        def isolation():
            result = {}
            session = str(uuid.uuid4())
            for index, (token, label) in enumerate(zip(users, ('alice','bob'))):
                other = 'bob' if label == 'alice' else 'alice'
                first = ok(token, 'SELECT 42 AS answer', session, [{'answer':42}])
                read = ok(token, f'SELECT * FROM bakeoff.{label}.sample', session, [{'id':11 if index == 0 else 22}])
                later = [ok(token, 'SELECT 42 AS answer', session, [{'answer':42}]) for _ in range(5)]
                foreign = denied(token, f'SELECT * FROM bakeoff.{other}.sample', session)
                writes = [denied(token, sql, session) for sql in (
                    f'INSERT INTO bakeoff.{label}.sample VALUES (99)',
                    f'UPDATE bakeoff.{label}.sample SET id=99 WHERE id>0',
                    f'DELETE FROM bakeoff.{label}.sample WHERE id>0',
                    f'DROP TABLE bakeoff.{label}.sample',
                    f'CREATE TABLE bakeoff.{label}.forbidden (id BIGINT) USING iceberg')]
                # Namespace grant inheritance includes a newly created table.
                t = admin.create_table(label+'.later', schema=pa.schema([pa.field('id',pa.int64())]))
                t.append(pa.Table.from_pylist([{'id':33}]))
                inherited = ok(token, f'SELECT * FROM bakeoff.{label}.later', session, [{'id':33}])
                # Replace namespace with a single table grant; new session avoids
                # treating Sail's metadata cache as a fresh catalog permission check.
                identity = 'user:oidc~'+decode(token)[1]['sub']
                namespace = 'namespace:'+admin.load_namespace_properties(label)['namespace_id']
                table_id = str(admin.load_table(label+'.sample').metadata.table_uuid)
                grant(catalog,key,identity,'select',namespace,True)
                grant(catalog,key,identity,'select',f'lakekeeper_table:{catalog.warehouse_id}/{table_id}')
                one = ok(token, f'SELECT * FROM bakeoff.{label}.sample', expected=[{'id':11 if index == 0 else 22}])
                sibling = denied(token, f'SELECT * FROM bakeoff.{label}.sibling')
                result[label] = dict(first=first, read=read, later=later, foreign=foreign, writes=writes,
                    namespace_inheritance=inherited, single_table=one, sibling=sibling)
            # Both users intentionally used exactly the same session_id.
            result['same_session_id'] = True
            return result
        record('per_user_C1_C2', isolation)
        record('security', lambda: (ok(users[0]),ok(users[1]),security())[-1])
        def idle():
            wait(lambda: not names(), 60)
            assert run('sudo', 'find', RUNTIME, '-type', 'f') == ''
            return dict(timeout_seconds=15, no_containers=True, no_token_files=True)
        record('idle_cleanup', idle)
        record('crash', lambda: crash_check(users))
        record('idle_after_crash', idle)
        def coalesced():
            before=len(run('sudo','cat',WORK/'lifecycle.jsonl').splitlines())
            jobs=[dict(token=users[0],sql='SELECT 42 AS answer',expected=[{'answer':42}]) for _ in range(5)]
            values=json.loads(run(PYTHON,ROOT/'evaluation/s5/client.py',input=json.dumps(dict(jobs=jobs)),
                env=dict(os.environ,GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=str(provider.ca))))
            events=[json.loads(line) for line in run('sudo','cat',WORK/'lifecycle.jsonl').splitlines()[before:]]
            starts=sum(e['event']=='ready' for e in events)
            assert all(v['status']=='OK' for v in values) and len(names())==starts==1,(values,starts,names())
            return dict(results=values,instances_created=starts)
        record('same_user_concurrent_start',coalesced)
        record('idle_after_coalesced',idle)
        record('active_stream_lease',lambda: active_stream(users[0]))
        record('idle_after_active_stream',idle)
        for n in (1,5,20):
            def scale_run(n=n):
                event_count = len(run('sudo','cat',WORK/'lifecycle.jsonl').splitlines())
                jobs = [dict(token=token,sql='SELECT 42 AS answer',expected=[{'answer':42}]) for token in scale[:n]]
                values = json.loads(run(PYTHON, ROOT/'evaluation/s5/client.py', input=json.dumps(dict(jobs=jobs)),
                    env=dict(os.environ,GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=str(provider.ca))))
                measured = memory()
                events = [json.loads(line) for line in run('sudo','cat',WORK/'lifecycle.jsonl').splitlines()[event_count:]]
                ready = sorted(e['ready_seconds'] for e in events if e['event']=='ready')
                times = sorted(v['seconds'] for v in values)
                evidence = dict(n=n, results=values, memory=measured, first_query_seconds=times, ready_seconds=ready,
                    min_seconds=min(times), median_seconds=statistics.median(times), max_seconds=max(times),
                    failures=sum(v['status']!='OK' for v in values))
                save(f'scale-{n}.json',evidence)
                assert evidence['failures']==0 and len(measured['instances'])==n and len(ready)==n, evidence
                return evidence
            record(f'scale_{n}',scale_run)
            record(f'idle_after_{n}',idle)
        record('resource_limits',lambda: limits(config,users[0]))
    finally:
        # Stop the exact launched gateway, then reap its supervised containers.
        run('sudo','kill','-TERM',str(proc.pid))
        proc.wait(timeout=15)
        (WORK/'gateway.pid').unlink(missing_ok=True)
        log.close()
        stop_all()
    assert all(c['status']=='PASS' for c in RESULTS['cases'].values()), 'S5 incomplete; see results.json'


def active_stream(token):
    # Unmodified pinned workload; construct its argv inside Python so the JWT
    # is never exposed in operating-system process arguments.
    path=WORK/'stream-token'
    write(path,token)
    wrapper = ("import os,sys,runpy; from pathlib import Path; "
        "sys.argv=[os.environ['S5_PROBE'], 'sc://sail:50051/;use_ssl=true;token='+Path(os.environ['S5_STREAM_TOKEN']).read_text(), "
        "'1000000','5','16','none']; runpy.run_path(sys.argv[0],run_name='__main__')")
    probe=SOURCE/'.sources/sail-ubi/tests/stream_probe.py'
    with (common.OUT/'active-stream.log').open('w') as output:
        process=subprocess.Popen([str(PYTHON),'-c',wrapper],stdout=output,stderr=subprocess.STDOUT,
            env=dict(os.environ,S5_PROBE=str(probe),S5_STREAM_TOKEN=str(path),
                     GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=str(WORK/'ca/ca.pem')))
        try:
            wait(lambda: len(names())==1,30)
            instance=objects()[0]['Name']
            # Outlive the 15-second idle timeout while the client backpressures.
            time.sleep(25)
            assert process.poll() is None,'Paced stream exited early'
            assert [o['Name'] for o in objects()]==[instance],'Active instance was reaped'
            assert process.wait(timeout=220)==0,'Paced stream failed; see active-stream.log'
        finally:
            if process.poll() is None:
                process.terminate(); process.wait(timeout=10)
            path.unlink(missing_ok=True)
    events=[json.loads(line) for line in (common.OUT/'active-stream.log').read_text().splitlines() if line.startswith('{')]
    complete=[e for e in events if e['event']=='workload_complete']
    assert len(complete)==1
    end=complete[0]
    assert (end['rows'],end['unique_ids'],end['payload_hashes_verified'],end['total'])==(1000000,1000000,1000000,499999500000),end
    assert end['elapsed']>=75
    calls=[e for e in events if e['event']=='rpc_start']
    done=[e for e in events if e['event']=='rpc_done']
    assert len(calls)==len(done)==1 and calls[0]['method'].endswith('/ExecutePlan') and done[0]['code']=='OK'
    return dict(same_instance_after_seconds=25,idle_timeout_seconds=15,result=end,execute_plan_calls=1)


def security():
    objs = objects()
    assert len(objs)==2
    evidence=[]
    for obj in objs:
        name=obj['Name'].lstrip('/')
        other=next(o for o in objs if o['Id']!=obj['Id'])
        address=other['NetworkSettings']['Networks'][common.NETWORK]['IPAddress']
        script = ('import os,socket,json,stat; '
            'p="/run/user-catalog/token"; s=os.stat(p); '
            'assert stat.S_IMODE(s.st_mode)==0o400 and s.st_uid==os.getuid()==10001; '
            'assert len(open(p).read())>100; '
            'c=socket.socket(); c.settimeout(2); '
            f'code=c.connect_ex(({address!r},50052)); assert code!=0; '
            'assert not os.path.exists("/var/run/docker.sock"); '
            'print(json.dumps(dict(mode=oct(stat.S_IMODE(s.st_mode)),uid=s.st_uid,peer_connect_errno=code)))')
        result=json.loads(run('docker','exec',name,'/usr/bin/python3.12','-c',script))
        assert obj['HostConfig']['ReadonlyRootfs'] and obj['HostConfig']['CapDrop']==['ALL']
        assert obj['HostConfig']['PortBindings']=={}
        assert obj['HostConfig']['Memory']==512*1024*1024 and obj['HostConfig']['NanoCpus']==1000000000
        other_sources={m['Source'] for m in other['Mounts'] if m['Destination']!='/ca/ca.pem'}
        assert all(m['Source'] not in other_sources for m in obj['Mounts'] if m['Destination']!='/ca/ca.pem')
        assert all(m['RW'] is False for m in obj['Mounts'] if m['Type']=='bind')
        # Same local pathname, different per-instance tmpfs and mount namespaces.
        run('docker','exec',name,'/usr/bin/python3.12','-c',
            f'from pathlib import Path; p=Path("/tmp/{name}"); p.write_text("private")')
        run('docker','exec',other['Name'].lstrip('/'),'/usr/bin/python3.12','-c',
            f'import os; assert not os.path.exists("/tmp/{name}")')
        evidence.append(dict(instance=name,checks=result,memory_cap=obj['HostConfig']['Memory'],
                             cpu_cap=obj['HostConfig']['NanoCpus']/1e9,readonly_mounts=True,private_tmp=True))
    return evidence


def crash_check(users):
    ok(users[0])
    before=objects()[0]['Name'].lstrip('/')
    run('docker','kill',before)
    recovered=ok(users[0])
    objs=objects()
    assert len(objs)==1
    after=objs[0]['Name'].lstrip('/')
    assert before!=after
    assert subprocess.run(['sudo','test','-e',str(RUNTIME/before)]).returncode==1
    # User B's same session cannot see A's temporary view after either restart.
    session=str(uuid.uuid4())
    ok(users[0],'CREATE OR REPLACE TEMP VIEW private_marker AS SELECT 123 AS secret',session)
    b=client(users[1],'SELECT * FROM private_marker',session)
    assert b['status']!='OK' and 'private_marker' in b.get('detail',''), b
    return dict(recovered=recovered,different_instance=True,old_token_directory_absent=True,foreign_temp_view=b)


def limits(config,token):
    # Test real cgroup enforcement on an isolated extra instance. Do not kill
    # shared fixture services or substitute failure for an authorization denial.
    instance=lifecycle(dict(op='ensure',token=token))
    name=instance['name']
    try:
        obj=json.loads(run('docker','inspect',name))[0]
        pid=obj['State']['Pid']
        cg=run('sudo','cat',f'/proc/{pid}/cgroup').strip().split('::',1)[1]
        base='/sys/fs/cgroup'+cg
        before=run('sudo','cat',base+'/cpu.stat')
        cpu=run('docker','exec',name,'/usr/bin/python3.12','-c',
            'import multiprocessing,time; '
            'end=time.monotonic()+3; '
            '\ndef busy():\n while time.monotonic()<end: pass\n'
            '\nps=[multiprocessing.Process(target=busy) for _ in range(4)]\n[p.start() for p in ps]\n[p.join() for p in ps]')
        after=run('sudo','cat',base+'/cpu.stat')
        def fields(text): return {k:int(v) for k,v in (line.split() for line in text.splitlines())}
        assert fields(after)['nr_throttled']>fields(before)['nr_throttled']
        event_before=run('sudo','cat',base+'/memory.events')
        result=subprocess.run(['docker','exec',name,'/usr/bin/python3.12','-c',
            'x=bytearray(768*1024*1024); print(len(x))'],capture_output=True,text=True,timeout=30)
        event_after=run('sudo','cat',base+'/memory.events')
        assert result.returncode!=0 and fields(event_after)['oom_kill']>fields(event_before)['oom_kill']
        return dict(memory_cap_bytes=obj['HostConfig']['Memory'],cpu_cap=obj['HostConfig']['NanoCpus']/1e9,
            allocation_bytes=768*1024*1024,allocation_exit=result.returncode,
            cpu_before=fields(before),cpu_after=fields(after),memory_events_before=fields(event_before),
            memory_events_after=fields(event_after),state=json.loads(run('docker','inspect',name))[0]['State'])
    finally:
        lifecycle(dict(op='stop',name=name))


def cleanup():
    if (WORK/'supervisor.json').exists():
        os.environ.update(S5_RUNTIME=str(RUNTIME),S5_CONFIG=str(WORK/'supervisor.json'))
        stop_all()
    # Gateway is killed by its exact PID, never a name-based kill.
    if (WORK/'gateway.pid').exists():
        subprocess.run(['sudo','kill','-TERM',(WORK/'gateway.pid').read_text().strip()],capture_output=True)
        (WORK/'gateway.pid').unlink()
    if (WORK/'lifecycle.jsonl').exists():
        save('lifecycle-events.json',[json.loads(line) for line in run('sudo','cat',WORK/'lifecycle.jsonl').splitlines()])
    common.cleanup()
    for network in run('docker','network','ls','-q','--filter','name=^authz-backend$').split():
        run('docker','network','rm',network)
    run('sudo','rm','-rf',WORK)
    save('cleanup.json',dict(runtime_removed=not WORK.exists(),instances_remaining=len(names())))


if __name__=='__main__':
    if sys.argv[1:]==['initialize']:
        RESULTS['cases']={n:dict(status='BLOCKED',reason='Runtime prerequisites not completed') for n in
            ('single','per_user_C1_C2','security','idle_cleanup','crash','scale_1','scale_5','scale_20','resource_limits')}
        save('results.json',RESULTS)
    elif sys.argv[1:]==['cleanup']:
        cleanup()
    else:
        evaluate()
