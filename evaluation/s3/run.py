"""Slice 3: exact native admission, per-team catalog identity and relay controls."""
import json
import os
import platform
import subprocess
import sys
import time
import traceback
import uuid
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT/'.sources/lakehouse-integration'
PIN = 'e8379a528bf413c05aad49e56bc8cd507b5e077a'
SAIL_PIN = 'e96e068f926b8fecb3939e953389685ee4780032'
assert subprocess.check_output(['git','-C',str(SOURCE),'rev-parse','HEAD'],text=True).strip() == PIN
sys.path.extend([str(ROOT/'evaluation/s1'),str(SOURCE/'evaluation/authz'),str(SOURCE/'evaluation/idp')])
import common
common.OUT = ROOT/'reports/s3'
from common import WORK, run, save, secret, write, wait, decode
from s1_fixture import setup, grant, Rauthy
from fixture import container, leaf, transport, BACKEND_NETWORK
import rauthy
INPUTS = json.loads((ROOT/'evaluation/s1/inputs.json').read_text())
rauthy.REVISION = INPUTS['rauthy-ubi']['revision']
PYTHON = SOURCE/'.sources/sail-venv/bin/python'
ARCH = {'aarch64':'arm64','x86_64':'amd64'}[platform.machine()]
assert ARCH == os.environ['INTEGRATION_ARCH']
CASES = ('valid','missing','expired','wrong_audience','wrong_key','alg_none','team_a','team_b',
         'revoked','authz_outage','rauthy_outage','live_lookup_outage','tls_plaintext','backend_isolation',
         'paced_stream','audit')
RESULTS = dict(architecture=ARCH,machine=platform.machine(),run=os.environ.get('RUN_URL'),
    source=os.environ.get('GITHUB_SHA'),sail=SAIL_PIN,inputs=INPUTS,
    cases={c:dict(status='BLOCKED',reason='Runtime prerequisites have not completed') for c in CASES})


def record(name, fn, required=False):
    try:
        RESULTS['cases'][name] = dict(status='PASS',evidence=fn())
    except Exception as exc:
        RESULTS['cases'][name] = dict(status='FAIL',error=str(exc),traceback=traceback.format_exc())
    save('results.json',RESULTS)
    print(name+': '+RESULTS['cases'][name]['status'],flush=True)
    if required:
        assert RESULTS['cases'][name]['status']=='PASS', name
    return RESULTS['cases'][name]


def token_file(name, token):
    path = WORK/(name+'.jwt')
    write(path, secret(token))
    return path


def probe(path, expected):
    return json.loads(run(PYTHON,ROOT/'evaluation/s3/client.py','sail:50051',path,expected,
        env=dict(os.environ,GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=str(WORK/'ca/ca.pem'))))


def query(token, sql, session=None):
    return json.loads(run(PYTHON,ROOT/'evaluation/s3/query.py',input=json.dumps(dict(token=token,sql=sql,session=session)),
        env=dict(os.environ,GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=str(WORK/'ca/ca.pem'))))


def rows(token, sql, expected, session=None):
    result = query(token,sql,session)
    assert result['status']=='OK' and result['rows']==expected, result
    return result


def denied(token, sql, session=None):
    result = query(token,sql,session)
    assert result['status'] in ('INTERNAL','UNKNOWN','INVALID_ARGUMENT'), result
    detail = result.get('detail','')
    assert any(s in detail for s in ('403 Forbidden','404 Not Found','CannotSee','does not exist','not found')), result
    assert not any(s in detail for s in ('401 Unauthorized','Connection refused','TLS','Syntax error')), result
    return result


def launch(catalog, key, team_tokens):
    restricted = ['--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=256','--memory=2g','--cpus=2']
    teams = []
    for name, group in (('a','lake-readers'),('b','no-access')):
        directory = WORK/('team-'+name)
        directory.mkdir(mode=0o700)
        sockets = directory/'socket'
        sockets.mkdir(mode=0o700)
        run('sudo','chown','999:0',sockets)
        token = directory/'token'
        write(token,team_tokens[name])
        run('sudo','chown','10001:10001',token)
        run('sudo','chmod','0400',token)
        config = directory/'sail.json'
        config.write_text(json.dumps(dict(bind='127.0.0.1',port=50052,allow_unauthenticated_remote=False)))
        config.chmod(0o444)
        container('sail-'+name,'localhost/sail-ubi:integration',env={
            'SAIL_CATALOG__LIST':'[{type="iceberg-rest", name="bakeoff", uri="'+catalog.base+'/catalog", warehouse="bakeoff", bearer_access_token_file="/run/team-token"}]',
            'SSL_CERT_FILE':'/ca/ca.pem','AWS_ACCESS_KEY_ID':catalog.storage.access,
            'AWS_SECRET_ACCESS_KEY':catalog.storage.password,'AWS_ENDPOINT':catalog.storage.endpoint,
            'AWS_REGION':'local','AWS_ALLOW_HTTP':'false','AWS_VIRTUAL_HOSTED_STYLE_REQUEST':'false','TOKIO_WORKER_THREADS':'2'},
            mounts=[(token,'/run/team-token'),(config,'/etc/sail/config.json'),(catalog.provider.ca,'/ca/ca.pem')],
            extra=restricted+['--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700',
                              '--tmpfs','/var/lib/sail:rw,noexec,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700'])
        container('socket-'+name,'localhost/authz-serve:s1',['sail-socket'],
            env={'SAIL_SOCKET':'/socket/sail.sock'},network='container:sail-'+name,
            extra=restricted+['--user','999:0','-v',f'{sockets}:/socket:rw'])
        teams.append(dict(id=name,group=group,socket='/teams/'+name+'/sail.sock'))
        def socket_ready():
            run('sudo','test','-S',sockets/'sail.sock')
            return True
        wait(socket_ready)
        wait(lambda:run('docker','exec','sail-'+name,'/usr/bin/python3.12','-c',
            "import socket; socket.create_connection(('127.0.0.1',50052),timeout=1).close(); print('ready')"))
    config = WORK/'teams.json'
    config.write_text(json.dumps(teams)); config.chmod(0o444)
    container('gateway','localhost/authz-serve:s1',['sail-gateway'],env={
        'AUTHZ_TLS_CERT':'/tls/cert.pem','AUTHZ_TLS_KEY':'/tls/key.pem','AUTHZ_KEY_FILE':'/run/cedar-key',
        'AUTHZ_CA_FILE':'/ca/ca.pem','AUTHZ_ENDPOINT':'https://cedar:8443',
        'AUTHZ_DATABASE_URL_FILE':'/run/cedar-db-url','AUTHZ_DATABASE_CA_FILE':'/ca/ca.pem',
        'SAIL_TEAMS_FILE':'/teams.json','SAIL_JWKS_URL':catalog.provider.discovery['jwks_uri'],
        'SAIL_ISSUER':catalog.provider.issuer,'SAIL_AUDIENCE':'lakekeeper,expiry','AUTHZ_LISTEN':'0.0.0.0:50051'},
        mounts=[(leaf('sail'),'/tls'),(catalog.provider.ca,'/ca/ca.pem'),(WORK/'cedar-key','/run/cedar-key'),
            (WORK/'cedar-db-url','/run/cedar-db-url'),(config,'/teams.json'),
            (WORK/'team-a/socket','/teams/a'),(WORK/'team-b/socket','/teams/b')],
        network=BACKEND_NETWORK,extra=restricted+['--user','999:0'])
    # The audit database must resolve at process startup. Attach the public
    # client/IdP network afterwards; no request is sent before both are ready.
    run('docker','network','connect','--alias','sail',common.NETWORK,'gateway')
    from common import host
    host('gateway','sail')
    wait(lambda:transport('sail',50051,catalog.provider.ca))


def evaluate():
    # Dedicated client-credentials identities; user JWTs never enter Sail mounts.
    original = Rauthy.config_rauthy
    def config(self):
        result = original(self)
        path = self.path/'bootstrap/clients.json'
        clients = json.loads(path.read_text())
        clients += [{**clients[0],'id':'sail-team-'+name,'name':'sail-team-'+name} for name in ('a','b')]
        write(path,clients)
        return result
    with patch.object(Rauthy,'config_rauthy',config):
        catalog, operator, key = setup(ARCH,record,
            machine_principals=('oidc~sail-team-a','oidc~sail-team-b'),
            extra_catalog_audiences=('sail-team-a','sail-team-b'))
    for image, pin in (('localhost/sail-ubi:integration',SAIL_PIN),('localhost/rauthy-ubi:authz',INPUTS['rauthy-ubi']['revision'])):
        obj = json.loads(run('docker','image','inspect',image))[0]
        assert obj['Architecture']==ARCH and obj['Config']['Labels']['org.opencontainers.image.revision']==pin
        RESULTS.setdefault('provenance',{})[image] = dict(id=obj['Id'],architecture=obj['Architecture'],labels=obj['Config']['Labels'])
    provider = catalog.provider
    tokens = {'a':secret(provider.human()['access_token']),
              'b':secret(provider.human(email='bob@idp.test',password=provider.bob_password)['access_token'])}
    team_tokens = {name:provider.token('sail-team-'+name) for name in ('a','b')}
    assert len({decode(t)[1]['sub'] for t in [*tokens.values(),*team_tokens.values()]})==4
    import pyarrow as pa
    admin = catalog.pyiceberg(operator)
    for name in ('a','b'):
        admin.create_namespace('team_'+name)
        for table in ('sample','sibling'):
            t = admin.create_table('team_'+name+'.'+table,schema=pa.schema([pa.field('id',pa.int64())]))
            t.append(pa.Table.from_pylist([{'id':11 if name=='a' else 22}]))
        namespace = 'namespace:'+admin.load_namespace_properties('team_'+name)['namespace_id']
        grant(catalog,key,'user:oidc~'+decode(team_tokens[name])[1]['sub'],'select',namespace)
    # Fail early on catalog credential configuration. A 401 must never be
    # mistaken for a team's authorization denial in the real Sail controls.
    for name, token in team_tokens.items():
        response = catalog.http.request('GET',catalog.base+'/catalog/v1/config',
            params={'warehouse':catalog.warehouse},headers={'Authorization':'Bearer '+token})
        assert response.status_code == 200, (name,'team catalog token',response.status_code)
    launch(catalog,key,team_tokens)
    paths = {name:token_file(name,token) for name,token in tokens.items()}
    record('valid',lambda:{name:probe(path,'OK') for name,path in paths.items()})
    record('missing',lambda:probe('-','UNAUTHENTICATED'))
    record('wrong_audience',lambda:probe(token_file('wrong-audience',provider.token('wrong-audience')),'UNAUTHENTICATED'))
    from catalog import bad_token, b64
    provider.human_token = tokens['a']
    record('wrong_key',lambda:probe(token_file('wrong-key',bad_token(provider,'different_key')),'UNAUTHENTICATED'))
    parts = tokens['a'].split('.')
    record('alg_none',lambda:probe(token_file('none',b64({'alg':'none','typ':'JWT'})+'.'+parts[1]+'.'),'UNAUTHENTICATED'))
    def expiry():
        token = provider.token('expiry')
        path = token_file('expiry',token)
        before = probe(path,'PERMISSION_DENIED')  # valid signature, no team membership
        deadline = decode(token)[1]['exp']+1
        while time.time() <= deadline:
            time.sleep(min(1,deadline-time.time()+0.1))
        expired = probe(path,'UNAUTHENTICATED')
        fresh = probe(token_file('fresh-expiry',provider.token('expiry')),'PERMISSION_DENIED')
        return dict(before=before,expired=expired,fresh=fresh)
    record('expired',expiry)
    shared_session = str(uuid.uuid4())
    def team(name):
        other = 'b' if name=='a' else 'a'
        value = 11 if name=='a' else 22
        # Sail 0.7.3 names this SHOW TABLES column 'database'. Require the
        # complete exact records, then exercise both reads and cross-team denials.
        return dict(tables=rows(tokens[name],'SHOW TABLES IN bakeoff.team_'+name,
                    [{'database':'team_'+name,'tableName':'sample','isTemporary':False},
                     {'database':'team_'+name,'tableName':'sibling','isTemporary':False}],shared_session),
            own=rows(tokens[name],'SELECT id FROM bakeoff.team_'+name+'.sample',[{'id':value}],shared_session),
            other=denied(tokens[name],'SELECT * FROM bakeoff.team_'+other+'.sample',shared_session))
    record('team_a',lambda:team('a'))
    record('team_b',lambda:team('b'))
    record('tls_plaintext',lambda:transport('sail',50051,provider.ca))
    def isolation():
        result = {}
        for name in ('a','b'):
            obj = json.loads(run('docker','inspect','sail-'+name))[0]
            assert not obj['HostConfig']['PortBindings'], obj['HostConfig']['PortBindings']
            address = obj['NetworkSettings']['Networks'][common.NETWORK]['IPAddress']
            code = int(run('docker','run','--rm','--network',common.NETWORK,'--entrypoint','/usr/bin/python3.12',
                'localhost/sail-ubi:integration','-c',
                f'import socket; s=socket.socket(); s.settimeout(3); print(s.connect_ex(({address!r},50052)))'))
            assert code==111, code
            mounts = obj['Mounts']
            assert [m['Destination'] for m in mounts if 'token' in m['Destination']]==['/run/team-token']
            assert not any('/socket' in m['Destination'] or '/teams' in m['Destination'] for m in mounts)
            stat = json.loads(run('docker','exec','sail-'+name,'/usr/bin/python3.12','-c',
                'import os,json; s=os.stat("/run/team-token"); print(json.dumps([s.st_uid,s.st_mode&511]))'))
            assert stat==[10001,256], stat
            result[name] = dict(peer_connect_errno=code,token_uid=stat[0],token_mode=oct(stat[1]))
        return result
    record('backend_isolation',isolation)
    def outage(target):
        probe(paths['a'],'OK')
        run('docker','stop','-t','5',target)
        try:
            time.sleep(0.3)
            refusal = probe(paths['a'],'UNAVAILABLE')
        finally:
            run('docker','start',target)
        wait(lambda:provider.http.request('GET',provider.base+'/auth/v1/health').status_code==200,180)
        wait(lambda:provider.http.request('POST','https://cedar:8443/sail/groups',
            headers={'Authorization':'Bearer '+key},json='oidc~'+decode(tokens['a'])[1]['sub']).status_code==200)
        return dict(unreachable=refusal,recovered=probe(paths['a'],'OK'))
    record('authz_outage',lambda:outage('cedar'))
    record('rauthy_outage',lambda:outage(provider.container))
    def live_outage():
        probe(paths['a'],'OK')
        run('docker','network','disconnect','slice1-idp','fga-postgres')
        try:
            time.sleep(0.3)
            # Gateway can still fetch JWKS: only serve's live-user path is broken.
            provider.http.json('GET',provider.discovery['jwks_uri'])
            refusal = probe(paths['a'],'UNAVAILABLE')
        finally:
            run('docker','network','connect','slice1-idp','fga-postgres')
        return dict(denied=refusal,recovered=probe(paths['a'],'OK'),jwks_available=True)
    record('live_lookup_outage',live_outage)
    from stream import stream
    record('paced_stream',lambda:stream(provider.ca,paths['a']))
    def revoke():
        probe(paths['a'],'OK')
        started = time.monotonic()
        provider.remove_group(decode(tokens['a'])[1]['sub'])
        time.sleep(0.3)
        first = probe(paths['a'],'PERMISSION_DENIED')
        elapsed = time.monotonic()-started
        assert elapsed < 5, elapsed
        time.sleep(0.3)
        return dict(seconds=elapsed,old_token=first,old_token_repeated=probe(paths['a'],'PERMISSION_DENIED'),
            unaffected_team_b=probe(paths['b'],'OK'))
    record('revoked',revoke)
    record('audit',lambda:audit(catalog,team_tokens))
    assert all(RESULTS['cases'][c]['status']=='PASS' for c in CASES), 'Slice 3 incomplete; see results.json'


def audit(catalog, team_tokens):
    from urllib.parse import urlsplit, unquote
    database = urlsplit(run('sudo','cat',WORK/'cedar-db-url').strip())
    values = dict(PGHOST=database.hostname,PGPORT=str(database.port or 5432),PGDATABASE=unquote(database.path.lstrip('/')),
        PGUSER=unquote(database.username),PGPASSWORD=unquote(database.password),PGSSLMODE='verify-full',PGSSLROOTCERT='/ca/ca.pem')
    write(WORK/'audit.env','\n'.join(k+'='+v for k,v in values.items())+'\n')
    query = """SELECT json_build_object('permits',count(*) FILTER(WHERE decision),
        'denials',count(*) FILTER(WHERE NOT decision), 'reasons',array_agg(DISTINCT reason),
        'teams',array_agg(DISTINCT resource->>'id') FILTER(WHERE decision),
        'invalid_principals',count(*) FILTER(WHERE reason='sail_invalid_token' AND principal<>'unauthenticated'),
        'missing_results',count(*) FILTER(WHERE result IS NULL))
        FROM authz_audit WHERE action='sail:admit';"""
    def sql(query):
        return json.loads(run('docker','run','--rm','-i','--network','container:fga-postgres','--env-file',WORK/'audit.env',
            '-v',f'{catalog.provider.ca}:/ca/ca.pem:ro','localhost/postgresql-ubi:integration','psql','-XAt','-f','-',input=query))
    result = sql(query)
    from collections import Counter
    events = [json.loads(line) for line in run('docker','logs','gateway').splitlines()
              if line.startswith('{') and 'sail_admission' in line]
    observed = Counter(str(e['grpc_status'])+':sail:'+e['team'] for e in events)
    persisted = sql("SELECT coalesce(json_object_agg(k,n),'{}'::json) FROM (SELECT (result->>'grpc_status')||':'||(resource->>'id') k,count(*) n FROM authz_audit WHERE action='sail:admit' GROUP BY 1) s;")
    assert dict(observed)==persisted and len(events)>0, (observed,persisted)
    result['exact_admission_records'] = len(events)
    refused = Counter(e['grpc_status'] for e in events if e['grpc_status'] != 0)
    # Independent client controls: five invalid JWTs, two valid expiry-token
    # membership denials, two old-token revocations, and three dependency outages.
    assert refused == {16:5, 7:4, 14:3}, refused
    assert sum(e['grpc_status']==0 for e in events) >= 17, observed
    assert result['permits']>0 and result['denials']>0 and sorted(result['teams'])==['sail:a','sail:b'], result
    assert result['missing_results']==result['invalid_principals']==0, result
    assert set(result['reasons'])=={'sail_team_permit','sail_invalid_token','sail_team_deny','sail_dependency_unavailable'}, result
    # Real catalog adapter records each team's machine identity reading only its grants.
    for name, token in team_tokens.items():
        principal = 'oidc~'+decode(token)[1]['sub']
        assert principal == 'oidc~sail-team-'+name, principal
        row = sql("SELECT json_build_object('allowed',count(*) FILTER(WHERE decision),'denied',count(*) FILTER(WHERE NOT decision)) FROM authz_audit WHERE principal='"+principal+"';")
        assert row['allowed']>0 and row['denied']>0, row
        result['catalog_team_'+name] = row
    return result


def cleanup():
    common.cleanup()
    for network in run('docker','network','ls','-q','--filter','name=^(authz-backend|slice1-idp)$').split():
        run('docker','network','rm',network)
    run('sudo','rm','-rf',WORK)


if __name__=='__main__':
    if sys.argv[1:]==['initialize']:
        save('results.json',RESULTS)
    elif sys.argv[1:]==['cleanup']:
        cleanup()
    else:
        save('results.json',RESULTS)
        try:
            evaluate()
        finally:
            cleanup()
