#!/usr/bin/env python3
"""Slice 4c adversarial review: the shipped authz `serve` binary against a private
TLS PostgreSQL and a mock Rauthy, both on the CI runner only. Every case asserts
the REQUIRED secure behaviour; a FAIL is a finding for owner triage. All cases
run; results go to reports/s4c/serve-harness.json; any FAIL exits non-zero.

Usage: python3 scripts/adversarial-serve.py [path/to/authz-serve-binary]
"""
import getpass
import glob
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BINARY = Path(sys.argv[1] if len(sys.argv) > 1 else 'reports/images/authz/binary').resolve()
OUT = Path('reports/s4c')
RESULTS = {}


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def record(name, fn):
    try:
        RESULTS[name] = {'status': 'PASS', 'evidence': fn()}
    except Exception as exc:  # every case runs; failures are findings
        RESULTS[name] = {'status': 'FAIL', 'error': str(exc), 'traceback': traceback.format_exc()}
    print(f'{name}: {RESULTS[name]["status"]}' + ('' if RESULTS[name]['status'] == 'PASS' else ' - ' + RESULTS[name]['error']), flush=True)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    pg_bin = Path(sorted(glob.glob('/usr/lib/postgresql/*/bin/postgres'))[-1]).parent
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)

        def command(*args, check=True, **kwargs):
            result = subprocess.run(args, capture_output=True, text=True, **kwargs)
            if check and result.returncode:
                raise AssertionError(f'{args[0]} failed: {result.stderr.strip()}')
            return result
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root/'ca-key.pem'), '-out', str(root/'ca.pem'),
                '-days', '1', '-subj', '/CN=s4c-ca', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign')
        command('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root/'key.pem'), '-out', str(root/'leaf.csr'), '-subj', '/CN=localhost')
        (root/'extensions').write_text('basicConstraints=CA:FALSE\nsubjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n')
        command('openssl', 'x509', '-req', '-in', str(root/'leaf.csr'), '-CA', str(root/'ca.pem'), '-CAkey', str(root/'ca-key.pem'),
                '-CAcreateserial', '-days', '1', '-extfile', str(root/'extensions'), '-out', str(root/'cert.pem'))
        for name in ('secret', 'trino-key', 'db-password', 'service-password', 'reader-key', 'owner-password', 'gateway-key',
                     'over-password'):
            (root/name).write_text(os.urandom(32).hex())
            (root/name).chmod(0o600)
        command(str(pg_bin/'initdb'), '-D', str(root/'pg'), '--auth-local=trust', '--auth-host=scram-sha-256', '--pwfile', str(root/'db-password'))
        dbport, serviceport = port(), port()
        pgargs = [str(pg_bin/'postgres'), '-D', str(root/'pg'), '-p', str(dbport), '-k', str(root), '-h', '127.0.0.1', '-c', 'ssl=on',
                  '-c', 'ssl_cert_file='+str(root/'cert.pem'), '-c', 'ssl_key_file='+str(root/'key.pem')]
        admin_env = dict(os.environ, PGPASSWORD=(root/'db-password').read_text(), PGSSLMODE='verify-full', PGSSLROOTCERT=str(root/'ca.pem'))
        service_env = dict(admin_env, PGUSER='authz_service', PGPASSWORD=(root/'service-password').read_text())

        def sql(statement, env=admin_env, database='authz', check=True):
            result = command(str(pg_bin/'psql'), '-X', '-h', 'localhost', '-p', str(dbport), '-d', database, '-v', 'ON_ERROR_STOP=1',
                             '-At', '-f', '-', input=statement, env=env, check=check)
            return result if not check else result.stdout.strip()
        logfile = (root/'postgres.log').open('w')
        postgres = subprocess.Popen(pgargs, stdout=logfile, stderr=logfile)
        service = server = None
        try:
            for _ in range(100):
                try:
                    sql('SELECT 1', database='postgres')
                    break
                except AssertionError:
                    time.sleep(.1)
            else:
                raise AssertionError('PostgreSQL readiness failed')
            # Setup (slice 4c fixes, F4): a schema-owner login that owns the
            # database and runs `migrate`, and the separate runtime login
            # authz_service that serve uses. The tamper assertions below still
            # run as authz_service, byte-for-byte unchanged.
            sql("CREATE ROLE authz_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '"
                + (root/'owner-password').read_text() + "'", database='postgres')
            sql("CREATE ROLE authz_service LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '"
                + (root/'service-password').read_text() + "'", database='postgres')
            sql('CREATE DATABASE authz OWNER authz_owner', database='postgres')

            idp = {'users': {'alice': ['readers'], 'bob': [], 'carol': []}, 'modes': {}, 'seen': []}

            class Idp(BaseHTTPRequestHandler):
                def log_message(self, *_):
                    pass

                def reply(self, status, body=None, headers=()):
                    data = json.dumps(body).encode() if body is not None else b''
                    self.send_response(status)
                    for k, v in headers:
                        self.send_header(k, v)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)

                def do_GET(self):
                    idp['seen'].append(self.path)
                    if self.headers.get('authorization') != (root/'reader-key').read_text():
                        return self.reply(401)
                    prefix = '/auth/v1/users/'
                    if not self.path.startswith(prefix):
                        return self.reply(404)
                    subject = urllib.parse.unquote(self.path[len(prefix):])
                    if subject.endswith('~redirected'):
                        original = subject[:-len('~redirected')]
                        return self.reply(200, {'id': original, 'enabled': True, 'groups': ['readers']})
                    if subject not in idp['users']:
                        return self.reply(404)
                    mode = idp['modes'].get(subject, 'ok')
                    groups = idp['users'][subject]
                    if mode == 'slow':
                        time.sleep(3.5)
                    if mode == 'error':
                        return self.reply(500)
                    if mode == 'redirect':
                        target = f'https://localhost:{self.server.server_port}{prefix}{urllib.parse.quote(subject)}~redirected'
                        return self.reply(302, headers=[('Location', target)])
                    if mode == 'mismatch':
                        return self.reply(200, {'id': subject+'-other', 'enabled': True, 'groups': groups})
                    if mode == 'disabled':
                        return self.reply(200, {'id': subject, 'enabled': False, 'groups': groups})
                    return self.reply(200, {'id': subject, 'enabled': True, 'groups': groups})
            server = ThreadingHTTPServer(('127.0.0.1', 0), Idp)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(root/'cert.pem', root/'key.pem')
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            url = (f'postgres://authz_service:{(root/"service-password").read_text()}@localhost:{dbport}/authz?sslmode=verify-full')
            (root/'db-url').write_text(url)
            (root/'db-url').chmod(0o600)
            for login in ('owner', 'over'):
                (root/f'{login}-url').write_text(f'postgres://authz_{login}:{(root/(login + "-password")).read_text()}'
                                                 f'@localhost:{dbport}/authz?sslmode=verify-full')
                (root/f'{login}-url').chmod(0o600)
            (root/'superuser-url').write_text(f'postgres://{getpass.getuser()}:{(root/"db-password").read_text()}'
                                              f'@localhost:{dbport}/authz?sslmode=verify-full')
            (root/'superuser-url').chmod(0o600)
            migrate_env = dict(os.environ, AUTHZ_DATABASE_URL_FILE=str(root/'owner-url'), AUTHZ_DATABASE_CA_FILE=str(root/'ca.pem'),
                               AUTHZ_RUNTIME_ROLE='authz_service')
            command(str(BINARY), 'migrate', env=migrate_env)
            env = dict(os.environ, AUTHZ_LISTEN=f'127.0.0.1:{serviceport}', AUTHZ_TLS_CERT=str(root/'cert.pem'),
                       AUTHZ_TLS_KEY=str(root/'key.pem'), AUTHZ_KEY_FILE=str(root/'secret'), AUTHZ_TRINO_KEY_FILE=str(root/'trino-key'),
                       AUTHZ_DATABASE_URL_FILE=str(root/'db-url'), AUTHZ_DATABASE_CA_FILE=str(root/'ca.pem'),
                       AUTHZ_RAUTHY_USERS_URL=f'https://localhost:{server.server_port}/auth/v1/users',
                       AUTHZ_RAUTHY_CA_FILE=str(root/'ca.pem'), AUTHZ_RAUTHY_KEY_FILE=str(root/'reader-key'),
                       AUTHZ_MACHINE_PRINCIPALS='oidc~machine', AUTHZ_DECISION_KEY_FILE=str(root/'gateway-key'))
            client_ctx = ssl.create_default_context(cafile=str(root/'ca.pem'))
            key = (root/'secret').read_text()
            trino = (root/'trino-key').read_text()

            def post(path, body, credential=key, raw=None, timeout=15):
                data = raw if raw is not None else json.dumps(body).encode()
                headers = {'Content-Type': 'application/json'}
                if credential:
                    headers['Authorization'] = 'Bearer ' + credential
                request = urllib.request.Request(f'https://localhost:{serviceport}/{path}', data=data, headers=headers)
                try:
                    with urllib.request.urlopen(request, context=client_ctx, timeout=timeout) as response:
                        payload = response.read()
                        return response.status, (json.loads(payload) if payload else None)
                except urllib.error.HTTPError as exc:
                    return exc.code, None
            service = subprocess.Popen([str(BINARY), 'serve'], env=env, stdout=(root/'serve.out').open('w'), stderr=(root/'serve.log').open('w'))
            for _ in range(150):
                if service.poll() is not None:
                    raise AssertionError('serve exited: ' + (root/'serve.log').read_text()[-2000:])
                try:
                    if post('decide', [])[0] == 200:
                        break
                except (urllib.error.URLError, ConnectionError):
                    pass
                time.sleep(.1)
            else:
                raise AssertionError('serve readiness failed')

            def mutate(m):
                status, _ = post('mutate', m)
                assert status == 204, (m, status)

            def table(i):
                return {'kind': 'Table', 'id': i}

            def user(i):
                return {'kind': 'User', 'id': i}

            def grant(subject, resource, access, remove=False):
                mutate({'op': 'grant', 'grant': {'subject': subject, 'resource': resource, 'access': access}, 'remove': remove})
            for t in ('t1', 't2', 't3'):
                mutate({'op': 'put', 'resource': table(t), 'parent': None, 'owner': None})
            grant(user('oidc~alice'), table('t1'), 'owner')
            grant(user('oidc~bob'), table('t2'), 'select')
            grant({'kind': 'Group', 'id': 'readers'}, table('t3'), 'select')
            grant(user('oidc~machine'), table('t2'), 'select')
            mutate({'op': 'bind_trino', 'name': ['iceberg', 's4c', 't3'],
                    'binding': {'resource': table('t3'), 'region_column': None, 'sensitive_column': None}})

            def check(principal, resource, action='read_data', **extra):
                return {'principal': principal, 'groups': [], 'action': action, 'resource': resource, **extra}

            def decide(*checks):
                return post('decide', list(checks))

            def last_reason():
                return sql('SELECT reason FROM authz_audit ORDER BY id DESC LIMIT 1')

            def settle():
                time.sleep(.3)  # past the 250 ms membership cache

            # Control: the fixture works and permits what it should.
            def control():
                for principal, resource in (('oidc~bob', table('t2')), ('oidc~alice', table('t3'))):
                    status, body = decide(check(principal, resource))
                    assert status == 200 and body[0]['allowed'] is True, (principal, status, body)
                return {'bob_t2': True, 'alice_group_t3': True}
            record('control_fixture_permits', control)

            def audit_tamper():
                owner = sql("SELECT tableowner FROM pg_tables WHERE tablename='authz_audit'")
                count = int(sql('SELECT count(*) FROM authz_audit'))
                assert count > 0, 'no audit rows to protect'
                # Non-destructive: always rolled back. The service's own credential
                # (which ran the migrations) must not be able to erase audit rows.
                attempt = sql('BEGIN;\nALTER TABLE authz_audit DISABLE TRIGGER authz_audit_append_only;\n'
                              'DELETE FROM authz_audit;\nSELECT \'TAMPERED\';\nROLLBACK;\n', env=service_env, check=False)
                drop = sql('BEGIN;\nDROP TRIGGER authz_audit_append_only ON authz_audit;\nTRUNCATE authz_audit;\n'
                           'SELECT \'TAMPERED\';\nROLLBACK;\n', env=service_env, check=False)
                assert int(sql('SELECT count(*) FROM authz_audit')) == count
                evidence = {'audit_table_owner': owner, 'service_role': 'authz_service',
                            'disable_trigger_then_delete': 'TAMPERED' in attempt.stdout,
                            'drop_trigger_then_truncate': 'TAMPERED' in drop.stdout}
                assert not evidence['disable_trigger_then_delete'] and not evidence['drop_trigger_then_truncate'], \
                    f'service credential can erase the append-only audit: {evidence}'
                return evidence
            record('audit_tamper_resistant_to_service_credential', audit_tamper)

            def grant_dos():
                # alice owns t1, so the owner-authorized grant API accepts her change.
                hostile = {'check': check('oidc~alice', table('t1'), 'manage_grants'),
                           'grant': {'subject': user('x\u0001y'), 'resource': table('t1'), 'access': 'select'}}
                change, _ = post('permissions', hostile)
                try:
                    status, body = decide(check('oidc~bob', table('t2')))
                    evidence = {'hostile_change_status': change, 'unrelated_decision_status': status,
                                'unrelated_reason': last_reason()}
                    assert status == 200 and body[0]['allowed'] is True, \
                        f'one owner-chosen grant subject denied service to every principal: {evidence}'
                    return evidence
                finally:
                    grant(user('x\u0001y'), table('t1'), 'select', remove=True)
                    assert decide(check('oidc~bob', table('t2')))[0] == 200, 'graph not restored'
            record('grant_subject_cannot_disable_all_decisions', grant_dos)

            def injection():
                hostile = "oidc~x'); DROP TABLE authz_audit; --"
                status, _ = decide(check(hostile, {'kind': 'Table', 'id': "t'||(SELECT 1)||'"}, action="read_data'; --"))
                stored = sql("SELECT principal FROM authz_audit ORDER BY id DESC LIMIT 1")
                region = "eu'); DROP TABLE authz_state; --"
                mutate({'op': 'set_region', 'principal': 'oidc~alice', 'region': region})
                _, snapshot = post('snapshot', {})
                tables = sql("SELECT string_agg(tablename, ',' ORDER BY tablename) FROM pg_tables WHERE tablename LIKE 'authz_%'")
                assert stored == hostile and snapshot['regions']['oidc~alice'] == region, (stored, snapshot['regions'])
                assert tables == 'authz_audit,authz_state', tables
                return {'decision_status': status, 'audited_verbatim': True, 'tables': tables}
            record('sql_injection_strings_are_inert', injection)

            def opa_groups():
                def opa(groups):
                    q = {'input': {'context': {'identity': {'user': 'oidc~bob', 'groups': groups}, 'properties': {'serviceKey': trino}},
                                   'action': {'operation': 'SelectFromColumns', 'resource': {'table': {
                                       'catalogName': 'iceberg', 'schemaName': 's4c', 'tableName': 't3', 'columns': ['id']}}}}}
                    return post('opa/allow', q)
                forged = opa(['readers'])
                assert forged == (200, {'result': False}), f'asserted Trino groups granted access: {forged}'
                idp['users']['bob'] = ['readers']
                settle()
                try:
                    live = opa([])
                    assert live == (200, {'result': True}), live
                finally:
                    idp['users']['bob'] = []
                    settle()
                return {'asserted_groups': forged[1], 'live_groups': live[1]}
            record('trino_asserted_groups_are_ignored', opa_groups)

            def decide_overrides():
                status, body = decide(check('oidc~bob', table('t3'), groups=['readers'], deny=False))
                assert status == 200 and body[0]['allowed'] is False, (status, body)
                return {'forged_groups_denied': True}
            record('decide_asserted_groups_are_ignored', decide_overrides)

            def idp_mode(mode, subject='alice'):
                idp['modes'][subject] = mode
                settle()
                try:
                    started = time.monotonic()
                    status, body = decide(check('oidc~'+subject, table('t3')))
                    return status, body, time.monotonic() - started, last_reason()
                finally:
                    idp['modes'].pop(subject, None)
                    settle()

            def idp_failures():
                evidence = {}
                for mode in ('slow', 'redirect', 'mismatch', 'disabled', 'error'):
                    status, body, seconds, reason = idp_mode(mode)
                    evidence[mode] = {'status': status, 'seconds': round(seconds, 2), 'reason': reason}
                    assert status == 503 and body is None, (mode, status, body)
                    assert reason == 'identity_provider_unavailable', (mode, reason)
                    assert seconds < 5, (mode, seconds)
                return evidence
            record('identity_provider_failures_fail_closed', idp_failures)

            def principals():
                evidence = {}
                for principal in ('oidc~ghost', 'ghost', 'kubernetes~alice', '', 'oidc~', 'oidc~alice\n', 'OIDC~alice'):
                    idp['seen'].clear()
                    status, body = decide(check(principal, table('t3')))
                    evidence[repr(principal)] = {'status': status, 'lookups': list(idp['seen'])}
                    assert status != 200 or not body[0]['allowed'], (principal, status, body)
                # A machine principal (no Rauthy user) holds only its direct grants.
                status, body = decide(check('oidc~machine', table('t2')))
                assert status == 200 and body[0]['allowed'], (status, body)
                status, body = decide(check('oidc~machine', table('t3')))
                assert status == 200 and not body[0]['allowed'], (status, body)
                return evidence
            record('unknown_and_malformed_principals_deny', principals)

            def batch():
                status, body = decide(check('oidc~bob', table('t2')), check('oidc~ghost', table('t2')))
                assert status == 503 and body is None, f'partial verdicts leaked: {status} {body}'
                return {'status': status}
            record('batch_with_one_unverifiable_identity_returns_no_verdicts', batch)

            def lock_timeout():
                holder = subprocess.Popen([str(pg_bin/'psql'), '-X', '-h', 'localhost', '-p', str(dbport), '-d', 'authz', '-At', '-c',
                                           'BEGIN; SELECT 1 FROM authz_state FOR UPDATE; SELECT pg_sleep(6); COMMIT;'],
                                          env=admin_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    time.sleep(1)
                    started = time.monotonic()
                    status, body = decide(check('oidc~bob', table('t2')))
                    seconds = time.monotonic() - started
                    assert status == 503 and body is None, (status, body)
                    assert seconds < 4.5, seconds
                    return {'status': status, 'seconds': round(seconds, 2)}
                finally:
                    holder.wait(timeout=15)
            record('database_lock_contention_fails_closed', lock_timeout)

            def audited():
                before = int(sql('SELECT coalesce(max(id), 0) FROM authz_audit'))
                decide(check('oidc~bob', table('t1')))                      # Cedar deny
                idp_mode('error', 'bob')                                     # IdP outage
                status, _ = post('permissions', {'check': check('oidc~bob', table('t1'), 'manage_grants'),
                                                 'grant': {'subject': user('oidc~bob'), 'resource': table('t1'), 'access': 'owner'}})
                assert status == 403, status
                rows = sql("SELECT string_agg(reason || ':' || decision::text, ',' ORDER BY id) FROM authz_audit WHERE id > " + str(before))
                assert rows == 'cedar_default_deny:false,identity_provider_unavailable:false,grant_management_deny:false', rows
                return {'rows': rows}
            record('denials_and_errors_are_audited_before_response', audited)

            def oversize():
                try:
                    status, _ = post('decide', None, raw=b'[' + b' ' * (3 << 20) + b']')
                except (urllib.error.URLError, ConnectionError, ssl.SSLError) as exc:
                    status = 'connection closed during upload: ' + type(exc).__name__  # also a rejection
                assert status in (400, 413) or isinstance(status, str), status
                assert decide(check('oidc~bob', table('t2')))[0] == 200, 'service did not survive'
                return {'status': status}
            record('oversized_request_is_rejected', oversize)

            def rauthy_tls():
                command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root/'rogue-key.pem'),
                        '-out', str(root/'rogue.pem'), '-days', '1', '-subj', '/CN=rogue')
                evidence = {}
                for name, change in (('http_url', {'AUTHZ_RAUTHY_USERS_URL': f'http://localhost:{server.server_port}/auth/v1/users'}),
                                     ('wrong_ca', {'AUTHZ_RAUTHY_CA_FILE': str(root/'rogue.pem')})):
                    other = port()
                    proc = subprocess.Popen([str(BINARY), 'serve'], env=dict(env, AUTHZ_LISTEN=f'127.0.0.1:{other}', **change),
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    try:
                        outcome = 'exited'
                        for _ in range(100):
                            if proc.poll() is not None:
                                break
                            try:
                                request = urllib.request.Request(f'https://localhost:{other}/decide', data=json.dumps(
                                    [check('oidc~bob', table('t2'))]).encode(), headers={'Content-Type': 'application/json',
                                                                                      'Authorization': 'Bearer ' + key})
                                with urllib.request.urlopen(request, context=client_ctx, timeout=10) as response:
                                    outcome = f'HTTP {response.status} {response.read()[:200]!r}'
                            except urllib.error.HTTPError as exc:
                                outcome = f'HTTP {exc.code}'
                            except (urllib.error.URLError, ConnectionError):
                                time.sleep(.1)
                                continue
                            break
                        evidence[name] = outcome
                        assert outcome in ('exited', 'HTTP 503'), f'{name}: {outcome}'
                    finally:
                        if proc.poll() is None:
                            proc.terminate()
                            proc.wait(timeout=10)
                return evidence
            record('identity_provider_tls_is_verified', rauthy_tls)

            def no_credentials():
                credentials = {n: (root/n).read_text() for n in ('secret', 'trino-key', 'reader-key', 'service-password', 'db-password')}
                texts = {'serve.out': (root/'serve.out').read_text(), 'serve.log': (root/'serve.log').read_text(),
                         'audit': sql("SELECT coalesce(json_agg(a)::text, '') FROM authz_audit a"),
                         'graph': sql('SELECT graph::text FROM authz_state')}
                leaks = [f'{n} in {t}' for t, text in texts.items() for n, c in credentials.items() if c in text]
                assert not leaks, leaks
                return {'scanned': sorted(texts), 'bytes': {t: len(v) for t, v in texts.items()}}
            record('logs_and_audit_contain_no_credentials', no_credentials)

            # ---- Slice 4c fixes: setup-drift guards and refuse-to-start checks ----
            def least_privilege():
                row = json.loads(sql(
                    "SELECT json_build_object("
                    "'owns_audit', pg_has_role('authz_service', (SELECT tableowner FROM pg_tables WHERE tablename='authz_audit'), 'USAGE'),"
                    "'owns_state', pg_has_role('authz_service', (SELECT tableowner FROM pg_tables WHERE tablename='authz_state'), 'USAGE'),"
                    "'audit_update', has_table_privilege('authz_service','authz_audit','UPDATE'),"
                    "'audit_delete', has_table_privilege('authz_service','authz_audit','DELETE'),"
                    "'audit_truncate', has_table_privilege('authz_service','authz_audit','TRUNCATE'),"
                    "'schema_create', has_schema_privilege('authz_service','public','CREATE'),"
                    "'audit_insert', has_table_privilege('authz_service','authz_audit','INSERT'))"))
                assert not any(row[k] for k in ('owns_audit', 'owns_state', 'audit_update', 'audit_delete', 'audit_truncate',
                                                'schema_create')), row
                assert row['audit_insert'], row
                return row
            record('runtime_login_is_least_privilege', least_privilege)

            def outcome(args, extra, seconds=8):
                """'exited: <reason>' if the process refuses to run, else 'running'."""
                proc = subprocess.Popen([str(BINARY), *args], env=dict(env, AUTHZ_LISTEN=f'127.0.0.1:{port()}', **extra),
                                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
                try:
                    proc.wait(timeout=seconds)
                    return 'exited: ' + proc.stderr.read()[-300:].replace('\n', ' ')
                except subprocess.TimeoutExpired:
                    return 'running'
                finally:
                    if proc.poll() is None:
                        proc.terminate()
                        proc.wait(timeout=10)
            sql("CREATE ROLE authz_over LOGIN PASSWORD '" + (root/'over-password').read_text() + "'", database='postgres')
            sql('GRANT SELECT, INSERT, DELETE ON authz_audit TO authz_over; GRANT SELECT, UPDATE ON authz_state TO authz_over')
            (root/'teams.json').write_text(json.dumps([{'id': 'a', 'group': 'team-a', 'socket': str(root/'a.sock')}]))
            gateway = {'AUTHZ_CA_FILE': str(root/'ca.pem'), 'AUTHZ_KEY_FILE': str(root/'gateway-key'),
                       'AUTHZ_ENDPOINT': f'https://localhost:{serviceport}', 'SAIL_JWKS_URL': 'https://localhost:1/jwks',
                       'SAIL_ISSUER': 'https://idp.test/', 'SAIL_AUDIENCE': 'sail', 'SAIL_TEAMS_FILE': str(root/'teams.json')}

            def refuses(role, extra):
                evidence = {}
                for login in ('owner', 'over', 'superuser'):
                    result = outcome([role], {**extra, 'AUTHZ_DATABASE_URL_FILE': str(root/f'{login}-url')})
                    evidence[login] = result
                    assert result.startswith('exited'), f'{role} started with the {login} login'
                control = outcome([role], extra)
                evidence['runtime_control'] = control
                assert control == 'running', f'{role} did not start with the least-privilege login: {control}'
                return evidence
            record('serve_refuses_owner_or_overprivileged_login', lambda: refuses('serve', {}))
            record('gateway_refuses_owner_or_overprivileged_login', lambda: refuses('sail-gateway', gateway))

            def migrate_fails_closed():
                evidence = {}
                for name, change in (('no_runtime_role', {'AUTHZ_RUNTIME_ROLE': ''}),
                                     ('unknown_role', {'AUTHZ_RUNTIME_ROLE': 'authz_missing'}),
                                     ('role_is_migration_login', {'AUTHZ_RUNTIME_ROLE': 'authz_owner'}),
                                     ('unsafe_role_name', {'AUTHZ_RUNTIME_ROLE': 'x"; DROP TABLE authz_audit; --'}),
                                     ('runtime_login_cannot_migrate', {'AUTHZ_DATABASE_URL_FILE': str(root/'db-url')})):
                    result = command(str(BINARY), 'migrate', env=dict(migrate_env, **change), check=False)
                    evidence[name] = result.returncode
                    assert result.returncode != 0, f'migrate succeeded: {name}'
                assert int(sql("SELECT count(*) FROM pg_tables WHERE tablename LIKE 'authz_%'")) == 2
                return evidence
            record('migrate_fails_closed', migrate_fails_closed)

            def gateway_key():
                gateway_credential = (root/'gateway-key').read_text()
                evidence = {}
                for path, body in (('mutate', {'op': 'set_region', 'principal': 'oidc~alice', 'region': 'all'}), ('snapshot', {}),
                                   ('permissions', {'check': check('oidc~alice', table('t1'), 'manage_grants'), 'grant': None})):
                    status, _ = post(path, body, credential=gateway_credential)
                    evidence[path] = status
                    assert status in (401, 403), f'gateway key reached /{path}: {status}'
                status, groups = post('sail/groups', 'oidc~alice', credential=gateway_credential)
                assert status == 200 and groups == ['readers'], (status, groups)
                assert post('sail/groups', 'oidc~alice')[0] == 401, 'admin key accepted on the gateway route'
                assert post('decide', [check('oidc~bob', table('t2'))], credential=gateway_credential)[0] == 200
                evidence.update({'sail_groups': status, 'admin_on_sail_groups': 401})
                return evidence
            record('gateway_key_cannot_administer', gateway_key)

            def unknown_reason():
                status, _ = decide(check('oidc~ghost', table('t2')))
                reason = last_reason()
                assert status == 503 and reason == 'unknown_principal', (status, reason)
                return {'status': status, 'reason': reason}
            record('unknown_principal_reason_is_accurate', unknown_reason)
        finally:
            if service and service.poll() is None:
                service.terminate()
                service.wait(timeout=10)
            if postgres.poll() is None:
                postgres.send_signal(signal.SIGINT)
                postgres.wait(timeout=10)
            if server:
                server.shutdown()
                server.server_close()
            logfile.close()
    (OUT/'serve-harness.json').write_text(json.dumps({'binary': str(BINARY), 'cases': RESULTS}, indent=2) + '\n')
    failed = [k for k, v in RESULTS.items() if v['status'] != 'PASS']
    print(json.dumps({'passed': len(RESULTS) - len(failed), 'failed': failed}))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
