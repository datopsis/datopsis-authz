#!/usr/bin/env python3
"""Local TLS/PostgreSQL integration check; separate from native C1-C8."""
import getpass
import glob
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    pg_bin = Path(sorted(glob.glob('/usr/lib/postgresql/*/bin/postgres'))[-1]).parent
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        def command(*args, **kwargs):
            return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout
        command('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost')
        (root/'cert.pem').rename(root/'ca.pem')
        (root/'key.pem').rename(root/'ca-key.pem')
        command('openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(root/'key.pem'),'-out',str(root/'leaf.csr'),'-subj','/CN=localhost')
        (root/'extensions').write_text('basicConstraints=CA:FALSE\nsubjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n')
        command('openssl','x509','-req','-in',str(root/'leaf.csr'),'-CA',str(root/'ca.pem'),'-CAkey',str(root/'ca-key.pem'),'-CAcreateserial','-days','1','-extfile',str(root/'extensions'),'-out',str(root/'cert.pem'))
        for name in ('secret','db-password','reader-key','runtime-password'):
            (root/name).write_text(os.urandom(32).hex())
        command(str(pg_bin/'initdb'),'-D',str(root/'pg'),'--auth-local=trust','--auth-host=scram-sha-256','--pwfile',str(root/'db-password'))
        dbport, serviceport = port(), port()
        pgargs = [str(pg_bin/'postgres'),'-D',str(root/'pg'),'-p',str(dbport),'-k',str(root),'-h','127.0.0.1','-c','ssl=on','-c','ssl_cert_file='+str(root/'cert.pem'),'-c','ssl_key_file='+str(root/'key.pem')]
        dbenv = dict(os.environ, PGPASSWORD=(root/'db-password').read_text())
        def sql(statement):
            return command(str(pg_bin/'psql'),'-X','-h','localhost','-p',str(dbport),'-d','postgres','-At','-c',statement, env=dbenv).strip()
        logfile = (root/'postgres.log').open('w')
        postgres = subprocess.Popen(pgargs, stdout=logfile, stderr=logfile)
        service = None
        server = None
        try:
            for _ in range(100):
                try:
                    sql('SELECT 1'); break
                except subprocess.CalledProcessError: time.sleep(.1)
            else: raise AssertionError('PostgreSQL readiness failed')
            state = {'groups':['readers'],'outage':False}
            class Idp(BaseHTTPRequestHandler):
                def log_message(self, *_): pass
                def do_GET(self):
                    if self.headers.get('authorization') != (root/'reader-key').read_text():
                        self.send_error(401); return
                    if state['outage']:
                        self.send_error(503); return
                    body = json.dumps({'id':'alice','enabled':True,'groups':state['groups']}).encode()
                    self.send_response(200)
                    self.send_header('Content-Type','application/json')
                    self.send_header('Content-Length',str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
            server = ThreadingHTTPServer(('127.0.0.1',0),Idp)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(root/'cert.pem',root/'key.pem')
            server.socket = ctx.wrap_socket(server.socket,server_side=True)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            url = f'postgres://{getpass.getuser()}:{(root/"db-password").read_text()}@localhost:{dbport}/postgres?sslmode=verify-full'
            (root/'db-url').write_text(url)
            # Owner login migrates; serve runs as a separate least-privilege login.
            sql("CREATE ROLE authz_runtime LOGIN PASSWORD '"+(root/'runtime-password').read_text()+"'")
            (root/'runtime-url').write_text(f'postgres://authz_runtime:{(root/"runtime-password").read_text()}@localhost:{dbport}/postgres?sslmode=verify-full')
            owner_env = dict(os.environ,AUTHZ_DATABASE_URL_FILE=str(root/'db-url'),AUTHZ_DATABASE_CA_FILE=str(root/'ca.pem'),AUTHZ_RUNTIME_ROLE='authz_runtime')
            env = dict(os.environ,AUTHZ_LISTEN=f'127.0.0.1:{serviceport}',AUTHZ_TLS_CERT=str(root/'cert.pem'),AUTHZ_TLS_KEY=str(root/'key.pem'),AUTHZ_KEY_FILE=str(root/'secret'),AUTHZ_DATABASE_URL_FILE=str(root/'runtime-url'),AUTHZ_DATABASE_CA_FILE=str(root/'ca.pem'),AUTHZ_RAUTHY_USERS_URL=f'https://localhost:{server.server_port}/auth/v1/users',AUTHZ_RAUTHY_CA_FILE=str(root/'ca.pem'),AUTHZ_RAUTHY_KEY_FILE=str(root/'reader-key'))
            # verify-full must reject both an unknown CA and a wrong hostname.
            command('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'other-key.pem'),'-out',str(root/'other.pem'),'-days','1','-subj','/CN=unknown')
            invalid = [dict(owner_env,AUTHZ_DATABASE_CA_FILE=str(root/'other.pem'))]
            (root/'wrong-url').write_text(url.replace('@localhost:', '@127.0.0.1:'))
            invalid.append(dict(owner_env,AUTHZ_DATABASE_URL_FILE=str(root/'wrong-url')))
            for bad_env in invalid:
                result = subprocess.run(['target/debug/authz-serve','migrate'],env=bad_env,capture_output=True,timeout=15)
                assert result.returncode != 0, 'PostgreSQL TLS downgrade accepted'
            client_ctx = ssl.create_default_context(cafile=str(root/'ca.pem'))
            def post(path, body, context=client_ctx, key=True):
                request = urllib.request.Request(f'https://localhost:{serviceport}/{path}',data=json.dumps(body).encode(),headers={'Content-Type':'application/json',**({'Authorization':'Bearer '+(root/'secret').read_text()} if key else {})})
                with urllib.request.urlopen(request,context=context,timeout=10) as response:
                    data = response.read()
                    return json.loads(data) if data else None
            def start():
                nonlocal service
                service = subprocess.Popen(['target/debug/authz-serve','serve'],env=env,stdout=subprocess.DEVNULL)
                for _ in range(100):
                    if service.poll() is not None: raise AssertionError('Service exited')
                    try: post('decide',[]); return
                    except (urllib.error.URLError,ConnectionError): time.sleep(.1)
                raise AssertionError('Service readiness failed')
            def denied_status(fn, status):
                try: fn()
                except urllib.error.HTTPError as exc: assert exc.code == status, exc.code
                else: raise AssertionError('Expected HTTP rejection')
            command('target/debug/authz-serve','migrate',env=owner_env)
            start()
            check = {'principal':'oidc~alice','groups':['forged'],'action':'read_data','resource':{'kind':'Table','id':'one'}}
            try:
                assert post('decide',[check])[0]['allowed'] is False
            except urllib.error.HTTPError as exc:
                raise AssertionError(sql('SELECT reason FROM authz_audit ORDER BY id DESC LIMIT 1')) from exc
            grant = {'subject':{'kind':'Group','id':'readers'},'resource':check['resource'],'access':'select'}
            post('mutate',{'op':'grant','grant':grant,'remove':False})
            assert post('decide',[check])[0]['allowed'] is True
            state['groups'] = []
            time.sleep(.3)
            assert post('decide',[check])[0]['allowed'] is False
            state['groups'] = ['readers']
            time.sleep(.3)
            assert post('decide',[check])[0]['allowed'] is True
            before = post('snapshot',{})
            service.terminate(); service.wait(timeout=10); start()
            assert post('snapshot',{}) == before
            for _ in range(2): command('target/debug/authz-serve','migrate',env=owner_env)
            assert post('snapshot',{}) == before
            assert post('decide',[check])[0]['allowed'] is True
            state['outage'] = True
            time.sleep(.3)
            denied_status(lambda:post('decide',[check]),503)
            assert sql("SELECT reason FROM authz_audit ORDER BY id DESC LIMIT 1") == 'identity_provider_unavailable'
            state['outage'] = False
            assert post('decide',[check])[0]['allowed'] is True
            postgres.send_signal(signal.SIGINT); postgres.wait(timeout=10)
            denied_status(lambda:post('decide',[check]),503)
            postgres = subprocess.Popen(pgargs,stdout=logfile,stderr=logfile)
            for _ in range(100):
                try:
                    if post('decide',[check])[0]['allowed']: break
                except (urllib.error.HTTPError,urllib.error.URLError): pass
                time.sleep(.1)
            else: raise AssertionError('Database recovery failed')
            # Invalid management mutations must retain their authorization audit.
            owner = {'subject':{'kind':'User','id':'oidc~alice'},'resource':check['resource'],'access':'owner'}
            post('mutate',{'op':'grant','grant':owner,'remove':False})
            snapshot = post('snapshot',{})
            for invalid_grant in ({**grant,'access':'unsupported'}, {**grant,'resource':{'kind':'Table','id':'other'}}):
                count = int(sql('SELECT count(*) FROM authz_audit'))
                denied_status(lambda:post('permissions',{'check':check,'grant':invalid_grant}),400)
                assert int(sql('SELECT count(*) FROM authz_audit')) == count + 1
                assert sql("SELECT reason FROM authz_audit ORDER BY id DESC LIMIT 1") == 'grant_management_permit'
                assert post('snapshot',{}) == snapshot
            # A corrupt persisted graph must audit the evaluation failure and deny.
            corrupt = {'parents':{'invalid':[{'kind':'Invalid!','id':'bad'},None]},'grants':snapshot['grants']}
            sql("UPDATE authz_state SET graph='"+json.dumps(corrupt)+"'::jsonb WHERE singleton")
            try:
                count = int(sql('SELECT count(*) FROM authz_audit'))
                denied_status(lambda:post('permissions',{'check':check,'grant':None}),503)
                assert int(sql('SELECT count(*) FROM authz_audit')) == count + 1
                assert sql("SELECT reason FROM authz_audit ORDER BY id DESC LIMIT 1") == 'evaluation_error'
                assert sql("SELECT decision::text FROM authz_audit ORDER BY id DESC LIMIT 1") == 'false'
            finally:
                sql("UPDATE authz_state SET graph='"+json.dumps(snapshot)+"'::jsonb WHERE singleton")
            for operation in ('UPDATE authz_audit SET reason=reason','DELETE FROM authz_audit','TRUNCATE authz_audit'):
                try: sql(operation)
                except subprocess.CalledProcessError: pass
                else: raise AssertionError('Audit mutation accepted')
            assert int(sql('SELECT count(*) FROM authz_audit')) >= 7
            denied_status(lambda:post('decide',[],key=False),401)
            try: post('decide',[],context=ssl.create_default_context())
            except urllib.error.URLError: pass
            else: raise AssertionError('Unknown service CA accepted')
            print('PASS: verified TLS, durable grants/audit, restart, repeated migrations, live removal, IdP/database outage and recovery (not C1-C8)')
        finally:
            if service and service.poll() is None:
                service.terminate(); service.wait(timeout=10)
            if postgres.poll() is None:
                postgres.send_signal(signal.SIGINT); postgres.wait(timeout=10)
            if server: server.shutdown(); server.server_close()
            logfile.close()

if __name__ == '__main__': main()
