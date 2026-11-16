#!/usr/bin/env python3
"""Real HTTPS proof, per-run CA/key; deliberately distinct from C1-C8."""
import json
import os
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def main():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        def command(*args):
            subprocess.run(args, cwd=root, check=True, capture_output=True)
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'key.pem', '-out', 'cert.pem', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
        (root / 'secret').write_text(os.urandom(32).hex())
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        env = dict(os.environ, AUTHZ_LISTEN=f'127.0.0.1:{port}', AUTHZ_TLS_CERT=str(root/'cert.pem'), AUTHZ_TLS_KEY=str(root/'key.pem'), AUTHZ_KEY_FILE=str(root/'secret'))
        proc = subprocess.Popen(['target/debug/authz-serve', 'serve'], env=env, stdout=subprocess.DEVNULL)
        try:
            ctx = ssl.create_default_context(cafile=str(root/'cert.pem'))
            def post(path, body, context=ctx, key=True):
                req = urllib.request.Request(f'https://localhost:{port}/{path}', data=json.dumps(body).encode(), headers={'Content-Type':'application/json', **({'Authorization':'Bearer '+(root/'secret').read_text()} if key else {})})
                return urllib.request.urlopen(req, context=context, timeout=3)
            for _ in range(100):
                if proc.poll() is not None:
                    raise AssertionError('service exited')
                try:
                    post('decide', [])
                    break
                except (urllib.error.URLError, ConnectionError):
                    time.sleep(.1)
            else:
                raise AssertionError('service readiness timeout')
            check = {'principal':'alice','groups':['readers'],'action':'read_data','resource':{'kind':'Table','id':'one'}}
            assert json.load(post('decide',[check]))[0]['allowed'] is False
            grant={'subject':{'kind':'Group','id':'readers'},'resource':check['resource'],'access':'select'}
            post('mutate',{'op':'grant','grant':grant,'remove':False})
            assert json.load(post('decide',[check]))[0]['allowed'] is True
            post('mutate',{'op':'grant','grant':grant,'remove':True})
            assert json.load(post('decide',[check]))[0]['allowed'] is False
            try:
                post('decide',[],key=False)
            except urllib.error.HTTPError as exc:
                assert exc.code == 401
            else:
                raise AssertionError('anonymous adapter accepted')
            try:
                post('decide',[],context=ssl.create_default_context())
            except urllib.error.URLError as exc:
                assert isinstance(exc.reason, ssl.SSLCertVerificationError)
            else:
                raise AssertionError('untrusted CA accepted')
            print('HTTPS: verified CA, unauthorized request, direct groups, grant and revoke PASS (not C1-C8)')
        finally:
            proc.terminate()
            proc.wait(timeout=10)

if __name__ == '__main__':
    main()
