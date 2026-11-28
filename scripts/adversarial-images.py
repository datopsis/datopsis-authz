#!/usr/bin/env python3
"""Slice 4c adversarial review of the hardened images (native CI only).

Exports each built image's filesystem and asserts the REQUIRED secure state:
nothing the runtime identity (10001:0) can write outside temporary directories,
no set-id files, no private keys or credential-looking configuration baked in,
and no secrets in image config, labels or build history. Results go to
reports/s4c/images.json; any FAIL exits non-zero after every check has run.
"""
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path

IMAGES = ('authz', 'lakekeeper-authz')
UID, GID = 10001, 0
TEMPORARY = ('tmp/', 'var/tmp/')
SECRET_NAME = re.compile(r'(PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIAL|PRIVATE|API_?KEY|ENCRYPTION_KEY)', re.I)
PRIVATE_KEY = re.compile(rb'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----')
OUT = Path('reports/s4c')


def writable(member):
    mode = member.mode
    if member.issym() or member.islnk():
        return False
    return bool(mode & 0o002 or (member.uid == UID and mode & 0o200) or (member.gid == GID and mode & 0o020))


def inspect(image):
    findings = []
    obj = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image], text=True))[0]
    config = obj['Config']
    if config.get('User') != f'{UID}:{GID}':
        findings.append(f'runs as {config.get("User")!r}')
    for entry in config.get('Env') or []:
        name = entry.split('=', 1)[0]
        if SECRET_NAME.search(name):
            findings.append(f'secret-looking environment variable {name}')
    for name, value in (config.get('Labels') or {}).items():
        if SECRET_NAME.search(name) or PRIVATE_KEY.search(value.encode()):
            findings.append(f'secret-looking label {name}')
    history = subprocess.check_output(['docker', 'history', '--no-trunc', '--format', '{{.CreatedBy}}', image], text=True)
    for line in history.splitlines():
        if PRIVATE_KEY.search(line.encode()) or re.search(r'(PASSWORD|SECRET|TOKEN)=\S', line):
            findings.append('credential-looking build history entry: ' + line[:120])
    container = subprocess.check_output(['docker', 'create', image], text=True).strip()
    files = setid = 0
    write_paths, key_files = [], []
    try:
        export = subprocess.Popen(['docker', 'export', container], stdout=subprocess.PIPE)
        with tarfile.open(fileobj=export.stdout, mode='r|') as archive:
            for member in archive:
                files += 1
                name = member.name.lstrip('./')
                if member.mode & 0o6000 and member.isfile():
                    setid += 1
                    findings.append(f'set-id file /{name}')
                if writable(member) and not (name + '/').startswith(TEMPORARY) and name not in ('tmp', 'var/tmp'):
                    write_paths.append('/' + name)
                if member.isfile() and member.size < (1 << 20):
                    data = archive.extractfile(member).read()
                    if PRIVATE_KEY.search(data):
                        key_files.append('/' + name)
        if export.wait():
            findings.append('docker export failed')
    finally:
        subprocess.run(['docker', 'rm', container], check=True, stdout=subprocess.DEVNULL)
    findings += [f'writable by {UID}:{GID}: {p}' for p in write_paths[:50]]
    findings += [f'private key material baked in: {p}' for p in key_files]
    return {'image': image, 'id': obj['Id'], 'files_scanned': files, 'writable_paths': write_paths,
            'private_key_files': key_files, 'setid_files': setid, 'user': config.get('User'), 'findings': findings,
            'status': 'FAIL' if findings else 'PASS'}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    results = [inspect(f'localhost/{name}:s4a') for name in IMAGES]
    (OUT / 'images.json').write_text(json.dumps(results, indent=2) + '\n')
    for r in results:
        print(r['image'], r['status'], json.dumps(r['findings'][:20]))
    return 1 if any(r['status'] != 'PASS' for r in results) else 0


if __name__ == '__main__':
    sys.exit(main())
