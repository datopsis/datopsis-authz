#!/usr/bin/env python3
"""Compose an official, digest-locked OPA plugin over the unmodified owner image."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request
import zipfile

URL = 'https://github.com/trinodb/trino/releases/download/484/trino-opa-484.zip'
SHA256 = 'f8627b3f2da8950e8209ddcf8fd436cc0e536459dd438c81261593ab8310dc24'
SIZE = 15384527
BASE = 'localhost/trino-ubi:integration'
IMAGE = 'localhost/trino-opa:s2'
ROOT = Path(__file__).resolve().parents[1]


def main():
    context = ROOT / 'target/s2-trino-image'
    if context.exists():
        shutil.rmtree(context)
    plugin = context / 'plugin'
    plugin.mkdir(parents=True)
    with urllib.request.urlopen(URL, timeout=120) as response:
        assert response.url.startswith('https://')
        data = response.read(SIZE + 1)
    assert len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA256
    jars = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for member in archive.infolist():
            path = Path(member.filename)
            assert len(path.parts) == 2 and path.parts[0] == 'trino-opa-484'
            assert path.name.endswith('.jar') and not member.is_dir()
            assert (member.external_attr >> 16) & 0o170000 != 0o120000
            assert path.name not in jars
            content = archive.read(member)
            (plugin / path.name).write_bytes(content)
            (plugin / path.name).chmod(0o444)
            jars[path.name] = hashlib.sha256(content).hexdigest()
    assert 'trino-opa-484.jar' in jars and len(jars) == 62
    (context / 'Containerfile').write_text(
        'FROM '+BASE+'\nCOPY --chown=0:0 plugin/ /opt/trino/plugin/opa/\n'
        'ARG SOURCE_REVISION\nLABEL org.opencontainers.image.source="https://github.com/datopsis/datopsis-authz" '
        'org.opencontainers.image.revision="$SOURCE_REVISION" '
        'io.datopsis.s2.opa-zip.sha256="'+SHA256+'"\n')
    if sys.argv[1:] == ['--prepare-only']:
        print('OPA 484: verified ZIP SHA-256, size, safe layout and 62 JARs')
        return
    def docker(*args):
        return subprocess.check_output(['docker',*args],text=True).strip()
    base = json.loads(docker('image','inspect',BASE))[0]
    assert base['Architecture'] == os.environ['INTEGRATION_ARCH']
    assert base['Config']['Labels']['org.opencontainers.image.revision'] == '685ff5bca0037d38e3c2e2ed47a60f2540dad7c2'
    # Actual runtime inventory of the unmodified pin, not just the lockfile claim.
    docker('run','--rm','--entrypoint','/bin/bash',BASE,'-c','test ! -d /opt/trino/plugin/opa && test -d /opt/trino/plugin/iceberg')
    print('Unmodified trino-ubi pin: OPA unavailable (FAIL); Iceberg present', flush=True)
    subprocess.run(['docker','build','-f',str(context / 'Containerfile'),'--build-arg','SOURCE_REVISION='+os.environ['GITHUB_SHA'],'-t',IMAGE,str(context)],check=True)
    derived = json.loads(docker('image','inspect',IMAGE))[0]
    assert derived['Architecture'] == base['Architecture']
    assert derived['Config']['Labels']['io.datopsis.s2.opa-zip.sha256'] == SHA256
    docker('run','--rm','--entrypoint','/bin/bash',IMAGE,'-c','test -r /opt/trino/plugin/opa/trino-opa-484.jar && test -d /opt/trino/plugin/iceberg')
    evidence = {'base_revision':'685ff5bca0037d38e3c2e2ed47a60f2540dad7c2',
        'architecture':base['Architecture'],'base_image_id':base['Id'],'base_opa_available':False,
        'image_id':derived['Id'],'labels':derived['Config']['Labels'],
        'zip_url':URL,'zip_sha256':SHA256,'zip_size':SIZE,'jars':jars}
    out = ROOT / 'reports/s2'
    out.mkdir(parents=True,exist_ok=True)
    (out / 'trino-composition.json').write_text(json.dumps(evidence,indent=2)+'\n')


if __name__ == '__main__':
    main()
