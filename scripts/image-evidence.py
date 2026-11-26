#!/usr/bin/env python3
"""Record custom artifacts separately from their verified owner-built base."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

arch = os.environ['INTEGRATION_ARCH']
revision = os.environ['GITHUB_SHA']
evidence = {'architecture': arch, 'revision': revision, 'cargo_lock_sha256': hashlib.sha256(Path('Cargo.lock').read_bytes()).hexdigest(), 'images': {}}
for image, binary in [('localhost/lakekeeper-datopsis:s1', 'lakekeeper-bin-datopsis'), ('localhost/authz-serve:s1', 'authz-serve')]:
    obj = json.loads(subprocess.check_output(['docker','image','inspect',image],text=True))[0]
    assert obj['Architecture'] == arch
    assert obj['Config']['Labels']['org.opencontainers.image.revision'] == revision
    assert obj['Config']['Labels']['io.datopsis.artifact-lock.sha256'] == evidence['cargo_lock_sha256']
    evidence['images'][image] = {'image_id': obj['Id'], 'architecture': obj['Architecture'], 'binary_sha256': hashlib.sha256((Path('target/debug')/binary).read_bytes()).hexdigest()}
evidence['ubi_runtime_libraries'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('target/spike-libs').iterdir() if p.is_file()}
Path('reports/s1').mkdir(parents=True,exist_ok=True)
Path('reports/s1/spike-builds.json').write_text(json.dumps(evidence,indent=2)+'\n')
