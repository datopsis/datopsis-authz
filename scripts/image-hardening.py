#!/usr/bin/env python3
"""Native CI checks against the actual images; failures are blocking."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path('reports/images')
root.mkdir(parents=True, exist_ok=True)
revision = os.environ['SOURCE_REVISION']
arch = os.environ['INTEGRATION_ARCH']
lock_sha = hashlib.sha256(Path('artifacts/images.lock.json').read_bytes()).hexdigest()
flags = ['--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--network=none']

def run(image, role, ok=False, env=()):
    command = ['docker','run','--rm',*flags,*env,f'localhost/{image}:s4a',role]
    result = subprocess.run(command, text=True, capture_output=True, timeout=30)
    assert (result.returncode == 0) == ok, (image, role, result.returncode, result.stderr)
    return {'role':role,'exit_code':result.returncode,'expected_success':ok}

for name, binary in [('authz','datopsis-authz'),('lakekeeper-authz','lakekeeper-datopsis')]:
    image = f'localhost/{name}:s4a'
    obj = json.loads(subprocess.check_output(['docker','image','inspect',image],text=True))[0]
    assert obj['Architecture'] == arch
    assert obj['Config']['User'] == '10001:0'
    labels = obj['Config']['Labels']
    assert labels['org.opencontainers.image.revision'] == revision
    assert labels['io.datopsis.artifact-lock.sha256'] == lock_sha
    status = subprocess.check_output(['docker','run','--rm',*flags,'--entrypoint','/bin/bash',image,
        '-c','id -u; cat /proc/self/status; if touch /tmp/write-probe 2>/dev/null; then exit 1; fi'],text=True)
    assert status.splitlines()[0] == '10001'
    assert 'CapEff:\t0000000000000000' in status
    assert 'CapPrm:\t0000000000000000' in status
    assert 'CapBnd:\t0000000000000000' in status
    assert 'CapInh:\t0000000000000000' in status
    assert 'CapAmb:\t0000000000000000' in status
    assert 'NoNewPrivs:\t1' in status
    if name == 'authz':
        roles = [run(name,'policy',True)]
        roles += [run(name,r) for r in ['serve','sail-gateway','token-broker','unknown-role']]
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory)/'key'
            secret.write_text(os.urandom(32).hex())
            secret.chmod(0o444)
            roles += [run(name,r,env=['-v',f'{secret}:/run/key:ro',
                                     '-e','AUTHZ_KEY_FILE=/run/key',
                                     '-e','AUTHZ_TLS_CERT=/missing','-e','AUTHZ_TLS_KEY=/missing'])
                      for r in ['serve','sail-gateway']]
    else:
        roles = [run(name,'version',True),run(name,'migrate'),run(name,'serve')]
        roles += [run(name,'serve',env=['-e','LAKEKEEPER__PG_ENCRYPTION_KEY='+'x'*32,
                                     '-e','AUTHZ_TLS_CERT=/missing','-e','AUTHZ_TLS_KEY=/missing'])]
    directory = root/name
    directory.mkdir(exist_ok=True)
    container = subprocess.check_output(['docker','create',image],text=True).strip()
    try:
        subprocess.run(['docker','cp',f'{container}:/usr/local/bin/{binary}',str(directory/'binary')],check=True)
    finally:
        subprocess.run(['docker','rm',container],check=True,stdout=subprocess.DEVNULL)
    # Retain a host executable for the existing CI-only TLS/PostgreSQL smoke.
    if name == 'authz':
        import shutil
        Path('target/debug').mkdir(parents=True,exist_ok=True)
        shutil.copyfile(directory/'binary','target/debug/authz-serve')
        Path('target/debug/authz-serve').chmod(0o755)
    evidence = {'architecture':arch,'revision':revision,'artifact_lock_sha256':lock_sha,
                'image_id':obj['Id'],'size_bytes':obj['Size'], 'roles':roles,
                'nonroot':True,'read_only_root':True,'no_capabilities':True,'no_new_privileges':True,
                'binary_sha256':hashlib.sha256((directory/'binary').read_bytes()).hexdigest()}
    (directory/'build-hardening.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print(name, json.dumps(evidence))
