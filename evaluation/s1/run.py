"""Pin-checked entry point; no edits to other repositories."""
import os
import platform
import subprocess
import sys
from pathlib import Path

PIN = 'e8379a528bf413c05aad49e56bc8cd507b5e077a'
ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / '.sources/lakehouse-integration'
assert subprocess.check_output(['git','-C',str(SOURCE),'rev-parse','HEAD'],text=True).strip() == PIN
# Local S1 modules precede pinned fixture helpers.
sys.path.extend([str(SOURCE/'evaluation/authz'),str(SOURCE/'evaluation/idp')])
import common
common.OUT = ROOT/'reports/s1'
import acceptance
arch = {'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
assert arch == os.environ['INTEGRATION_ARCH']
if sys.argv[1:] == ['initialize']:
    acceptance.initialize(arch)
elif sys.argv[1:] == ['cleanup']:
    common.cleanup()
    networks = common.run('docker','network','ls','-q','--filter','name=^authz-backend$').split()
    for network in networks:
        common.run('docker','network','rm',network)
elif sys.argv[1:] == ['build']:
    # importlib avoids this entry point's filename collision.
    import importlib.util
    spec = importlib.util.spec_from_file_location('upstream_run',SOURCE/'evaluation/authz/run.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # The imported entry point sets its own output directory. Keep its data
    # in this repository’s allowlisted, subsequently sanitized evidence tree.
    common.OUT = ROOT/'reports/s1'
    # Build the additional extension-free relationship-store image at the reviewed pin.
    module.build()
    import build as owner
    import json
    revision = 'c31b5b8f53873c0e733d5271df45fba4643a4334'
    source = ROOT/'.sources/postgresql-ubi'
    common.run('git','clone','https://github.com/datopsis/postgresql-ubi',source)
    common.run('git','-C',source,'checkout','--detach',revision)
    common.run('bash','scripts/build-offline.sh',cwd=source,
        env=dict(os.environ,CONTAINER_RUNTIME='docker',IMAGE='localhost/postgresql-ubi:integration',RELEASE_REVISION=revision))
    obj = json.loads(common.run('docker','image','inspect','localhost/postgresql-ubi:integration'))[0]
    lock = source/f'artifacts/locks/{arch}.json'
    assert not owner.provenance_errors(obj,revision,owner.sha(lock),arch)
    assert not common.run('git','-C',source,'status','--porcelain')
    common.save('relationship-database-image.json', {'revision':revision,'lock_sha256':owner.sha(lock),'architecture':obj['Architecture'],'labels':obj['Config']['Labels']})
else:
    acceptance.evaluate(arch)
