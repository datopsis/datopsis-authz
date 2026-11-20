"""Pin-checked entry point; no edits to other repositories."""
import os
import json
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
# Override only immutable fixture inputs, not the pinned external checkout.
INPUTS = json.loads((ROOT/'evaluation/s1/inputs.json').read_text())
import rauthy
rauthy.REVISION = INPUTS['rauthy-ubi']['revision']
import acceptance
arch = {'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
assert arch == os.environ['INTEGRATION_ARCH']
if sys.argv[1:] == ['initialize']:
    acceptance.initialize(arch)
    common.save('fixture-inputs.json', INPUTS)
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
    sys.path.insert(0, str(SOURCE/'integration'))
    import build as owner
    owner.PINS['postgresql-lakekeeper-ubi'] = INPUTS['postgresql-lakekeeper-ubi']['revision']
    from fixture_inputs import seed_rauthy_feed
    from unittest.mock import patch
    original_run = rauthy.run
    def invoke_rauthy(*args, **kwargs):
        if args[:2] == ('bash', 'scripts/build.sh'):
            seed_rauthy_feed(kwargs['cwd'], ROOT/'.sources/fixture-inputs/fido-mds.jwt', arch)
        return original_run(*args, **kwargs)
    # Reuse only generated, checksum-verified input. No owner source is edited;
    # its original checksum, authenticated-feed and provenance checks still run.
    with patch.object(rauthy, 'run', invoke_rauthy):
        module.build()
    # Additional extension-free relationship-store image, with strict provenance.
    revision = INPUTS['postgresql-ubi']['revision']
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
