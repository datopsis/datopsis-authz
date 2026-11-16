"""Use Sail's supported Podman build path; preserve pinned owner verification."""
import importlib
import json
import os
import sys
from pathlib import Path

SAIL_PIN = 'e96e068f926b8fecb3939e953389685ee4780032'


def configure(integration, reports):
    sys.path.insert(0, str(integration/'integration'))
    owner = importlib.import_module('build')
    original = owner.run

    def invoke(args, **kwargs):
        source = Path(kwargs.get('cwd', '.'))
        if list(args) != ['bash', 'scripts/build.sh'] or source.name != 'sail-ubi':
            return original(args, **kwargs)
        assert owner.output(['git', '-C', str(source), 'rev-parse', 'HEAD']) == SAIL_PIN
        env = kwargs['env']
        assert env['CONTAINER_RUNTIME'] == 'docker'
        assert env['IMAGE'] == 'localhost/sail-ubi:integration'
        kwargs['env'] = dict(env, CONTAINER_RUNTIME='podman')
        result = original(args, **kwargs)
        archive = source.parent/'s3-sail-transfer.tar'
        try:
            original(['podman', 'save', '--format', 'docker-archive', '-o', str(archive), env['IMAGE']])
            original(['docker', 'load', '-i', str(archive)])
        finally:
            archive.unlink(missing_ok=True)
        reports.mkdir(parents=True, exist_ok=True)
        (reports/'sail-build-transport.json').write_text(json.dumps(dict(
            revision=SAIL_PIN, architecture=os.environ['INTEGRATION_ARCH'],
            build_runtime='podman', test_runtime='docker', image=env['IMAGE'],
            unchanged_source=not owner.output(['git', '-C', str(source), 'diff', 'HEAD'])
        ), indent=2)+'\n')
        # owner.build now performs its original Docker inspect, architecture,
        # revision, combined artifact-lock hash and clean-source assertions.
        return result

    owner.run = invoke
