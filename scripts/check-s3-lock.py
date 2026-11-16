"""S3 dependency approval: same packages, versions, sources and checksums as S1."""
import subprocess
import tomllib
from pathlib import Path

BASE = '070522db03217da42a8fcbca590ef5c78ebc6c99'
before = tomllib.loads(subprocess.check_output(['git', 'show', BASE+':Cargo.lock'], text=True))
after = tomllib.loads(Path('Cargo.lock').read_text())
def inventory(lock):
    return {(p['name'], p['version'], p.get('source'), p.get('checksum')) for p in lock['package']}
added = inventory(after) - inventory(before)
removed = inventory(before) - inventory(after)
assert not added and not removed, dict(added=sorted(added), removed=sorted(removed))
# No other package's dependencies or metadata may change either.
old_packages = {p['name']+'@'+p['version']: p for p in before['package']}
for package in after['package']:
    if package['name'] != 'authz-serve':
        assert package == old_packages[package['name']+'@'+package['version']], package['name']
allowed = {'bytes', 'h2', 'http 1.5.0', 'jsonwebtoken 10.4.0', 'tokio-rustls'}
old = set(old_packages['authz-serve@0.0.1']['dependencies'])
new = set(next(p for p in after['package'] if p['name']=='authz-serve')['dependencies'])
assert new - old == allowed and not old-new, (new-old, old-new)
print(f'PASS: {len(inventory(after))} identical locked packages; only five approved direct dependency edges added')
