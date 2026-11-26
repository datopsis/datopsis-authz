#!/usr/bin/env python3
"""CI-only acquisition of the pinned native compiler and RPM closures."""
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.request

arch = sys.argv[1]
lock_path = Path('artifacts/images.lock.json')
lock = json.loads(lock_path.read_text())['architectures'][arch]
root = Path('.image-bundle')
root.mkdir(exist_ok=True)
checks = []
for section, items in [('rpms', lock['packages']), ('build-rpms', lock['build_packages']),
                       ('tools', list(lock['downloads'].values()))]:
    for item in items:
        assert re.fullmatch('[0-9a-f]{64}', item['sha256'])
        assert item['url'].startswith('https://')
        assert Path(item['filename']).name == item['filename']
        path = root/section/item['filename']
        path.parent.mkdir(exist_ok=True)
        if not path.exists():
            with urllib.request.urlopen(item['url'], timeout=120) as source, path.open('wb') as dest:
                while chunk := source.read(1024*1024):
                    dest.write(chunk)
        assert hashlib.file_digest(path.open('rb'), 'sha256').hexdigest() == item['sha256'], path
        checks.append(f"{item['sha256']}  {path.relative_to(root)}")
    if section != 'tools':
        (root/f'{section}.nevras').write_text('\n'.join(sorted(p['nevra'] for p in items))+'\n')
(root/'SHA256SUMS').write_text('\n'.join(checks)+'\n')
# Docker build arguments come only from this architecture's reviewed lock.
(root/'build.env').write_text('\n'.join(f'{k.upper()}={v}' for k,v in lock['baseImages'].items())+'\n')
