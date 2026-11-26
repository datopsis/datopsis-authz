#!/usr/bin/env python3
"""Only direct edges to already-resolved crates are approved for slice 3."""
import hashlib
import json
import tomllib
from pathlib import Path

# Semantic digest of slice 2 Cargo.lock at 504995adeacc9b403913bbf71bbec5c90dbb78be.
BASE = "ea6d6ca37de2ac16e79358aa5c502cfff7ac7fbb30f98636ffcfe1aa4994cab7"
lock = tomllib.loads(Path('Cargo.lock').read_text())
edges = {'bytes', 'h2', 'http 1.5.0', 'jsonwebtoken 10.4.0', 'tokio-rustls'}
package = next(p for p in lock['package'] if p['name']=='authz-serve')
assert edges <= set(package['dependencies'])
package['dependencies'] = [d for d in package['dependencies'] if d not in edges]
actual = hashlib.sha256(json.dumps(lock,sort_keys=True,separators=(',',':')).encode()).hexdigest()
assert actual == BASE, 'New Cargo.lock crates, versions or other changes need coordinator approval'
print('No new Cargo.lock crates or versions; only five existing dependency edges.')
