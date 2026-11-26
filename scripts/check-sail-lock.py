#!/usr/bin/env python3
"""Only direct edges to already-resolved crates are approved for slice 3."""
import hashlib
import json
import tomllib
from pathlib import Path

# Semantic digest of slice 2 Cargo.lock at cdcdb9d79ce0936aa0bf968ef083f1b21521b421.
BASE = "8744967a8317ce0ded7f5fdd5402593b2849fdc1f96f53e0c03d17f6b98438d1"
lock = tomllib.loads(Path('Cargo.lock').read_text())
edges = {'bytes', 'h2', 'http 1.5.0', 'jsonwebtoken 10.4.0', 'tokio-rustls'}
package = next(p for p in lock['package'] if p['name']=='authz-serve')
assert edges <= set(package['dependencies'])
package['dependencies'] = [d for d in package['dependencies'] if d not in edges]
actual = hashlib.sha256(json.dumps(lock,sort_keys=True,separators=(',',':')).encode()).hexdigest()
assert actual == BASE, 'New Cargo.lock crates, versions or other changes need coordinator approval'
print('No new Cargo.lock crates or versions; only five existing dependency edges.')
