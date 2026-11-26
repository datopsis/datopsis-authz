#!/usr/bin/env python3
"""Freeze the reviewed coordinator-approved slice-4a lock without exemptions."""
import hashlib
import json
import tomllib
from pathlib import Path

# Reviewed Lakekeeper 0.13.9 / SQLx fork / Azure bump; full identity diff in
# docs/evals/slice-4a-lock-review.md. Existing transport edges only.
BASE = "92b401eba4a7183475c1e208af77ba22d69733a727178611653eefcc631e19f3"
lock = tomllib.loads(Path('Cargo.lock').read_text())
actual = hashlib.sha256(json.dumps(lock,sort_keys=True,separators=(',',':')).encode()).hexdigest()
assert actual == BASE, 'Additional Cargo.lock changes need coordinator approval'
print('Cargo.lock matches the reviewed coordinator-approved slice-4a baseline.')
