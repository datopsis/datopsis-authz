#!/usr/bin/env python3
"""Freeze the reviewed coordinator-approved slice-4a lock without exemptions."""
import hashlib
import json
import tomllib
from pathlib import Path

# Reviewed Lakekeeper 0.13.9 / SQLx fork / Azure bump; full identity diff in
# docs/evals/slice-4a-lock-review.md. Axum-server 0.9.2 refresh approved 2026-11-27.
BASE = "02ac64278cdea8367c5fa49f2f519e748a71c3e4bee7d0d4fd8ca551528944f0"
lock = tomllib.loads(Path('Cargo.lock').read_text())
actual = hashlib.sha256(json.dumps(lock,sort_keys=True,separators=(',',':')).encode()).hexdigest()
assert actual == BASE, 'Additional Cargo.lock changes need coordinator approval'
print('Cargo.lock matches the reviewed coordinator-approved slice-4a baseline.')
