#!/usr/bin/env python3
"""Freeze the reviewed coordinator-approved slice-4a lock without exemptions."""
import hashlib
import json
import tomllib
from pathlib import Path

# SQLite removal reuses existing core/Postgres identities, changing only authz dependency edges.
# Reviewed Lakekeeper 0.13.9 / SQLx fork / Azure bump; full identity diff in
# docs/evals/slice-4a-lock-review.md. Axum-server 0.9.2 refresh approved 2026-11-27.
BASE = "24e0546b842503b3730b4554dc1128176d61aee2aa914ca387f888b34f3513ff"
lock = tomllib.loads(Path('Cargo.lock').read_text())
actual = hashlib.sha256(json.dumps(lock,sort_keys=True,separators=(',',':')).encode()).hexdigest()
assert actual == BASE, 'Additional Cargo.lock changes need coordinator approval'
print('Cargo.lock matches the reviewed coordinator-approved slice-4a baseline.')
