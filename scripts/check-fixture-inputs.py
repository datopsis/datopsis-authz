#!/usr/bin/env python3
"""Fail early on unavailable immutable fixture inputs. Never replace locked bytes."""
import json
import os
from pathlib import Path
import urllib.error
import urllib.request
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'evaluation/s1'))
from fixture_inputs import download_locked
inputs = json.loads((ROOT/'evaluation/s1/inputs.json').read_text())
RAUTHY = inputs['rauthy-ubi']['revision']
arch = os.environ['INTEGRATION_ARCH']
assert arch in ('amd64', 'arm64')
url = f'https://raw.githubusercontent.com/datopsis/rauthy-ubi/{RAUTHY}/artifacts/locks/{arch}.json'
with urllib.request.urlopen(url, timeout=30) as response:
    item = json.load(response)['downloads']['fido-mds']
try:
    download_locked(item, ROOT/'.sources/fixture-inputs/fido-mds.jwt')
except (urllib.error.URLError, TimeoutError, ValueError) as error:
    raise SystemExit(f'BLOCKED: immutable Rauthy FIDO fixture input unavailable: {error}') from error
print('Locked Rauthy FIDO metadata available; original image build must verify it again.')
