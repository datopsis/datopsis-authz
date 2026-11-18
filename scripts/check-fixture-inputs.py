#!/usr/bin/env python3
"""Fail early on unavailable immutable fixture inputs. Never replace locked bytes."""
import hashlib
import json
import os
import urllib.error
import urllib.request

RAUTHY = '1e114b84b01988bf15306b110b040378878488d3'
arch = os.environ['INTEGRATION_ARCH']
assert arch in ('amd64', 'arm64')
url = f'https://raw.githubusercontent.com/datopsis/rauthy-ubi/{RAUTHY}/artifacts/locks/{arch}.json'
with urllib.request.urlopen(url, timeout=30) as response:
    item = json.load(response)['downloads']['fido-mds']
try:
    with urllib.request.urlopen(item['url'], timeout=30) as response:
        actual = hashlib.sha256(response.read()).hexdigest()
except (urllib.error.URLError, TimeoutError) as error:
    raise SystemExit(f'BLOCKED: immutable Rauthy FIDO fixture input unavailable: {error}') from error
assert actual == item['sha256'], (
    'BLOCKED: Rauthy FIDO metadata differs from its immutable owner lock; '
    f"expected {item['sha256']}, got {actual}. An updated owner pin or exact locked blob is required."
)
print('Locked Rauthy FIDO metadata available; original image build must verify it again.')
