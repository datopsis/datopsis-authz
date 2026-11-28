"""CI-only reuse of exact owner-locked FIDO bytes; owner authentication still runs."""
import hashlib
import json
from pathlib import Path
import shutil
import time
import urllib.error
import urllib.request
from email.utils import parsedate_to_datetime


def verified_bytes(path, item):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != item['sha256']:
        raise ValueError('FIDO bytes do not match the immutable owner lock')
    return data


def download_locked(item, cache, *, open_url=urllib.request.urlopen, sleep=time.sleep):
    cache = Path(cache)
    if cache.exists():
        verified_bytes(cache, item)
        return cache
    for attempt in range(4):
        try:
            with open_url(item['url'], timeout=30) as response:
                data = response.read()
            break
        except urllib.error.HTTPError as error:
            if error.code != 429 or attempt == 3:
                raise
            retry = error.headers.get('Retry-After', '60')
            try:
                delay = float(retry)
            except ValueError:
                delay = parsedate_to_datetime(retry).timestamp() - time.time()
            delay = max(60, delay)
            if delay > 120:
                raise  # Never retry earlier than requested, or wait without bound.
            print(f'FIDO publisher rate limited; retrying in {delay:g}s ({attempt+1}/3)', flush=True)
            sleep(delay)
    if hashlib.sha256(data).hexdigest() != item['sha256']:
        raise ValueError('FIDO download differs from the immutable owner lock')
    cache.parent.mkdir(parents=True, exist_ok=True)
    temporary = cache.with_suffix('.tmp')
    temporary.write_bytes(data)
    temporary.replace(cache)
    return cache


def seed_rauthy_feed(source, cache, arch):
    source = Path(source)
    lock = json.loads((source/f'artifacts/locks/{arch}.json').read_text())
    item = lock['downloads']['fido-mds']
    if Path(item['filename']).name != item['filename']:
        raise ValueError('Invalid owner feed filename')
    verified_bytes(cache, item)
    destination = source/'.artifact-bundle'/item['filename']
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(cache, destination)
    # scripts/build.sh still hashes this file, fetches fresh CRLs and verifies
    # the feed's signature/path/serial/dates before consuming the bundle.
