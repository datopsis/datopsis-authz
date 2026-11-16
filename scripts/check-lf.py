#!/usr/bin/env python3
"""Reject carriage returns in tracked text, or staged blobs at commit time."""
import subprocess
import sys

staged = '--staged' in sys.argv
args = ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACM', '-z'] if staged else ['git', 'ls-files', '-z']
failed = []
for name in subprocess.check_output(args).split(b'\0'):
    if not name:
        continue
    path = name.decode()
    data = subprocess.check_output(['git', 'show', ':' + path]) if staged else open(path, 'rb').read()
    if b'\0' not in data and b'\r' in data:
        failed.append(path)
if failed:
    sys.exit('CR/CRLF found: ' + ', '.join(failed))
