#!/usr/bin/env python3
"""Collect the UBI build's non-glibc shared libraries, including transitive needs."""
import re
import shutil
import subprocess
import sys
from pathlib import Path

binary, destination = map(Path, sys.argv[1:])
# Already supplied by the pinned UBI Micro base and used by the upstream binary.
base = {'libc.so.6', 'libm.so.6', 'libdl.so.2', 'libpthread.so.0', 'librt.so.1', 'libgcc_s.so.1'}
output = subprocess.check_output(['ldd', str(binary)], text=True)
assert 'not found' not in output, output
destination.mkdir(parents=True, exist_ok=True)
for filename in re.findall(r'=> (/\S+)', output):
    path = Path(filename)
    if path.name not in base:
        shutil.copyfile(path, destination / path.name)
print('Additional UBI runtime libraries: ' + ', '.join(sorted(p.name for p in destination.iterdir())))
