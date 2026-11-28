#!/usr/bin/env python3
"""Isolate authz metadata resolution; allow only a subset of the reviewed lock."""
import ast
import json
import re
from pathlib import Path
import shutil
import subprocess
import sys


def read_lock(path):
    # Cargo-generated v4 lock syntax only. UBI 9's Python 3.9 has no tomllib.
    # Reject unknown syntax instead of silently skipping integrity fields.
    blocks = path.read_text().split('[[package]]')
    header = '\n'.join(line for line in blocks[0].splitlines() if line and not line.startswith('#'))
    if header != 'version = 4':
        raise ValueError('Unexpected Cargo.lock header')
    packages = []
    for block in blocks[1:]:
        package = {}
        match = re.search(r'dependencies = (\[[^]]*\])', block)
        if match:
            edges = ast.literal_eval(match[1])
            if not isinstance(edges, list) or not all(isinstance(x, str) for x in edges):
                raise ValueError('Invalid lock dependency list')
            package['dependencies'] = edges
            block = block[:match.start()]+block[match.end():]
        for line in block.splitlines():
            if not line.strip():
                continue
            field = re.fullmatch(r'(name|version|source|checksum) = (".*")', line)
            if not field or field[1] in package:
                raise ValueError('Unexpected lock record: '+line)
            package[field[1]] = json.loads(field[2])
        if not package.get('name') or not package.get('version'):
            raise ValueError('Missing package identity')
        packages.append(package)
    if not packages:
        raise ValueError('Empty package lock')
    return {'package': packages}


def identity(package):
    return package['name'], package['version'], package.get('source', '')


def dependencies(package, packages):
    result = set()
    for edge in package.get('dependencies', []):
        parts = edge.split(' ', 2)
        matches = [identity(p) for p in packages if p['name'] == parts[0]
                   and (len(parts) < 2 or p['version'] == parts[1])
                   and (len(parts) < 3 or p.get('source', '') == parts[2].strip('()'))]
        if len(matches) != 1:
            raise ValueError('Ambiguous or missing lock dependency: '+edge)
        result.add(matches[0])
    return result


def verify_subset(original, isolated):
    reviewed = {identity(p): p for p in original['package']}
    for package in isolated['package']:
        key = identity(package)
        if key not in reviewed:
            raise ValueError('Isolated lock introduces an unreviewed package: '+str(key))
        before = reviewed[key]
        if {k:v for k,v in package.items() if k != 'dependencies'} != {k:v for k,v in before.items() if k != 'dependencies'}:
            raise ValueError('Isolated lock changes reviewed package data: '+str(key))
        if not dependencies(package, isolated['package']) <= dependencies(before, original['package']):
            raise ValueError('Isolated lock adds dependency edges: '+str(key))


def main():
    destination = Path(sys.argv[1])
    destination.mkdir()
    source = Path.cwd()
    manifest = (source/'Cargo.toml').read_text()
    expected = 'members = ["crates/*"]'
    if manifest.count(expected) != 1:
        raise ValueError('Unexpected workspace member declaration')
    (destination/'Cargo.toml').write_text(manifest.replace(expected,
        'members = ["crates/authz-core", "crates/authz-serve"]'))
    for name in ('Cargo.lock', 'rust-toolchain.toml'):
        shutil.copy2(source/name, destination/name)
    for name in ('.cargo', 'policies', 'migrations', 'crates/authz-core', 'crates/authz-serve'):
        shutil.copytree(source/name, destination/name)
    # Cargo must prune unreachable workspace entries once. Offline resolution may
    # remove entries/edges only; the verification below forbids new versions,
    # sources, checksums or edges before the locked production build runs.
    subprocess.run(['cargo', 'tree', '--offline', '-p', 'authz-serve', '--prefix', 'none'],
                   cwd=destination, check=True, stdout=subprocess.DEVNULL)
    original = read_lock(source/'Cargo.lock')
    isolated = read_lock(destination/'Cargo.lock')
    verify_subset(original, isolated)
    evidence = {'workspace_members': ['authz-core', 'authz-serve'],
                'source_packages': len(original['package']),
                'isolated_packages': len(isolated['package']),
                'new_packages_or_edges': False}
    (destination/'workspace-isolation.json').write_text(json.dumps(evidence, indent=2)+'\n')
    print(json.dumps(evidence))


if __name__ == '__main__':
    main()
