#!/usr/bin/env python3
"""Gate every RustSec advisory against cargo-auditable data in the shipped ELFs."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib


def inventory(path):
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Expected native little-endian ELF64')
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, strings = struct.unpack_from('<HHH', data, 58)
    if size != 64 or not 0 < strings < count:
        raise ValueError('Invalid ELF section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset+i*size) for i in range(count)]
    table = sections[strings]
    names = data[table[4]:table[4]+table[5]]
    matches = [s for s in sections if names[s[0]:].split(b'\0', 1)[0] == b'.dep-v0']
    if len(matches) != 1:
        raise ValueError('Missing/duplicate cargo-auditable section')
    s = matches[0]
    obj = json.loads(zlib.decompress(data[s[4]:s[4]+s[5]]))
    packages = obj['packages']
    if not packages or not all(p.get('name') and p.get('version') for p in packages):
        raise ValueError('Empty/invalid cargo-auditable inventory')
    if obj.get('format', 0) < 2:
        raise ValueError('Inventory must distinguish proc-macros from shipped runtime code')
    if sum(bool(p.get('root')) for p in packages) != 1:
        raise ValueError('Inventory must identify exactly one root binary')
    if any(p.get('kind', 'runtime') not in ('runtime', 'build') for p in packages):
        raise ValueError('Unknown cargo-auditable dependency kind')
    return obj


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory-only', action='store_true')
    args = parser.parse_args()
    root = Path('reports/images')
    if args.inventory_only:
        for name in ['authz', 'lakekeeper-authz']:
            directory = root/name
            metadata = inventory(directory/'binary')
            (directory/'cargo-auditable.json').write_text(json.dumps(metadata,indent=2)+'\n')
            print(name, 'validated cargo-auditable format', metadata['format'])
        return 0
    result = subprocess.run(['cargo', 'audit', '--json', '--file', 'Cargo.lock'], capture_output=True, text=True)
    if result.returncode not in (0, 1):
        raise RuntimeError('RustSec execution failed: '+result.stderr)
    report = json.loads(result.stdout)
    (root/'full-lock-rustsec.json').write_text(json.dumps(report, indent=2)+'\n')
    findings = report['vulnerabilities']['list']
    warnings = report['warnings']
    if not isinstance(warnings, dict):
        raise ValueError('Malformed RustSec warnings')
    for kind, rows in warnings.items():
        for row in rows:
            findings.append({**row, 'warning_kind': kind})
    blocked = False
    for name in ['authz', 'lakekeeper-authz']:
        directory = root/name
        binary = directory/'binary'
        metadata = inventory(binary)
        (directory/'cargo-auditable.json').write_text(json.dumps(metadata, indent=2)+'\n')
        packages = {(p['name'], p['version']) for p in metadata['packages'] if p.get('kind', 'runtime') == 'runtime'}
        shipped, build_only = [], []
        for finding in findings:
            p = finding['package']
            (shipped if (p['name'],p['version']) in packages else build_only).append(finding)
        output = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                  'database':report['database'], 'shipped_package_count':len(packages),
                  'blocking_shipped':shipped,'nonblocking_build_only_or_unselected':build_only}
        (directory/'rustsec.json').write_text(json.dumps(output,indent=2)+'\n')
        print(name, 'blocking shipped:',len(shipped),'build-only/unselected:',len(build_only))
        blocked |= bool(shipped)
    return int(blocked)


if __name__ == '__main__':
    raise SystemExit(main())
