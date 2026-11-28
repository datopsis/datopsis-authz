#!/usr/bin/env python3
"""One tracking issue for shipped advisories without patches; no gate exemptions.

CI publishes current native reports. The daily workflow refreshes RustSec against
those same binaries' source lock and inventories. Only changed tracking records
produce a comment; a new run/head/database commit alone never does.
"""
import argparse
import base64
import hashlib
import html
import json
import os
from pathlib import Path
import re
import subprocess

from rustsec_policy import classify

MARKER = '<!-- datopsis-rustsec-unpatched-tracking:v1 -->'
STATE = r'<!-- rustsec-state:([A-Za-z0-9+/=]+) -->'
TITLE = 'Track shipped RustSec advisories without a published patch'


def gh(*args, payload=None, raw=False):
    command = ['gh', *args]
    if payload is not None:
        command += ['--input', '-']
    result = subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
                            text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError('GitHub request failed: '+result.stderr)
    return result.stdout if raw else json.loads(result.stdout)


def latest_reports(repository, root):
    branch = gh('api', f'repos/{repository}')['default_branch']
    runs = gh('run', 'list', '--repo', repository, '--workflow', 'ci.yml', '--branch', branch,
              '--status', 'completed', '--limit', '1', '--json', 'databaseId,headSha')
    if len(runs) != 1:
        raise ValueError('No completed default-branch native evidence')
    run = runs[0]
    artifacts = gh('api', f'repos/{repository}/actions/runs/{run["databaseId"]}/artifacts?per_page=100')['artifacts']
    names = [a['name'] for a in artifacts if a['name'].startswith('s1-') and not a['expired']]
    if len(names) != 2:
        raise ValueError('Latest run lacks both complete native report artifacts')
    for name in names:
        subprocess.run(['gh','run','download',str(run['databaseId']),'--repo',repository,
                        '--name',name,'--dir',str(root/name)], check=True)


def snapshots(root):
    found = {}
    for path in root.rglob('images/*/rustsec.json'):
        name = path.parent.name
        build = json.loads((path.parent/'build-hardening.json').read_text())
        result = json.loads(path.read_text())
        data = json.loads((path.parent/'cargo-auditable.json').read_text())
        identity = (build['architecture'], name)
        if identity in found or name not in {'authz','lakekeeper-authz'} or data['format'] < 2:
            raise ValueError('Duplicate/invalid native inventory')
        if result['binary_sha256'] != build['binary_sha256']:
            raise ValueError('Binary identity differs between build and advisory report')
        runtime = {(p['name'],p['version']) for p in data['packages'] if p.get('kind','runtime') == 'runtime'}
        found[identity] = (build, result, runtime, path.parent.parent/'full-lock-rustsec.json')
    if set(found) != {(a,n) for a in ('amd64','arm64') for n in ('authz','lakekeeper-authz')}:
        raise ValueError('Missing complete two-image/two-architecture RustSec evidence')
    if len({b['revision'] for b,_,_,_ in found.values()}) != 1 or len({r['cargo_lock_sha256'] for _,r,_,_ in found.values()}) != 1:
        raise ValueError('Mixed source revisions/locks in native evidence')
    return found


def record(row, scope):
    p, a = row['package'], row['advisory']
    description = a.get('description') or ''
    # Guidance is publisher data, not an inferred replacement or per-ID rule.
    guidance = description if re.search(r'replac|alternativ|migrat', description, re.I) else ''
    return {'crate':p['name'],'version':p['version'],'advisory':a['id'],
            'type':a.get('informational') or 'vulnerability',
            'patched':sorted(row['versions']['patched']), 'replacement_guidance':guidance,
            'scopes':[scope]}


def key(row):
    return (row['crate'],row['version'],row['advisory'])


def collect(found, refreshed=None):
    no_patch, runtime_rows = {}, {}
    for (arch,name), (_,_,runtime,raw_path) in sorted(found.items()):
        report = refreshed if refreshed is not None else json.loads(raw_path.read_text())
        classification = classify(report, runtime)
        for row in classification['blocking']+classification['report_only_no_patch']:
            value = record(row, f'{name}/{arch}')
            identity = key(value)
            if identity in runtime_rows:
                previous = runtime_rows[identity]
                if {k:v for k,v in previous.items() if k != 'scopes'} != {k:v for k,v in value.items() if k != 'scopes'}:
                    raise ValueError('Inconsistent advisory data between native reports')
                previous['scopes'] = sorted(set(previous['scopes']+value['scopes']))
            else:
                runtime_rows[identity] = value
            if not value['patched']:
                no_patch[identity] = runtime_rows[identity]
    return no_patch, runtime_rows


def tracking_records(previous, no_patch, runtime_rows):
    # Continue monitoring a previously no-patch advisory when a patch appears.
    identities = set(no_patch) | {key(r) for r in previous if key(r) in runtime_rows}
    return [runtime_rows[k] for k in sorted(identities)]


def fingerprint(records):
    return hashlib.sha256(json.dumps(records,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def decode(body):
    matches = re.findall(STATE, body)
    if len(matches) != 1:
        raise ValueError('Tracking issue is missing its unique machine-readable state')
    state = json.loads(base64.b64decode(matches[0],validate=True))
    if state['version'] != 1 or state['fingerprint'] != fingerprint(state['records']):
        raise ValueError('Tracking issue state is malformed')
    return state['records']


def changes(previous, current):
    old = {key(r):r for r in previous}
    lines = []
    for row in current:
        before = old.get(key(row))
        label = f"{row['crate']} {row['version']} / {row['advisory']}"
        if not before and not row['patched']:
            lines.append(f'New shipped advisory without a published patch: {label}')
        if row['patched'] and (not before or before['patched'] != row['patched']):
            lines.append(f"FIX AVAILABLE: {label}: {', '.join(row['patched'])}")
        if row['replacement_guidance'] and (not before or before['replacement_guidance'] != row['replacement_guidance']):
            lines.append(f'Replacement guidance published/changed: {label}; review the advisory text below.')
    removed = set(old)-{key(r) for r in current}
    lines += [f'Resolved or no longer selected: {n} {v} / {a}' for n,v,a in sorted(removed)]
    return lines


def render(records, previous, provenance):
    def safe(text):
        return html.escape(str(text)).replace('@','&#64;').replace('|','&#124;')
    state = {'version':1,'records':records,'fingerprint':fingerprint(records)}
    encoded = base64.b64encode(json.dumps(state,sort_keys=True).encode()).decode()
    lines = [MARKER, f'<!-- rustsec-state:{encoded} -->', '# Shipped RustSec advisory tracking', '',
             'Owner policy (2026-11-27): patched versions available → BLOCK for shipped crates, '
             'regardless of advisory type. No published patch → REPORT and TRACK. '
             'Build-only/unselected crates remain report-only. No per-ID exemption exists.', '',
             'This one issue tracks no-patch shipped advisories and continues flagging them when a patch appears. '
             'The scheduled check reads fresh RustSec data for the latest native binary inventories. '
             'Replacement guidance is taken only from the advisory publisher. '
             'No new run/head/database timestamp alone causes a comment.', '',
             f'Last changed evidence: {safe(provenance)}', '',
             '| Crate | Version | Advisory | Type | Patched versions | Scope |',
             '| --- | --- | --- | --- | --- | --- |']
    for r in records:
        lines.append('| '+' | '.join(safe(v) for v in [r['crate'],r['version'],r['advisory'],r['type'],
                     ', '.join(r['patched']) or 'none published', ', '.join(r['scopes'])])+' |')
    if not records:
        lines += ['', 'No tracked advisories remain in the latest native inventories.']
    for message in changes(previous,records):
        lines += ['', '**'+safe(message)+'**']
    for r in records:
        if r['replacement_guidance']:
            lines += ['', f"Publisher replacement guidance — {safe(r['advisory'])}:", '',
                      '> '+safe(r['replacement_guidance']).replace('\n','\n> ')]
    lines += ['', 'Build-only/unselected findings remain in the separate CI reports. '
              'This tracking issue cannot affect a security-gate decision.', '',
              'Built with [Cloudroom](https://cloudroom.dev)', '']
    return '\n'.join(lines)


def publish(repository, no_patch, runtime_rows, provenance, api=gh):
    pages = api('api','--paginate','--slurp',f'repos/{repository}/issues?state=all&per_page=100')
    matches = [i for page in pages for i in page if 'pull_request' not in i and MARKER in (i.get('body') or '')]
    if len(matches) > 1:
        raise ValueError('Multiple marked tracking issues; refusing to create or update another')
    issue = matches[0] if matches else None
    previous = decode(issue['body']) if issue else []
    current = tracking_records(previous,no_patch,runtime_rows)
    if issue and fingerprint(previous) == fingerprint(current):
        print('Tracking set unchanged; no issue edit or comment.')
        return issue['html_url'], False
    body = render(current, previous, provenance)
    if issue:
        number = issue['number']
        note = ['RustSec tracking set changed.', *changes(previous,current),
                f'Current tracking fingerprint: `{fingerprint(current)}`.']
        fields = {'body':body}
        if current and issue['state'] == 'closed':
            fields['state'] = 'open'
        # Persist first: a retry after an uncertain comment response cannot spam
        # an unchanged set. The issue body itself always contains the alert.
        api('api','--method','PATCH',f'repos/{repository}/issues/{number}',payload=fields)
        api('api','--method','POST',f'repos/{repository}/issues/{number}/comments',
            payload={'body':'\n\n'.join(note)})
        return issue['html_url'], True
    issue = api('api','--method','POST',f'repos/{repository}/issues',payload={'title':TITLE,'body':body})
    return issue['html_url'], True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reports', type=Path, required=True)
    parser.add_argument('--latest', action='store_true', help='Download latest completed default-branch evidence and refresh RustSec')
    args = parser.parse_args()
    repository = os.environ['GITHUB_REPOSITORY']
    if args.latest:
        latest_reports(repository,args.reports)
    found = snapshots(args.reports)
    first_build, first_result, _, _ = next(iter(found.values()))
    revision = first_build['revision']
    if not re.fullmatch('[0-9a-f]{40}',revision):
        raise ValueError('Evidence source must be a full commit')
    refreshed = None
    if args.latest:
        lock = args.reports/'source-Cargo.lock'
        data = gh('api',f'repos/{repository}/contents/Cargo.lock?ref={revision}',
                  '-H','Accept: application/vnd.github.raw+json',raw=True)
        lock.write_text(data)
        if hashlib.sha256(lock.read_bytes()).hexdigest() != first_result['cargo_lock_sha256']:
            raise ValueError('Source lock differs from native binary evidence')
        audit = subprocess.run(['cargo','audit','--json','--file',str(lock)],capture_output=True,text=True)
        if audit.returncode not in (0,1):
            raise RuntimeError('RustSec refresh failed: '+audit.stderr)
        refreshed = json.loads(audit.stdout)
        (args.reports/'fresh-rustsec.json').write_text(json.dumps(refreshed,indent=2)+'\n')
    # Superseded PR runs must not replace current tracking evidence.
    event_path = os.environ.get('GITHUB_EVENT_PATH')
    event = json.loads(Path(event_path).read_text()) if event_path else {}
    if event.get('pull_request'):
        number = event['pull_request']['number']
        if gh('api',f'repos/{repository}/pulls/{number}')['head']['sha'] != revision:
            print('Superseded PR evidence; tracking issue unchanged.')
            return
    no_patch, runtime_rows = collect(found,refreshed)
    url, changed = publish(repository,no_patch,runtime_rows,
                           f"source {revision}; check https://github.com/{repository}/actions/runs/{os.environ['GITHUB_RUN_ID']}")
    message = f'RustSec tracking issue: {url}; changed={changed}; current no-patch advisories={len(no_patch)}\n'
    print(message)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as handle:
            handle.write(message)


if __name__ == '__main__':
    main()
