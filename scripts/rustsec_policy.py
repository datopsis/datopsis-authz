"""Owner policy 2026-11-27: shipped + published patched versions blocks.

Advisory type never exempts or promotes a finding. Missing/invalid evidence is
an execution failure, not evidence that a patch is unavailable.
"""
import html
import os
import re
from pathlib import Path

GROUPS = ('blocking', 'report_only_no_patch', 'report_only_build_or_unselected')


def parse_runtime_tree(tree):
    runtime = set()
    for line in tree.splitlines():
        if not line.strip():
            continue  # Cargo separates multiple selected package trees with a blank line.
        parts = line.split()
        if len(parts) < 2 or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?', parts[1]):
            raise ValueError('Malformed Cargo runtime tree row: '+line)
        runtime.add((parts[0], parts[1][1:]))
    if not runtime:
        raise ValueError('Empty Cargo runtime tree')
    return runtime


def audit_findings(report):
    settings = report['settings']
    if settings['ignore'] or settings['severity'] is not None or settings['target_arch'] or settings['target_os']:
        raise ValueError('Filtered/ignored RustSec advisories are forbidden')
    if not {'unmaintained','unsound','notice'} <= set(settings['informational_warnings']):
        raise ValueError('RustSec advisory warning coverage is incomplete')
    rows = list(report['vulnerabilities']['list'])
    if not isinstance(report['vulnerabilities']['list'], list) or not isinstance(report['warnings'], dict):
        raise ValueError('Malformed RustSec report')
    for kind, warnings in report['warnings'].items():
        if not isinstance(warnings, list):
            raise ValueError('Malformed RustSec warning list')
        rows.extend({**row, 'warning_kind': kind} for row in warnings)
    return rows


def classify(report, runtime):
    result = {group: [] for group in GROUPS}
    result['report_only_non_advisory_warnings'] = []
    for row in audit_findings(report):
        package = row['package']
        if not package.get('name') or not package.get('version'):
            raise ValueError('Missing RustSec package identity')
        advisory = row.get('advisory')
        if advisory is None:
            # e.g. registry yanks: retain raw warnings, but they are not RustSec advisories.
            if not row.get('warning_kind'):
                raise ValueError('Vulnerability has no advisory')
            result['report_only_non_advisory_warnings'].append(row)
            continue
        if not advisory.get('id'):
            raise ValueError('Missing RustSec advisory identity')
        patched = row['versions']['patched']
        if not isinstance(patched, list) or not all(isinstance(v, str) and v.strip() for v in patched):
            raise ValueError('Invalid or missing RustSec patched-version evidence')
        if (package['name'], package['version']) not in runtime:
            group = 'report_only_build_or_unselected'
        else:
            group = 'blocking' if patched else 'report_only_no_patch'
        result[group].append(row)
    return result


def markdown(subject, classification):
    def cell(value):
        return html.escape(str(value)).replace('|', '&#124;').replace('\n', ' ').replace('@', '&#64;')
    lines = [f'## {cell(subject)} RustSec', '',
             'Shipped advisories with patched versions block, whatever their type. '
             'No-patch shipped advisories are reported and tracked; build-only/unselected advisories are report-only.', '',
             '| Decision | Crate | Version | Advisory | Type | Patched versions |',
             '| --- | --- | --- | --- | --- | --- |']
    for group in GROUPS:
        for row in classification[group]:
            a, p = row['advisory'], row['package']
            values = [group, p['name'], p['version'], a['id'],
                      a.get('informational') or row.get('warning_kind') or 'vulnerability',
                      ', '.join(row['versions']['patched']) or 'none published']
            lines.append('| '+' | '.join(cell(v) for v in values)+' |')
    if classification['report_only_non_advisory_warnings']:
        lines += ['', f"Other report-only registry warnings: {len(classification['report_only_non_advisory_warnings'])}."]
    return '\n'.join(lines)+'\n'


def write_summary(path, subject, classification):
    text = markdown(subject, classification)
    Path(path).write_text(text)
    print(text)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as handle:
            handle.write(text+'\n')
