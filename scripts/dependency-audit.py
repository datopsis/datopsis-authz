#!/usr/bin/env python3
"""Gate runtime dependencies in the exact workspace feature set. No advisory ignores."""
import json
import os
from pathlib import Path
import subprocess

out = Path('reports/audit')
out.mkdir(parents=True, exist_ok=True)
# The two packages are precisely the shipped binaries. Resolve together, just as
# cargo build --workspace does; exclude dev and build edges for the runtime gate.
tree = subprocess.run(['cargo','tree','--locked','-p','authz-serve','-p','lakekeeper-bin-datopsis',
    '--edges','normal,no-proc-macro','--prefix','none','--format','{p}'],text=True,capture_output=True,check=True).stdout
(out/'runtime-tree.txt').write_text(tree)
audit = subprocess.run(['cargo','audit','--json'],text=True,capture_output=True)
if audit.returncode not in (0,1):
    raise RuntimeError('cargo audit failed to execute')
report = json.loads(audit.stdout)
(out/'full-lock.json').write_text(json.dumps(report,indent=2)+'\n')
runtime = {tuple(line.replace(' (*)','').split()[:2]) for line in tree.splitlines()}
blocking, nonblocking = [], []
for finding in report['vulnerabilities']['list']:
    package = finding['package']
    item = {'crate':package['name'],'version':package['version'], 'advisory':finding['advisory']['id']}
    (blocking if (package['name'],'v'+package['version']) in runtime else nonblocking).append(item)
result = {'blocking_runtime':blocking,'nonblocking_build_or_unselected':nonblocking,'warnings':report.get('warnings',{})}
(out/'classification.json').write_text(json.dumps(result,indent=2)+'\n')
summary = f'Blocking shipped dependency findings: {len(blocking)}\nNon-blocking build-only/unselected findings: {len(nonblocking)}\n\n'+json.dumps(result,indent=2)
if any(item['crate'] == 'quick-xml' for item in blocking):
    summary += '\n\nOwner status: upstream Lakekeeper, Azure path, no fix yet; upstream proposal in progress. Lint remains RED; no ignore or S3-only patch. Merge waits for upstream.'
print(summary)
if os.environ.get('GITHUB_STEP_SUMMARY'):
    with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as handle:
        handle.write('```\n'+summary+'\n```\n')
raise SystemExit(bool(blocking))
