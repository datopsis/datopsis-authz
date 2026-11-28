#!/usr/bin/env python3
"""Gate runtime dependencies in the exact workspace feature set. No advisory ignores."""
import json
import os
from pathlib import Path
import subprocess

from rustsec_policy import classify, write_summary

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
runtime = {(line.replace(' (*)','').split()[0], line.replace(' (*)','').split()[1].removeprefix('v'))
           for line in tree.splitlines()}
classification = classify(report, runtime)
result = {'database':report['database'],
          'blocking_runtime':classification['blocking'],
          'report_only_runtime_no_patch':classification['report_only_no_patch'],
          'nonblocking_build_or_unselected':classification['report_only_build_or_unselected'],
          'report_only_non_advisory_warnings':classification['report_only_non_advisory_warnings'],
          'warnings':report['warnings']}
(out/'classification.json').write_text(json.dumps(result,indent=2)+'\n')
write_summary(out/'summary.md', 'Selected source runtime', classification)
raise SystemExit(bool(classification['blocking']))
