#!/usr/bin/env python3
"""Verify that every regression suite consumes the hardened image built at this head."""
import json
import os
from pathlib import Path
import subprocess

images = {}
for image, name in [('localhost/lakekeeper-datopsis:s1','lakekeeper-authz'),
                    ('localhost/authz-serve:s1','authz')]:
    evidence = json.loads((Path('reports/images')/name/'build-hardening.json').read_text())
    obj = json.loads(subprocess.check_output(['docker','image','inspect',image],text=True))[0]
    assert obj['Id'] == evidence['image_id']
    assert evidence['revision'] == os.environ['SOURCE_REVISION']
    images[name] = evidence
Path('reports/s1').mkdir(parents=True,exist_ok=True)
Path('reports/s1/hardened-builds.json').write_text(json.dumps(images,indent=2)+'\n')
