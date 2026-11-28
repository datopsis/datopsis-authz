#!/usr/bin/env bash
set -euo pipefail
arch=${INTEGRATION_ARCH:?}
image=${1:?image name}
output="reports/images/${image}"
mkdir -p "$output"
builder=$(python3 -c 'import json,sys; print(json.load(open("artifacts/images.lock.json"))["architectures"][sys.argv[1]]["baseImages"]["builder"])' "$arch")
status=0
timeout 600 docker build --build-arg "BUILDER=$builder" --build-arg "TARGET=localhost/${image}:s4a" -t "localhost/gate-${image}:s4a" - <<'CONTAINERFILE' || status=$?
ARG BUILDER
ARG TARGET
FROM ${TARGET} AS target
FROM ${BUILDER}
COPY --from=target / /target
RUN cp -a /etc/yum.repos.d /ubi-repos \
    && microdnf install -y dnf \
    && rpm --root /target -qa --qf '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n' > /inventory.tsv
CONTAINERFILE
# Preserve the original gate's lock schema without changing its query policy.
python3 - "$arch" "$output/query-lock.json" <<'PY'
import json,sys
from pathlib import Path
lock=json.load(open('artifacts/images.lock.json'))['architectures'][sys.argv[1]]
Path(sys.argv[2]).write_text(json.dumps({'baseImages':lock['baseImages']}))
PY
if test "$status" = 0; then
    timeout 600 docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
        --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,noexec,nosuid,nodev --tmpfs /var/tmp:rw,noexec,nosuid,nodev \
        -v "$PWD:/work:ro" -v "$PWD/$output:/evidence:rw" -w /work --entrypoint python3 \
        "localhost/gate-${image}:s4a" scripts/ubi_vulnerability_gate.py \
        --architecture "$arch" --lock "/evidence/query-lock.json" --inventory /inventory.tsv --repo-dir /ubi-repos \
        --trivy /evidence/trivy.json --grype /evidence/grype.json --output /evidence/gate.json || status=$?
fi
if ! test -s "$output/gate.json"; then
    python3 scripts/ubi_vulnerability_gate.py --architecture "$arch" --output "$output/gate.json" \
        --failure "Scanner/gate setup or query failure (exit $status)" || true
    status=1
fi
cat "$output/gate.md" >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"
exit "$status"
