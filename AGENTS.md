# Agent instructions

Owner approved the MVP on 2026-11-17. This branch implements catalog slice 1 plus owner-approved Trino slice 2 (2026-11-25). Preserve the owner's one-monorepo, one-platform-program
with roles decision. The Lakekeeper adapter is compiled into a separate catalog
binary. Trino enforcement shares serve; Sail gateway and hardened images are later slices.

Pin external repositories by full commit; do not modify them. Lakekeeper source:
9bd377162345b64a716f0a4fcffe4e7e7f3c7534. Acceptance harness:
e8379a528bf413c05aad49e56bc8cd507b5e077a. Rauthy:
1bedace6e61627820e0f863a86c6ccc791f5e22b (coordinator-approved unmerged PR #3 test pin).

Trino image: 9343071e44fc58e4848c6e6b66ae1403a394d17f (coordinator-approved
unmerged PR #8 test pin; Iceberg JAR CVE gate remains RED; OPA opt-in).

Fail closed. Do not weaken C1-C8. Explicitly document C3's direct-claim adaptation.
Blocked prerequisites never pass. No secrets or raw credential artifacts. No
GitHub settings changes, force pushes, merges, sign-offs or coauthor trailers.

Keep LF endings; enable .githooks. CI jobs are named exactly lint and test.
Validate YAML. Native amd64 and arm64 runtime evidence is required. Containers
cannot run here; inspect actual Actions logs. Update the spike report and diagram
with architecture changes. Do not report compilation or unit tests as C1-C8 passes.

Owner decision 2026-11-18: keep quick-xml's RustSec findings honestly RED in lint:
"upstream Lakekeeper, Azure path, no fix yet; upstream proposal in progress".
No ignore entry and no S3-only Lakekeeper patch. Finish the other slice-1 work;
merge waits for the upstream fix. Rauthy PR #3 is approved for test builds only;
its SvelteKit gate stays RED pending a separate owner decision. Do not bypass
its FIDO verification or checksum guards.

CI-first: locally run only lightweight lint, unit tests, YAML/LF, cargo check/clippy.
Image builds, artifact acquisition/unpacking, scans, container/runtime tests and
native multi-architecture validation run only in existing PR Actions jobs. Read
logs/artifacts instead of reproducing them locally. Do not rerun unchanged
expensive checks. Use at most one gh pr checks --watch and stop your servers,
watchers and background jobs at the end of each step. Keep security gates,
both architectures and the exact required check names unchanged.
