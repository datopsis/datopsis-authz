# Agent instructions

This is S1, not the MVP. Preserve the owner's one-monorepo, one-platform-program
with roles decision. The Lakekeeper adapter is compiled into a separate catalog
binary. Do not begin the MVP without the owner's go/no-go.

Pin external repositories by full commit; do not modify them. Lakekeeper source:
9bd377162345b64a716f0a4fcffe4e7e7f3c7534. Acceptance harness:
e8379a528bf413c05aad49e56bc8cd507b5e077a. Rauthy:
1e114b84b01988bf15306b110b040378878488d3.

Fail closed. Do not weaken C1-C8. Explicitly document C3's direct-claim adaptation.
Blocked prerequisites never pass. No secrets or raw credential artifacts. No
GitHub settings changes, force pushes, merges, sign-offs or coauthor trailers.

Keep LF endings; enable .githooks. CI jobs are named exactly lint and test.
Validate YAML. Native amd64 and arm64 runtime evidence is required. Containers
cannot run here; inspect actual Actions logs. Update the spike report and diagram
with architecture changes. Do not report compilation or unit tests as C1-C8 passes.
