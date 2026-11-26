# S3 Sail gateway: per-team MVP follow-on

Owner approved slice 3 on 2026-11-26. The original
[S3 feasibility report](https://github.com/datopsis/datopsis-authz/blob/10d508b668b8d7005ba7e5949602d8f09668dbc5/docs/spikes/S3-sail-gateway.md)
records the proven HTTP/2 PING fix and historical native evidence. Its shared-engine
admission and session-isolation gaps describe that spike, not a qualified MVP.

The production follow-on keeps the independent HTTP/2 drivers and the exact,
blocking paced million-row/no-retry oracle. It resolves current Rauthy groups
through serve's existing 250 ms live-lookup cache, routes to one private Sail
instance per team, and commits every admission audit before forwarding. Each
instance has its own catalog identity, accepted OAuth audience and scoped grants.
Users within a team share permissions and session state; per-user instances and
per-session identity remain deferred. See [deployment and limits](../SAIL.md) and
[the per-team topology](../diagrams/sail-per-team.svg).

[Slice-3 PR #8](https://github.com/datopsis/datopsis-authz/pull/8), stacked on #7
and #5, is the current native evaluation record. Its table distinguishes each
amd64/arm64 assertion and links actual runs/artifacts. Historical spike passes
never substitute for current proof. Missing prerequisites remain BLOCKED; all
Sail assertions, C1–C8 and slice-2 regressions remain blocking. Dependency gates
remain unsuppressed and this work is not merged or release-image qualified.

The [S5 costs cited in deployment documentation](../SAIL.md#per-team-instance-cost)
apply per team process here. Direct storage credentials bypass catalog checks:
row/column-restricted tables must remain inaccessible to non-enforcing Sail and
direct clients. This slice does not qualify Phase D storage-path isolation.


Slice 4a now composes the regression fixture from the separate, source-built
`authz` and `lakekeeper-authz` images. [Image/runtime details](../IMAGES.md) and
[the build boundary](../diagrams/hardened-images.svg) replace the spike binary
layers. This change does not qualify a new runtime pass: the slice-4a PR must
supply its own native evidence and unsuppressed security results. The Cedar
Authorizer interface and behavior are unchanged by the Lakekeeper 0.13.9 bump.
