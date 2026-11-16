# S4: groups and revocation timing

**Spike complete: C3 PASS with B and C on native amd64 and arm64. Full C1–C8
acceptance FAIL (C7/C8); dependency audit FAIL. No MVP qualification or merge.**

## Inputs and evidence

Stacked on unmerged S1, branch `room/datopsis-authz-spike-s1-lakekeeper-adapt-w46b`
at `070522db03217da42a8fcbca590ef5c78ebc6c99`. Reuses authz-core, authz-serve and
the compiled Lakekeeper adapter; Cedar 4.14.1 remains the rules engine. The one
program/image with serve/sail-gateway/token-broker/policy roles is retained;
this spike extends serve only. [Updated architecture](../diagrams/authz-architecture.svg).

- Platform plan §4a and AUTHZ-EVALUATION read at integration main
  `369dbdec67445eb1c2931b39b45f3364ec71ead4`; acceptance harness pinned to
  `e8379a528bf413c05aad49e56bc8cd507b5e077a`.
- Lakekeeper: `9bd377162345b64a716f0a4fcffe4e7e7f3c7534`.
- Rauthy owner image: **`1e114b84b01988bf15306b110b040378878488d3`**;
  its locks pin Rauthy **0.37.2**, source `fe6bcb95192e8a83c29e2b525bf4960933bea3bd`.
- Tested PR source: `0dd09eb2642302ef6d79bd3ea08696f591eda1ee`, through merge
  commit `ba5e85cb64ec71b9402e2c040977f581fd6a6201`.
- [Run 43904291205](https://github.com/datopsis/datopsis-authz/actions/runs/43904291205),
  [amd64 job][amd64] and [arm64 job][arm64]: actual logs and sanitized artifacts read.
  Native machine assertions and image provenance pass; no QEMU or external source patches.

Permanent sanitized evidence: [amd64](S4-results-amd64.json),
[arm64](S4-results-arm64.json). These retain every timing sample, typed denials,
exact rows, client outcomes, input revisions, image/lock/binary/library hashes and
owner-image provenance. Full sanitized service logs remain in the run artifacts
for 14 days. Per-run CA, keys and tokens are never committed or uploaded.
The documentation/evidence follow-up changes no tested program or assertions.

## Removal to denial: native results

Times start at Rauthy's membership **PUT response acknowledgement**, after which
an authoritative GET confirms removal. Fresh table-load responses are polled.
These are single-user, single-node observations, not distributed revocation SLAs.

| Experiment | [amd64][amd64] | [arm64][arm64] | Verdict |
| --- | --- | --- | --- |
| A: access lifetime 30s | 90.703s → 401 | 90.566s → 401 | **FAIL C3**; old token allowed until authentication expiry |
| B: 1s admin poll → epoch | 1.010s → 404 | 1.011s → 404 | **PASS healthy-path full C3**; stale-feed outage unsafe |
| C: live, no membership cache | 25.464ms → 404 | 40.615ms → 404 | **PASS full C3 and IdP outage control** |
| C: 250ms positive cache | 123.343ms → 404 | 298.871ms → 404 | **PASS full C3 and post-TTL IdP outage control** |

Each B/C mode preserves all C3 assertions: genuine groups grant nothing without
an explicit mapping; mapping allows exact rows; removing the mapping denies the
retained token; removing membership at Rauthy while the mapping remains denies
that **same old, unexpired, groups-bearing token**. The original typed table/
namespace denial oracle remains strict. A 401, TLS error, timeout or arbitrary
exception never substitutes for a C3 authorization denial. The retained reader
keeps S1's pre-existing catalog configuration; a separate fresh REST probe also
requires 403/404. Fresh tokens recover after B's epoch boundary.

## A: expiry exposure, client refresh load and failures

The fixture updates the real Rauthy client to 30s and verifies `exp-iat == 30`.
The existing verifier's 60s clock allowance makes observed exposure about **90.6–90.7s**,
with 1s probe spacing. Expiry alone cannot deny the old token while it is still
unexpired, so it cannot pass C3. It also cannot revoke already-fetched metadata,
query data or issued storage credentials.

Native workloads run at approximately 0/20/40/60s, using a fixed workload identity.
Counts below are the same on both architectures. Persisted TokenIssued events
count successful issuance; error log entries count the observed base64 failures,
not a general HTTP traffic meter. PyIceberg's initial token is acquired before
its measured window; zero below means no successful renewal in that window.

| Client at 30s TTL | Native successful workloads / 4 (both CPUs) | Issued tokens during window | Base64 error log entries | Observed behavior |
| --- | ---: | ---: | ---: | --- |
| Trino 484 | 0 / 4 | 0 | 4 | Initial short-TTL query and every later query fail with ICEBERG_CATALOG_ERROR |
| PyIceberg 0.12.0 | 2 / 4 | 0 | 2 | Reads at 0/20s succeed; renewal attempts at 40/60s fail with OAuthError |
| Sail 0.7.3 + external file writer | 4 / 4 | 4 | 0 | Four explicit client-credentials acquisitions and in-place file updates; exact rows and typed write/other-namespace denials pass |

The window durations are about 60.3s for Trino/PyIceberg and
61.60/62.09s for Sail on amd64/arm64.
Sail's stale expired-file client exits 1; rewriting the same mounted inode with
a fresh token makes the full pinned client exit 0 on both CPUs. Its failure's
client exception text was deliberately not retained, so no typed 401 claim is
made for that native Sail attempt. Atomic rename/directory mounts were not tested.

Five explicit acquisitions per client label (15 total per CPU) form a separate
shared-endpoint microbenchmark: median token endpoint latency is
3.041ms amd64 /
4.856ms arm64. These are scripted mints, not native refresh counts.
A 20s renewal schedule projects **3 requests/minute per active broker** after the
initial acquisition; relative to once per 1800s this is 90× steady-state issuance.
That ratio is arithmetic, not a measured long-TTL baseline or capacity test.

**Do not recommend 30s TTL for the current Trino/PyIceberg flow.** Rauthy logs
`B64 decoding error` during the failing renewals. Its pinned TokenRequest parser
attempts base64 decoding for any Authorization header. A Bearer-header interaction
is a source-based hypothesis; request headers and a corrective client configuration
were not runtime captured/tested. C5's unchanged 1800s initial-read/denial tests pass,
but that does not qualify long-running renewal at 1800s either.

Human membership removal is measured with a genuine human token at the catalog.
These workload-client tests do not establish human end-user propagation through
Trino or Sail, nor each engine's precise cache/fetched-data exposure window.

## B: epoch cost and failure mode

Lakekeeper forwards verified `iat` from its authenticated Authentication object,
not a client header. The relationship store keeps a monotonic per-user cutoff;
`iat < epoch` and missing `iat` deny. Lower/out-of-order epoch updates cannot undo
revocation. The poll compares an authoritative snapshot over verified TLS, then
writes `floor(now)+1` to reject all tokens minted in the detection second.
The test waits past that boundary and proves a fresh genuine token recovers.

Each measured removal adds **one Users GET plus one epoch write** after the chosen
full 1s poll phase; normal decisions add only a local epoch lookup. First REST
denial after epoch-write acknowledgement took
6.730/
6.893ms on amd64/arm64.
The separately retained typed-client confirmation completes later. Continuous
per-user polling at interval P would add approximately N/P GETs/s for N users.
This prototype is a fixture-side single poll cycle, not a production reconciler
or polling-scale benchmark; its phase is explicit, not sampled randomly.

**Epochs alone continue granting access when change delivery is unavailable.** On both
CPUs a second removal followed by stopping Rauthy makes the admin poll hit a
ConnectTimeout (the fixture HTTP client has a 30s timeout). With no new cutoff,
the previously valid token still receives **200**. There is no epoch freshness
gate; normal JWT expiry remains the eventual backstop. The RAM store also loses
epochs on restart. Durable shared state, authenticated delivery, reconciliation,
freshness limits, clock/skew budgets and propagation are the major complexity.

## C: latency, API load and fail closed behavior

Live mode replaces JWT groups with authoritative groups for configured users.
The 250ms cache is per principal. No stale-on-error path exists after TTL; request
timeout is 2s, HTTPS uses the per-run CA, and redirects are disabled. Rauthy's
omitted empty-group field is accepted only after validating user ID and enabled
state; malformed/mismatched responses fail closed.

| Profile, 20 fresh REST loads | amd64 | arm64 |
| --- | --- | --- |
| No cache: Users GET count | 60 | 60 |
| No cache: median REST latency / same-mode no-lookup control | 30.773 / 28.493ms | 47.845 / 43.594ms |
| 250ms cache: Users GET count | 2 | 4 |
| 250ms cache: median REST latency / no-lookup control | 24.074 / 23.939ms | 38.835 / 38.781ms |
| No-cache median membership GET latency | 0.619ms | 1.086ms |

A table load makes three decisions, so uncached lookup adds three IdP GETs here.
Caching cuts observed lookup traffic by 96.7%/93.3% in these serial bursts. The
small REST-latency differences are not a CPU ranking or throughput SLA. Cache
age, network time and probe phase explain the varying removal-to-denial samples;
250ms is a configured cache age, not a claimed end-to-end latency ceiling.

Stop Rauthy, wait past TTL: **503 AuthorizationBackendError, no metadata/config/
storage-credentials** on both CPUs, in both cache modes. The measured outage
responses take 8.808/8.987ms without cache and
8.778/8.568ms with cache, in this stopped-container case.
A still-valid positive cache can allow during its remaining 250ms, including
while Rauthy is down; the verified outage result is **after TTL**. Production
complexity is synchronous IdP dependency, bounded concurrency, cache-miss
coalescing, protected read-only credentials and availability/latency budgets.

## Rauthy change delivery at the exact source pin

- [EventType](https://github.com/sebadob/rauthy/blob/fe6bcb95192e8a83c29e2b525bf4960933bea3bd/src/api_types/src/events.rs): no membership-change event. Notification integrations are not a membership webhook contract.
- [User update](https://github.com/sebadob/rauthy/blob/fe6bcb95192e8a83c29e2b525bf4960933bea3bd/src/api/src/users.rs): writes user, then spawns outbound SCIM synchronization asynchronously; errors logged.
- [SCIM contract](https://github.com/sebadob/rauthy/blob/fe6bcb95192e8a83c29e2b525bf4960933bea3bd/book/src/work/scim.md): Rauthy pushes to an application's Users/Groups endpoints; group membership uses PATCH add/remove. Requires implementing the receiving endpoints and reconciliation. This is outbound provisioning, not a Rauthy membership-read endpoint.
- Admin `GET /auth/v1/users/{id}` returns authoritative groups using an API key scoped to Users/read. The fixture also needs Users/update for removals and Clients/read/update for lifetime experiments. Production reader credentials need only read access.

The [SCIM retry scheduler](https://github.com/sebadob/rauthy/blob/fe6bcb95192e8a83c29e2b525bf4960933bea3bd/src/schedulers/src/scim_tasks.rs) sleeps 60–90 seconds between retry scans, and eventually deletes tasks after the configured retry limit. SCIM alone cannot promise seconds during receiver outages. SCIM delivery/retry timing is not runtime verified. Source evidence supports
polling as the smallest measurable prototype, with SCIM plus reconciliation a
candidate for reducing detection delay.

## Recommendation and remaining acceptance

Use **C with a short positive cache as the demonstrated fail-closed baseline**.
Add **durable B epochs** as the cheap fast path when authoritative change-feed
freshness is known, using outbound SCIM plus polling/reconciliation. If freshness
is stale, perform C or deny after its cache expires; never fall back to JWT groups.
This combination addresses B's measured stale-feed 200 and C's measured IdP load.
The combined freshness-gated implementation is a recommendation, not built or
qualified in this spike.

Keep a bounded access-token lifetime as a backstop and use an external Sail
writer, but fix/qualify Trino and PyIceberg renewal before tightening TTLs. A
30s token still has about 90s observed verifier exposure and breaks those native
renewal flows, so A is not a seconds-level revocation solution or a C3 substitute.

| Acceptance | [amd64][amd64] | [arm64][arm64] |
| --- | --- | --- |
| C1 read, exact rows, other namespace/write denials | PASS | PASS |
| C2 inheritance and single-table isolation | PASS | PASS |
| C3 all controls for B, C/no-cache, C/250ms | PASS | PASS |
| C4 grant revocation | PASS — 21.714ms | PASS — 32.956ms |
| C5 original 1800s Trino/PyIceberg/Sail read and denial assertions | PASS — all three | PASS — all three |
| C6 denied vending/no S3 keys, STS disabled | PASS | PASS |
| C7 security/outage/recovery | FAIL — restart loses state; 120s recovery wait expires | FAIL — same |
| C8 durable restart/repeated migrations | FAIL — complete snapshot lost | FAIL — same |
| Required lint/test checks | FAIL | FAIL |

C7's earlier spoofing, invalid-token, network-isolation and structured-outage
assertions complete before the recovery failure; this is not a C7 pass. C8's
migration assertions are not reached. Explicit fixture resets occur only between
cases and after C8, never inside restart assertions. Epochs and live-mode
selectors/cache are volatile too; restarting is not a revocation-safe recovery.
Live mode is opt-in; unconfigured principals retain S1's claim path. This image
is not a production-safe default group-revocation implementation.

The actual lint log reports the unchanged three locked-graph advisories:
libsqlite3-sys / RUSTSEC-2026-0459; quick-xml / RUSTSEC-2026-0194 and
RUSTSEC-2026-0195, plus informational warnings. No ignores/exemptions were added.
Local workspace tests, changed-service regression test, Clippy, formatting,
HTTPS component checks, YAML validation and LF checks pass. Native workspace
tests and both runtime loader probes also pass; none substitutes for C1–C8.

Not verified: SCIM delivery/retry runtime; continuous polling scale; combined
freshness gate; HA, durable epochs/grants, replay, multi-node clocks/propagation;
all user-disable/deletion/group-rename paths; fresh no-group JWT compatibility
(the separate S1 Lakekeeper empty-role-source gap); successful native automatic
renewal or a working minimum TTL for Trino/PyIceberg; production token broker and
atomic file replacement; exact per-engine cached-data revocation windows; human
identity propagation through engines; STS/issued-credential revocation; production
image/supply-chain and durable audit qualification. All performance numbers are
small single-node observations. No other repository, GitHub setting/permission,
production database or acceptance oracle was changed.

## Earlier attempts and fixture corrections

[Run 43885508158](https://github.com/datopsis/datopsis-authz/actions/runs/43885508158)
reached native compilation/tests/HTTPS smoke, but amd64 acceptance was BLOCKED:
PGDG's rolling `rhel-9-x86_64` alias returned 404 for three locked PostgreSQL 18.6
RPMs. The official `rhel-9.8-x86_64` path still serves exactly the locked bytes.
All four PostgreSQL packages on **both** architectures were downloaded locally
and checked against the original pinned sizes/SHA256 values.

`evaluation/artifact_transport/sitecustomize.py` supplies an HTTPS transport-only
fallback for the exact 18.6 RPM names, only after a 404 and only on the same
`download.postgresql.org` host. It is enabled for child Python acquirers during
fixture builds. Owner sources and locks are unchanged; their locked size/hash,
key-fingerprint, signature, offline-build and image-provenance checks all remain
mandatory. There is no version or trust fallback. The final run below gets through this prerequisite on both CPUs.

A second prerequisite failure reached final-image smoke on amd64 in
[43886994650](https://github.com/datopsis/datopsis-authz/actions/runs/43886994650/job/133367725832)
and arm64 in
[43885508158](https://github.com/datopsis/datopsis-authz/actions/runs/43885508158/job/133362433810):
`authz-serve` could not load `libssl.so.3`. Workspace feature unification pulls
native TLS into the new reqwest-using service even though its direct dependency
requests rustls. S1 copied UBI runtime libraries only into the catalog image.
The correction collects dependencies from **both** binaries, includes them in
both images, and probes **both** binaries against Micro before fixture builds.
These attempts provide no C1–C8 or S4 runtime pass.

[Run 43892123832](https://github.com/datopsis/datopsis-authz/actions/runs/43892123832)
executed the real fixture on both CPUs: C1/C2/C4/C5/C6 passed, while C7/C8 retained
the S1 state-loss failures. C3 failed with a strict **503**, never accepted as an
authorization denial. The first removal exposed Rauthy's `UserResponse.groups`
`skip_serializing_if=None`: an empty group list is omitted from the response.
The resolver now accepts omission only after verifying the returned user ID and
`enabled=true`; malformed/mismatched responses still fail closed. A regression
unit test and local HTTPS check cover the exact omitted-field shape.

The same run exposed Trino's short-lifetime incompatibility: its first query at
30s TTL returned `ICEBERG_CATALOG_ERROR` and Rauthy logged `B64 decoding error`.
C5's unchanged 1800s native-client assertions passed. The short-token experiment
now records this failure and continues the other measurements. TokenIssued counts
measure successful issuance; separate base64-error log counts expose known failed
token requests. Failed Trino queries never count as successful reads. The
[source credential parser](https://github.com/sebadob/rauthy/blob/fe6bcb95192e8a83c29e2b525bf4960933bea3bd/src/api_types/src/oidc.rs)
at this pin attempts base64 decoding for any Authorization header; a Bearer-header
interaction is a source-based hypothesis, not a captured-header runtime claim.

[Run 43899913941](https://github.com/datopsis/datopsis-authz/actions/runs/43899913941)
completed live C3 controls and A measurements on both CPUs, but B's retained-token
assertion constructed a new catalog: the epoch hid warehouse discovery and
PyIceberg raised generic RESTError/NoSuchWarehouseException before a table load.
This was not accepted as a typed authorization denial; C3 failed and the old
human token caused downstream C4/C7 failures. The final run restores S1's
already-configured reader for the strict retained-token table assertion, retaining
the separate fresh REST 403/404 probe and every C3 control. It passes C3 on both
CPUs; no generic REST exception was added to the denial allowlist.

Other superseded preparation runs were cancelled before runtime and establish
no acceptance result.

[amd64]: https://github.com/datopsis/datopsis-authz/actions/runs/43904291205/job/133428847992
[arm64]: https://github.com/datopsis/datopsis-authz/actions/runs/43904291205/job/133428848010
