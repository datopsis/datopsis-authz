# S3: Sail gateway

Status: **minimum S3 feasibility PASS on native amd64 and arm64.** The exact paced
million-row workload completes without a retry or reset, and the result
connection ACKs Sail's 60-second PING while downstream DATA is backpressured.
General table authorization and admitted-user session isolation remain gaps.
**Full platform acceptance and audit remain FAIL. This is not the MVP.**

[Stacked PR #4](https://github.com/datopsis/datopsis-authz/pull/4) targets the
unmerged `room/datopsis-authz-spike-s1-lakekeeper-adapt-w46b` branch. No merge.

## Native evidence and answers

The authoritative [run 43895646867](https://github.com/datopsis/datopsis-authz/actions/runs/43895646867)
tested PR source `dca2ef51ee416f083cb8500aeb5882e0d59221d7` through merge commit
`3a4efae921497d341fc8266267e926ad20b5cceb`. Both native jobs' actual logs and sanitized
artifacts were read. Final follow-up changes only record documentation/evidence.

| Control | [amd64][amd64] | [arm64][arm64] |
| --- | --- | --- |
| Genuine human token / real ExecutePlan, exact answer 42 | PASS | PASS |
| Independent machine token / exact answer 42 | PASS | PASS |
| Missing token | PASS — UNAUTHENTICATED (16) | PASS — 16 |
| Genuine expired token, with before-expiry and fresh-token positive controls | PASS — OK / 16 / OK | PASS — OK / 16 / OK |
| Genuine wrong-audience Rauthy token | PASS — 16 | PASS — 16 |
| Token signed with a different RSA key, retaining genuine claims/kid | PASS — 16 | PASS — 16 |
| Denied human and machine principals | PASS — PERMISSION_DENIED (7) | PASS — 7 |
| Remove acknowledged Cedar grant; same unexpired human token on a fresh RPC | PASS — 7 | PASS — 7 |
| Verified TLS; unknown CA, wrong name and plaintext refused | PASS — TLS 1.3 | PASS — TLS 1.3 |
| Peer container reaches gateway :50051, cannot reach backend :50052 by IP | PASS — 0 / ECONNREFUSED (111) | PASS — 0 / 111 |
| 1,000,000 rows, first 16 batches paced at 5 seconds, retries disabled | PASS — 85.962 s | PASS — 86.130 s |
| Exact IDs / sum / every SHA-512 payload | PASS — 1,000,000 / 499,999,500,000 / 1,000,000 | PASS — same |
| One ExecutePlan, 123 batches, final gRPC OK, no ReattachExecute | PASS | PASS |
| Result-connection PING age / ACK latency during downstream wait | PASS — 60.001 s / 0.133 ms | PASS — 60.003 s / 0.219 ms |
| Result DATA bytes / capture drops / reassembly gaps | 73,339,912 / 0 / 0 | 73,339,920 / 0 / 0 |
| Duplicate identity-field and trailers-only error regression tests | PASS | PASS |
| General table-level authorization | NOT IMPLEMENTED — source gap | Same |
| Ownership of sessions between admitted users | FAIL — source gap below | Same |

[amd64]: https://github.com/datopsis/datopsis-authz/actions/runs/43895646867/job/133398352978
[arm64]: https://github.com/datopsis/datopsis-authz/actions/runs/43895646867/job/133398352465

Durable sanitized evidence: [amd64](S3-results-amd64.json) and
[arm64](S3-results-arm64.json). These retain exact controls, client RPC events,
result-connection counters, PING/backpressure overlap, build provenance, binary
hashes and raw-evidence digests. Full sanitized logs/control-frame JSONL are in
the run artifacts for 14 days; no packets, DATA/HPACK bodies or TLS secrets are
retained. Per-run CA private keys, service keys and JWTs are outside Git/artifacts.

**Reset answer:** fixed for this exact finite workload on both CPUs. The
[pinned nginx baseline](https://github.com/datopsis/sail-ubi/blob/e96e068f926b8fecb3939e953389685ee4780032/docs/evals/2026-11-13-sail-stream-reset.md)
failed around 80 seconds with partial results and INTERNAL/RST_STREAM 2. S3 runs
the owner's unmodified paced client with mode `none`, checks the complete unique
ID set and hashes, and requires an active ExecutePlan RPC beyond 70 seconds.
The client still requests reattachability, but performs no reattachment/retry.
Sail's wheel, keepalive timers, workload and pacing are unchanged.

The passive observer requires zero drops and contiguous TCP reassembly. The test
selects the Sail-to-gateway connection carrying the largest result DATA volume,
requires a PING after 50 seconds of that connection's age, matches its reverse
ACK, and proves overlap with a gateway downstream-send wait. Initial PINGs on
short ReleaseExecute/control connections cannot satisfy this assertion. This
establishes control-frame progress under the tested pressure, not an arbitrary
idle-duration, load or infinite-stream guarantee.

## Implemented boundary

The existing `authz-serve` binary/image now implements `sail-gateway` alongside
`serve` and the S1 `policy` schema check. `authz-core`, its schema and Cedar 4.14.1
are reused without changes. `token-broker` remains explicitly unimplemented.
See [the S3 topology](../diagrams/s3-sail-gateway.svg) and the updated
[shared architecture](../diagrams/authz-architecture.svg).

The gateway terminates TLS/HTTP2 and validates RS256 JWT signatures using a
configured HTTPS JWKS endpoint, exact issuer/audience, mandatory subject/expiry,
zero configured clock leeway and nbf validation. JWKS is fetched per RPC with
no stale-key cache. It calls the existing Cedar `/decide` over verified HTTPS,
authenticated by a per-run service key; neither redirects nor ambient proxies
are used. JWKS/decision calls have a five-second timeout and fail closed.

Every supported RPC, including ExecutePlan, AnalyzePlan and ReattachExecute,
checks `execute_plan` on `Server::"sail"` for `oidc~<verified-sub>` with verified
groups. Invalid JWTs return gRPC 16; Cedar denies return 7; unavailable decision
or JWKS dependencies return 14. The fixture grants individual users owner access
to that server resource; S1 `select` grants do not admit execution. This is broad
per-user admission, not read-only or table policy. Alice/Bob controls use genuine
Rauthy PKCE access tokens; machine controls use independent client credentials.

The gateway replaces all top-level Spark UserContext occurrences with the
verified subject, drops its untrusted extensions and strips bearer/identity
headers before forwarding. Only known unary Spark methods are supported; unknown
methods, streaming AddArtifacts and gRPC-compressed request messages are refused.
One uncompressed unary request is limited to 4 MiB. The backend is fixed at
127.0.0.1:50052 in the shared Sail/gateway network namespace. Sail binds loopback
only. The fixture uses read-only roots, dropped capabilities, no-new-privileges,
2 CPUs / 2 GiB for Sail and the owner's private 256 MiB writable tmpfs mounts.

Independent h2 connection tasks drive control frames. Backend receive windows
start at 65,535 bytes; DATA credit is returned only after downstream send capacity
accepts the bytes. Response DATA and trailers are forwarded without collecting
the whole result. A real-client local check caught trailers-only INVALID_ARGUMENT
becoming UNKNOWN through an added empty DATA frame. The regression test failed
before the fix; the relay now preserves END_STREAM on initial response HEADERS.
That test passes natively on both CPUs. Supplemental controlled JWKS/Cedar/gRPC
checks also verified wrong-issuer rejection, subject replacement, stripped tokens
and preservation of backend errors; these are not Rauthy/Sail acceptance passes.

## Table-level answer: visible syntax, incomplete enforcement

The runtime `plan-inventory.json` probe uses the exact hash-locked PySpark 4.2.0
client. The [pinned protocol](https://github.com/apache/spark/blob/32f7299601108917fb01920a54e084595b7b3bf8/sql/connect/common/src/main/protobuf/spark/connect/base.proto)
puts Plan at ExecutePlanRequest field 3 and UserContext at field 2.

| Plan surface | Visible information | Remaining authorization problem |
| --- | --- | --- |
| Read.named_table | Unparsed identifier such as catalog.namespace.table | Authoritative catalog/namespace resolution, temporary objects and stable Lakekeeper IDs are absent. |
| Read.data_source | Format and paths such as s3://bucket/prefix | No catalog table identity; direct storage paths bypass table naming. |
| SQL relations / SQL commands | SQL text and arguments | Requires compatible parsing, analysis, resolution, view expansion and action classification. |
| Relation trees and expressions | Explicit project/filter/join children | Must cover every nested dependency, subquery, UDF and session/cached reference. |
| Commands | Writes, views, functions, data sources, merge, external/pipeline operations | ExecutePlan is not synonymous with read. |
| Extensions / unknowns / compressed_operation | Opaque payload or reference | Reject or obtain trusted engine analysis; this gateway does not inspect plan nodes. Sail 0.7.3 itself rejects compressed_operation. |

A strict supported subset with trusted name resolution could be authorized at a
gateway. S3 does not implement it. **An admitted user can submit arbitrary Sail-
supported plans, including writes and direct paths.** Full table enforcement
needs a trusted resolution/enforcement point and scoped storage credentials;
S1 C5's catalog checks are not proof of gateway table authorization.

**Session gap:** the pinned [Spark handler](https://github.com/lakehq/sail/blob/ac4690078021cf2a5402dc5c7b38a886f1916c73/crates/sail-spark-connect/src/server.rs)
passes session_id/user_id separately, but the
[session manager](https://github.com/lakehq/sail/blob/ac4690078021cf2a5402dc5c7b38a886f1916c73/crates/sail-session/src/session_manager/actor/handler.rs)
looks up existing sessions by session_id without re-checking user_id. Replacing
UserContext does not isolate two admitted users who choose the same session ID.
Denied users remain blocked before Sail on every RPC. Session ownership and its
restart semantics are unimplemented/unverified and block a multi-user MVP claim.

## C1–C8 and audit remain red

No C-suite assertion was changed. S1's documented direct-claim adaptation remains,
including its original old-token membership-removal assertion and durability/
recovery assertions. The final native run retains the same failures:

| Case | amd64 | arm64 |
| --- | --- | --- |
| C1 exact namespace reads and write/other-namespace denials | PASS | PASS |
| C2 inheritance / sibling isolation | PASS | PASS |
| C3 groups plus old-token membership revocation | FAIL — old token still grants | FAIL — same |
| C4 revoke within 30 seconds | PASS | PASS |
| C5 PyIceberg / Trino / Sail | PASS — all three | PASS — all three |
| C6 no denied storage credentials | PASS | PASS |
| C7 outage and recovery | FAIL — recovery wait | FAIL — recovery wait |
| C8 durable state and repeated migrations | FAIL — restart loses state | FAIL — same; migrations not reached |

C3 reports `Denied operation succeeded`; C7 times out waiting for an allowed load
after volatile-state loss; C8 reports `Cedar restart lost relationship/grant state`.
S3 grant revocation is per fresh RPC, not IdP membership revocation or cancellation
of an already admitted stream. The resets between destructive C7/C8 cases remain
outside their assertions, as documented in S1.

The unchanged [audit job](https://github.com/datopsis/datopsis-authz/actions/runs/43895646867/job/133398353006)
reports three inherited vulnerabilities: libsqlite3-sys 0.37.0 / RUSTSEC-2026-0459
and quick-xml 0.40.1 / RUSTSEC-2026-0194, RUSTSEC-2026-0195, plus five warnings.
No upgrade, suppression or gate change was made. No cargo-deny invocation/config
exists in the base; none was disabled. Full security qualification, HA/load,
policy bundles, durable audit/state, key-rotation behavior, comprehensive Spark
compatibility and outbound token-broker/end-user propagation are not verified.

## Dependency constraint, inputs and acquisition

Only five approved direct dependencies were added, each exactly pinned to S1's
resolved version: **h2 0.4.20, bytes 1.12.1, http 1.5.0, jsonwebtoken 10.4.0,
tokio-rustls 0.26.6**. Cargo.lock gains **zero crates or versions**: its diff adds
only five authz-serve dependency edges. `scripts/check-s3-lock.py` verifies all
690 package identities, versions, sources/checksums and every other dependency
list against S1 `070522db03217da42a8fcbca590ef5c78ebc6c99`; it passes locally and in
CI. All builds use `--locked`. Rust tests/Clippy, YAML validation, LF and diff
checks pass. No GitHub settings/permissions/secrets were changed, no upstream
repository was modified, and no sign-off/coauthor trailer or force push was used.

- Platform plan section 4a / evaluation contract read at
  lakehouse-integration `369dbdec67445eb1c2931b39b45f3364ec71ead4`.
- Executable acceptance fixture: `e8379a528bf413c05aad49e56bc8cd507b5e077a`.
- Sail owner/client/probe/observer: `e96e068f926b8fecb3939e953389685ee4780032`,
  wheel 0.7.3 / upstream `ac4690078021cf2a5402dc5c7b38a886f1916c73`.
- Rauthy owner: `1e114b84b01988bf15306b110b040378878488d3`.
- PostgreSQL owner: `0ff367fae85d9685eed9d4851dce9203cccae2b2`.
  All other fixture source/image pins and provenance are retained in the summaries.

The pinned PostgreSQL rolling rhel-9 URLs returned 404, then an incomplete 200
body (5,242,880 versus 7,606,326 locked bytes). The owner's verification correctly
failed; these attempts are not passes. The explicit rhel-9.8 paths on the same
publisher contain identical locked bytes: [all eight checked downloads](S3-pgdg-mirror-check.json).
Build-only PYTHONPATH routing in `evaluation/s3/downloads/sitecustomize.py` applies
only to that exact PostgreSQL 18.6/RHEL 9.8 package family. Original HTTPS host,
size/SHA-256, key fingerprint, RPM signature and image provenance checks remain
intact; owner sources/locks and acceptance assertions are unchanged.

Earlier attempts: [43884152945](https://github.com/datopsis/datopsis-authz/actions/runs/43884152945)
and [43886130893](https://github.com/datopsis/datopsis-authz/actions/runs/43886130893)
exposed those acquisition failures. A quiet period after Sail export was initially
misread as a buildx stall; that interpretation was withdrawn after S1's successful
build timings showed 27–29 minutes and later helpers captured output. The temporary
builder override was removed. Superseded attempts were cancelled, not passed.
[43890340285](https://github.com/datopsis/datopsis-authz/actions/runs/43890340285)
then passed all S3 controls on both CPUs; its result-flow captures were inspected
separately. The authoritative final run above includes the trailers-only fix and
automated result-connection PING selector. Final source uses the owner's original
build path. Containers never ran locally; Actions is the native runtime evidence.
