# S3: Sail gateway (in progress)

This is a bounded feasibility spike stacked on S1, not the MVP. No acceptance
or runtime success is claimed yet. The gateway is implemented; native container evidence is pending. This report
will record actual Actions outcomes before the spike is concluded.

## Inputs

Read README.md, AGENTS.md, CLAUDE.md and the S1 report on
`room/datopsis-authz-spike-s1-lakekeeper-adapt-w46b` before starting.

- Platform plan section 4a and C1–C8 contract:
  `datopsis/lakehouse-integration` main resolved to
  `369dbdec67445eb1c2931b39b45f3364ec71ead4` when read.
- Executable acceptance fixture stays pinned to S1's
  `e8379a528bf413c05aad49e56bc8cd507b5e077a`.
- Sail owner image, client locks, paced probe, passive HTTP/2 observer and reset
  report: `datopsis/sail-ubi` at
  `e96e068f926b8fecb3939e953389685ee4780032`.
  Its artifact lock identifies Sail 0.7.3 source
  `ac4690078021cf2a5402dc5c7b38a886f1916c73`.
- Rauthy owner build: `1e114b84b01988bf15306b110b040378878488d3`.

External checkouts are immutable evaluation inputs. No other repo is modified.
S1's C1–C8 assertions and reported failures remain unchanged.

## Questions and required evidence

| Check | amd64 | arm64 |
| --- | --- | --- |
| Valid Rauthy JWT reaches real ExecutePlan and returns Arrow data | NOT RUN | NOT RUN |
| Missing / genuine expired / wrong audience / different signing key refused | NOT RUN | NOT RUN |
| Authenticated principal denied by Cedar receives PERMISSION_DENIED | NOT RUN | NOT RUN |
| Verified TLS, wrong CA/name and plaintext refusal | NOT RUN | NOT RUN |
| Backend 127.0.0.1:50052 unreachable from another container | NOT RUN | NOT RUN |
| Million rows, first 16 Arrow batches paced at 5 seconds, exact IDs/sum/hashes | NOT RUN | NOT RUN |
| Backend PING/ACK before deadline during that stream, lossless passive capture | NOT RUN | NOT RUN |

Run links and results are pending. Local `cargo check -p authz-serve --locked`,
Python syntax compilation, YAML validation, formatting and LF checks pass; these
are not runtime acceptance evidence.

## Implemented boundary

The existing authz-serve binary/image now implements `sail-gateway` alongside
`serve` and `policy`; token-broker remains unimplemented. It authenticates RS256
JWTs using HTTPS JWKS, issuer, audience, mandatory expiry and zero clock leeway.
Each RPC fetches JWKS and calls the existing Cedar `/decide` over verified HTTPS
with the per-run service credential. Upstream TLS uses the per-run CA; redirects
and ambient proxy settings are not used. JWKS/decision calls time out after five
seconds and fail closed. No credentials or raw plans appear in gateway logs.

Every supported RPC, including ExecutePlan and ReattachExecute, asks Cedar for
`execute_plan` on `Server::"sail"` with principal `oidc~<verified-sub>` and verified
groups. Missing/invalid JWTs return gRPC UNAUTHENTICATED (16); Cedar denies return
PERMISSION_DENIED (7); unavailable dependencies return UNAVAILABLE (14). S1's
`select` grants do not permit this action. The fixture grants individual users
owner access to this one server resource. This broad grant is per-user admission,
not table or read-only authorization. No new Cedar policy language is invented.

The gateway replaces all top-level protobuf UserContext fields with the verified
subject, dropping asserted identity/extensions, and strips credentials and other
identity headers before forwarding. This stops an unverified UserContext from
becoming Sail's recorded user identity; it does not establish session ownership. It accepts only known unary Spark
Connect methods, one uncompressed message up to 4 MiB; unknown methods,
gRPC-compressed request messages and streaming AddArtifacts are refused. It does not decode
or authorize individual plan nodes. Backend address is fixed at 127.0.0.1:50052;
Sail shares the gateway's network namespace and listens only on loopback.

Independent h2 connection tasks drive frontend/backend control frames. Backend
stream/connection receive windows start at 65,535 bytes; upstream DATA credit is
returned only after downstream send capacity accepts the bytes. gRPC response
headers, DATA and trailers are forwarded, preserving the real final status.
Downstream waits of at least one second are recorded with timestamps so the
passive PING capture can prove overlap with backpressure. This is bounded flow
control, not buffering the complete result or changing Sail's keepalive timers.
See [the S3 topology](../diagrams/s3-sail-gateway.svg); the shared architecture
diagram also records the gateway role.

## Table-level answer: visible syntax, incomplete enforcement

The hash-locked PySpark 4.2.0 descriptor probe passes locally and is repeated in
native CI (`plan-inventory.json`). The
[pinned Spark protocol](https://github.com/apache/spark/blob/32f7299601108917fb01920a54e084595b7b3bf8/sql/connect/common/src/main/protobuf/spark/connect/base.proto)
puts the plan at ExecutePlanRequest field 3 and UserContext at field 2.

| Plan surface | What a gateway can observe | Why it is insufficient for general table authorization |
| --- | --- | --- |
| Read.named_table | `unparsed_identifier`, e.g. catalog.namespace.table | Requires authoritative catalog/namespace resolution and distinction between temporary/session objects and catalog tables; no stable Lakekeeper table ID is provided. |
| Read.data_source | Format and paths, e.g. parquet at s3://bucket/prefix | No catalog table identity; direct storage reads can bypass table naming entirely. |
| Relation.sql / Command.sql_command | SQL query text and arguments | Requires Spark-compatible parsing, analysis, resolution, view expansion and action classification; string matching cannot establish the touched objects. |
| Project/filter/join and other relation trees | Explicit child relations and expressions | A complete walker must cover every nested form, UDF/subquery and dependency, including views and session references. |
| Commands | Write operations, view/function/data-source registration, merge, external/pipeline commands | ExecutePlan is not synonymous with read; relation-only checks would miss writes and state changes. |
| Local/cached relations, extensions, unknowns and compressed_operation | Data or opaque references/payloads | No complete table set is present in the request; unknown/opaque forms require rejection or trusted engine analysis. |

A strict subset gateway could reject every unrecognized form and admit only
explicitly supported operations, with trusted name resolution. This spike does
not implement that subset or resolve table identities. **The implemented gate is
per-user admission to the Sail server, not per-table authorization.** An admitted
user can submit arbitrary supported Sail plans, including writes and direct paths;
no table-level or read-only guarantee is claimed. Full enforcement needs a
trusted resolution/enforcement point in the engine/catalog and appropriately
scoped storage credentials.

**Additional source-level gap:** the pinned
[Spark handler](https://github.com/lakehq/sail/blob/ac4690078021cf2a5402dc5c7b38a886f1916c73/crates/sail-spark-connect/src/server.rs)
passes session_id and user_id separately, but the
[session manager](https://github.com/lakehq/sail/blob/ac4690078021cf2a5402dc5c7b38a886f1916c73/crates/sail-session/src/session_manager/actor/handler.rs)
looks up an existing session by session_id without re-checking user_id. Merely
replacing UserContext cannot isolate two admitted users who choose the same
session ID. Denied users remain blocked on every RPC before reaching Sail.
Session ownership enforcement, restart behavior and cross-user session tests
remain unimplemented/unverified; this is a material limit for any multi-user MVP.

The prepared harness reuses the owner's unmodified million-row probe with retry
mode `none`, checking exact unique IDs, every SHA-512 payload and the ID sum.
It records control frames through the pinned passive observer, never packet
bodies, private keys or TLS session secrets. Any arbitrary transport failure is a
failure; only the exact historical INTERNAL/RST_STREAM 2 at 70–90 seconds can be
classified as the previous reset. No retry or alternate workload replaces it.

## Dependency constraint and checks

Coordinator approval permits exactly five new direct dependencies, each already
resolved in S1: h2 0.4.20, bytes 1.12.1, http 1.5.0, jsonwebtoken 10.4.0 and
tokio-rustls 0.26.6. Cargo.toml uses exact version constraints. The Cargo.lock diff
contains only those five dependency edges on authz-serve: **zero new packages or
versions**. `scripts/check-s3-lock.py` compares all 690 package identities,
versions, sources and checksums, and all other dependency lists, against immutable
S1 commit `070522db03217da42a8fcbca590ef5c78ebc6c99`. It runs in CI. All builds use
`--locked`. The inherited `cargo audit` step remains unchanged; this repository
has no cargo-deny invocation/configuration to alter. No advisory is suppressed.

S3 runs before S1's unchanged C1–C8 assertions, using a separate runtime directory.
Its test outcome remains blocking even though CI continues to collect the C-suite
results after an S3 failure. No human sign-off, settings/permissions change, merge
or force push is part of this spike. Per-run CA, keys and tokens stay outside Git
and uploaded evidence; only sanitized reports and control-frame counters are
retained for 14 days.

## Audit status

The unchanged [lint job](https://github.com/datopsis/datopsis-authz/actions/runs/43884152945/job/133357613888)
ran the lock inventory gate successfully, then `cargo audit` failed with three
inherited vulnerabilities: libsqlite3-sys 0.37.0 / RUSTSEC-2026-0459 and
quick-xml 0.40.1 / RUSTSEC-2026-0194, RUSTSEC-2026-0195. Five inherited warnings
were also emitted. The actual job log was read. No dependency upgrade, suppression
or audit-gate change was made. This spike cannot claim security qualification.

## Fixture acquisition correction

The first [amd64 job](https://github.com/datopsis/datopsis-authz/actions/runs/43884152945/job/133357614232)
compiled and tested the workspace, passed HTTPS smoke and the Micro loader probe,
then stopped before runtime: the pinned PostgreSQL owner's rolling
`rhel-9-x86_64` URLs returned 404 for PostgreSQL 18.6 RPMs. No S3 or C-suite runtime
pass is claimed for that attempt.

The publisher's explicit `rhel-9.8-{x86_64,aarch64}` directories contain the exact
same eight locked packages. All eight downloads were SHA-256 checked against the
immutable owner locks; see [the retained checks](S3-pgdg-mirror-check.json). The
unmodified owner's downloader was also exercised locally with its original URL,
locked size and SHA-256 checks, and completed through the fallback.

A build-step-only PYTHONPATH loads `evaluation/s3/downloads/sitecustomize.py`.
Only the exact PostgreSQL 18.6/RHEL 9.8 package family is routed to the same
publisher's explicit minor-release path. Other URLs, versions and architectures
retain their original behavior. The first correction retried only 404s; the
[second amd64 job](https://github.com/datopsis/datopsis-authz/actions/runs/43886130893/job/133364641151)
then correctly failed the owner's locked-size assertion because the rolling
server-RPM alias returned an incomplete HTTP 200 body (5,242,880 bytes versus
7,606,326 expected). Explicit routing avoids both alias failure modes. The
unmodified owner downloader also passes locally for the complete server RPM
using its exact locked size and SHA-256. Owner HTTPS host restrictions,
size/hash verification, signing-key fingerprints, RPM signatures and provenance
checks remain unchanged. No owner checkout or lockfile is modified. This changes
artifact acquisition transport, not any acceptance assertion or shipped image
input. The workaround is evaluation-only, not a general dependency mirror.
