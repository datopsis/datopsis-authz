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
identity headers before forwarding. This prevents client-selected user IDs from
selecting another principal's Sail session. It accepts only known unary Spark
Connect methods, one uncompressed message up to 4 MiB; unknown methods,
compressed requests and streaming AddArtifacts are refused. It does not decode
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

Table-level authorization is an open question in this spike. A Spark Connect plan
can contain named relations, SQL text, paths, temporary/session objects, commands
and extensions. Extracting visible names alone does not establish a complete,
resolved set of table accesses or trustworthy read/write semantics. S3 must
report the actual boundary without claiming that a per-user gate enforces table
policy. A diagram update is required when the implemented design is established.

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
