# S3: Sail gateway (in progress)

This is a bounded feasibility spike stacked on S1, not the MVP. No acceptance
or runtime success is claimed yet. The gateway implementation is pending approval
for direct dependencies already present in the inherited lockfile.

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

No run links or PR exist yet. Local Python syntax compilation of the prepared
harness passes; that is not runtime evidence.

## Planned boundary

Retain one platform program/image. Add the `sail-gateway` role to authz-serve,
reuse authz-core through the existing HTTPS Cedar decision service, terminate TLS,
and authenticate requests against a configured HTTPS JWKS endpoint, issuer,
audience and expiry. Use per-user ExecutePlan admission as the minimum gate.
The transport experiment must drive the upstream HTTP/2 connection independently
from downstream DATA flow, preserve gRPC status/trailers, and bound buffered data.

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
