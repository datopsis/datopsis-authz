# Slice 4c: adversarial review of the authorization MVP

Independent security review of slices 1–4a (serve, Lakekeeper adapter, Sail
gateway, policy/token-broker roles, hardened images), written as tests of the
**required secure behaviour**. Where the code is not secure the test still asserts
the secure outcome, so it fails. A failing test is a finding for owner triage. It
is not fixed, skipped or relaxed in this slice. Production code is unchanged; the
only production-file edits are `#[cfg(test)]` module declarations.

These are review checks, not C1–C8 passes. C1–C8 and every slice 1–3 assertion
stay unchanged and run first.

## Where the checks run

All checks run in the existing native `native (ubuntu-24.04)` / `native
(ubuntu-24.04-arm)` jobs, after every existing step, so a finding never hides
earlier evidence. Results are uploaded under `reports/s4c/` in the retained
evidence artifact.

| Step | Source | What it drives |
| --- | --- | --- |
| Slice 4c adversarial unit tests | `crates/*/src/adversarial*.rs`, `crates/authz-serve/src/adversarial/` | Real Cedar evaluation, OPA wire adapter, gateway JWT admission (in-process verified TLS/HTTP2 JWKS mock, per-run openssl keys), relay, protobuf identity rewrite, live membership lookup |
| Image filesystem and configuration checks | `scripts/adversarial-images.py` | `docker export` of both built images |
| Serve harness | `scripts/adversarial-serve.py` | The shipped `authz` binary, private TLS PostgreSQL with a non-superuser service role, mock Rauthy |
| Runtime | `evaluation/s4c/run.py` | Unchanged S2 fixture: Rauthy, Lakekeeper + Cedar adapter, serve, stock Trino 484 OPA |

The unit tests are `#[ignore]`d so the image build's `cargo test` stays the
existing regression gate. The dedicated step runs them with `--ignored`. Locally:
`cargo test -p authz-core -p authz-serve --locked -- --ignored adversarial`
(Linux; needs the `openssl` CLI).

## Findings (this repository only)

| ID | Area | Severity | Required secure behaviour | Actual | Tests |
| --- | --- | --- | --- | --- | --- |
| F1 | Relationship store / Cedar | High | One grant must not affect decisions for unrelated principals | Any resource owner can add a grant whose subject ID contains a control character (for example U+0001). JSON escaping produces `\u0001`, which Cedar rejects, so **every** later decision for every principal is an evaluation error (platform-wide fail-closed outage until the grant is removed through `/mutate`) | `adversarial_one_unrepresentable_grant_cannot_deny_service_to_everyone`; harness `grant_subject_cannot_disable_all_decisions` |
| F2 | Trino bindings | High | A SQL name may authorize only the table it was bound to | `iceberg.<ns>.<name>` stays bound to the old UUID after an in-place rename. Lakekeeper calls the detach/attach hooks only when a rename changes namespace, contrary to docs/TRINO.md. A new table created under the old name is read through the privileged connector with the **old** table's grants | runtime `rename_in_place_stale_binding`; control `drop_and_recreate_same_name` |
| F3 | Sail gateway / serve credentials | Medium | The internet-facing gateway's credential must not administer grants | The gateway's `AUTHZ_KEY_FILE` is serve's single native key. It authorizes `/mutate`, `/snapshot`, `/permissions` and `/decide` as well as `/sail/groups`. Trino already has a separate decision-only key | `adversarial_gateway_credential_cannot_administer_the_relationship_store` |
| F4 | Audit | Medium | The serve credential must not be able to erase audit rows | serve runs migrations with its runtime credential, so it owns `authz_audit`. It can disable or drop the append-only trigger and then delete or truncate (the harness always rolls back). The CI fixture also uses the database owner | harness `audit_tamper_resistant_to_service_credential`; runtime `audit_owner_separation` |
| F5 | Trino column masks | Medium | A bound sensitive column is masked, or the binding is refused | Mask matching is case-sensitive. Trino presents lower-case column names, so a binding spelled `Email` (for example copied from catalog metadata) is never masked. This fails open, whereas table bindings fail closed | `adversarial_trino_mask_applies_regardless_of_column_name_case` |
| F6 | Live membership lookup | Low | Look up exactly the principal's own Rauthy user, or refuse | The subject is not validated before URL construction. `oidc~` queries `/auth/v1/users/` and accepts a response with `id: ""`. `.` and `..` query the users collection, and control characters are dropped (`a\nb` looks up `ab`). The `id` equality check prevents a wrong grant in every case except the empty subject | `adversarial_membership_lookup_cannot_escape_the_user_resource` |

### Observations without a failing test

- O1 (availability): every unauthenticated gateway RPC with an RS256 header and
  `kid` triggers a JWKS fetch and a durable audit insert. This gives request
  amplification toward Rauthy and unbounded audit growth. No load test was added.
- O2 (low): service credentials (`Authorization` header, OPA `serviceKey`) are
  compared with non-constant-time equality. No timing test was added because it
  would be flaky on shared runners.
- O3 (low/medium): `lakekeeper-authz` falls back to bootstrap principal
  `oidc~operator` when `AUTHZ_BOOTSTRAP_PRINCIPAL` is unset, instead of refusing
  startup. Not tested: adapter unit tests would need Lakekeeper compiled on the host.
- O4 (low, audit attribution): a token that expires during body upload is audited
  as `unauthenticated` even though its subject was verified.
- O5 (info): unknown Rauthy users (404) are denied with HTTP 503 and audit reason
  `identity_provider_unavailable`. The outcome fails closed, but the label is misleading.

## Secure behaviour confirmed by passing tests

Cross-team reads, writes, discovery and grant management deny. Identifier case,
Unicode, separator and quote tricks do not alias resources. ID text cannot inject
Cedar policy. Upward discovery never yields data or management. Detach, delete
and group removal revoke immediately. Explicit-deny and anonymous checks never
permit.

JWT checks reject all of the following: expired, `exp`/`nbf` edge cases, wrong,
missing or case-changed issuer and audience, empty or missing `sub`, `alg=none`,
HS256 keyed with the RSA public key, RS384/RS512/PS256, wrong key under the same
`kid`, unknown or missing `kid`, payload swap, stripped or truncated signatures,
oversize (1 MiB) and malformed tokens, an `oct` JWK, and strict `Bearer` framing.
JWKS failures fail closed: HTTP error, redirect, malformed, empty, over 4 MiB,
untrusted TLS and unreachable.

On the Sail path, an audit outage refuses with UNAVAILABLE before any backend
connection. Membership is resolved again for every RPC on a reused connection.
Zero, ambiguous or look-alike team groups never reach a backend. The relay strips
`authorization`, cookies, forwarded and asserted identity headers. The protobuf
identity rewrite removes every client `UserContext` and rejects groups, field 0,
truncation, overflow, compression and multiple messages. Endpoint and team
configuration is fail-closed.

On the Trino path, cross-team tables, schemas and catalogs deny, and other
catalogs, hidden `$files`/`$snapshots`-style tables and look-alike names deny.
Writes, DDL, procedures, impersonation and admin operations deny even for owners.
Row-filter identifiers and literals are quoted. Unknown or unreadable tables get
FALSE/NULL obligations.

Live membership never falls back to cached groups on error, disabled, mismatched
or malformed users. Revocation is visible within 250 ms, the cache stays within
its bound, and non-OIDC principals never reach Rauthy. Malformed service
credentials are refused.

The serve harness and runtime suite add the following checks on the real binary
and the real stack:

- SQL-injection strings are stored verbatim.
- Asserted Trino and `/decide` groups are ignored.
- Rauthy timeout, redirect, mismatch, disabled user and 5xx fail closed within
  5 s and are audited.
- Database lock contention fails closed.
- A batch with one unverifiable identity returns no verdicts.
- Denials and errors are audited before the response.
- Oversized bodies are rejected.
- Rauthy TLS is verified (plain HTTP refused, wrong CA denied).
- No credential appears in logs, audit or graph.
- Metadata, stats, mask/row-filter predicate oracles, writes and impersonation
  are checked through stock Trino.

Native per-architecture results are in the PR and in `reports/s4c/`.

## Not verified by this slice

- Lakekeeper adapter decisions in isolation (`lakekeeper-authz` unit tests would
  compile Lakekeeper on the host). They remain covered only by C1–C8.
- New live Sail runtime cases. JWT and admission cases run in process against the
  real gateway code, while the live Sail path relies on the unchanged S3 suite.
- Load or denial-of-service behaviour (O1), timing side channels (O2) and HTTP/2
  framing attacks below the `h2` crate.
- TLS on hops configured inside upstream components (Lakekeeper to PostgreSQL,
  Rauthy and storage). The standing storage-credential rule (docs/TRINO.md,
  docs/SAIL.md) is a documented deployment requirement and is not exercised.
- `token-broker` is unimplemented and refuses startup. The existing image checks
  cover that refusal.
