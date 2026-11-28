# datopsis-authz (working name)

Apache-2.0 catalog authorization service, catalog slice 1, Trino slice 2 and Sail slice 3 of the owner-approved MVP
(2026-11-17). The owner will rename this repository. The four spike PRs remain
open as evidence. Native C1–C8 and dependency-gate results are recorded in the PR;
unverified work is not an acceptance pass.

The fixture pins coordinator-approved Rauthy PR #3 at
`52c3fec20beca1975467a9c955730082cef8bf46` (verified FIDO serial 303).
That PR adds a hash-keyed FIDO cache and is unmerged. Its known SvelteKit
vulnerability gate remains RED pending an owner decision. This test pin does not claim image security qualification.
The runtime dependency gate also blocks on Lakekeeper's Azure/quick-xml path.
Owner decision 2026-11-18: "upstream Lakekeeper, Azure path, no fix yet; upstream proposal in progress".
Lint stays red with no ignore or S3-only patch; merge waits for upstream's fix.
C1–C8 results will be recorded after native Actions validation.

One Rust workspace produces the platform program (`authz-serve`, installed as
`datopsis-authz`) and a thin Lakekeeper binary containing `lakekeeper-authz`.
`serve` evaluates Cedar against a PostgreSQL relationship/grant store.
`migrate` applies the repeatable schema. `policy` validates the Cedar schema.
`sail-gateway` admits users to isolated team engines; its private `sail-socket` helper
bridges each engine’s loopback listener to the gateway. `token-broker` fails closed until implemented.
Trino enforcement uses the same serve role through its OPA-compatible API; see
[Trino setup and semantics](docs/TRINO.md). See [Sail configuration and team isolation limits](docs/SAIL.md). Policy bundles/analysis
belong to later slices. Slice 4a adds [hardened authz and lakekeeper-authz images](docs/IMAGES.md), pending security admission. The existing C5 engine/client catalog checks remain.

Implemented catalog behavior: owner and select grants, inherited resource
permissions, item-filtered discovery, namespace/table/view lifecycle hooks,
rename detach/attach, and owner-authorized grant read/add/remove endpoints.
Unsupported role assumption, delegated checks, role administration and other
permission routes deny. Fresh human JWTs with empty group claims retain the
upstream RoleSourceIdError compatibility gap; C3 checks the retained old token. See [architecture](docs/ARCHITECTURE.md) for the API and
limits, and [security](SECURITY.md) for deployment requirements.

Human membership is looked up live against Rauthy over verified HTTPS with a
250 ms cache. JWT groups are ignored. After expiry of that cache, unavailable or
malformed IdP responses fail closed. The fixture uses 900-second access tokens
as a backstop and a separate 30-second expiry control. Epoch synchronization is
deferred. PostgreSQL always uses `verify-full`; decisions and their durable,
append-only audits commit before responses. Database/audit failures return 503.

## Development

Use Rust 1.94.1, `protobuf-compiler`, `pkg-config`, `libssl-dev` and Python 3.
Under the owner's CI-first policy, local checks are limited to lightweight work:


```
git config core.hooksPath .githooks
cargo test --workspace --locked
cargo fmt --all -- --check
python3 scripts/check-lf.py
```

Use `CARGO_BUILD_JOBS=2` on small machines. CI builds/runs identical catalog
assertions on native amd64/arm64 and retains sanitized evidence. Required jobs
are exactly `lint` and `test`. Local component checks do not substitute for C1–C8.
Image builds, artifact acquisition/unpacking, vulnerability scans and all
container/runtime and multi-architecture checks (including `scripts/tls-smoke.py`)
run only in the existing PR Actions jobs. Do not rerun unchanged expensive checks;
read their logs/artifacts. Use one checks watcher at a time and stop background
work at each step's end. No external source repository is modified.

For `serve`, configure `AUTHZ_TLS_CERT`, `AUTHZ_TLS_KEY`, `AUTHZ_KEY_FILE`,
`AUTHZ_DATABASE_URL_FILE`, `AUTHZ_DATABASE_CA_FILE`, `AUTHZ_RAUTHY_USERS_URL`,
`AUTHZ_RAUTHY_CA_FILE`, `AUTHZ_RAUTHY_KEY_FILE`. All secret files must be protected.

Three separate credentials, each at least 32 characters, must all differ:

| File | Holder | Accepted on |
| --- | --- | --- |
| `AUTHZ_KEY_FILE` (admin) | Lakekeeper adapter, operators | `/mutate`, `/snapshot`, `/permissions`, `/decide` |
| `AUTHZ_DECISION_KEY_FILE` (optional) | Sail gateway (as its `AUTHZ_KEY_FILE`) | `/sail/groups`, `/decide` |
| `AUTHZ_TRINO_KEY_FILE` (optional) | Trino `opa.context-file` | `/opa/*` |

Without a decision key, `/sail/groups` rejects every request. Credentials are
compared in constant time.

**Database logins.** `serve` and `sail-gateway` never run DDL. Run `migrate` as a
separate step with the schema-owner login in `AUTHZ_DATABASE_URL_FILE`, and set
`AUTHZ_RUNTIME_ROLE` to the separate runtime login (`[a-z_][a-z0-9_]*`).
`migrate` grants it `SELECT, INSERT` on `authz_audit` and `SELECT, UPDATE` on
`authz_state`, revokes schema `CREATE`, and fails unless the result is least
privilege. `serve` and `sail-gateway` refuse to start if their login is a superuser,
owns either table, or can `UPDATE`, `DELETE` or `TRUNCATE` the audit or create
objects in the schema. A table owner can always disable triggers, so only this
split makes the append-only audit tamper-resistant against the service credential. `AUTHZ_LISTEN` defaults to
`0.0.0.0:8443`. The database URL is read from a file; do not put credentials on
command lines. Verification cannot be downgraded by URL options.

The adapter needs `AUTHZ_ENDPOINT=https://…`, `AUTHZ_CA_FILE`, `AUTHZ_KEY_FILE`.
`AUTHZ_BOOTSTRAP_PRINCIPAL` (`oidc~<subject>`) is required; the catalog refuses
to start without it. Explicit machine subjects
must be provisioned in `AUTHZ_MACHINE_PRINCIPALS` (comma-separated); they never
receive group membership from a missing-user response. There are no default
service credentials. Keep serve isolated from catalog clients.

## Images

The `authz` image runs the single platform binary with an explicit role.
The `lakekeeper-authz` image compiles our Cedar adapter into unmodified Lakekeeper
0.13.9. Both use locked UBI 9 source builds, Micro runtimes, UID 10001, verified
TLS, cargo-auditable inventories and blocking image/RustSec gates.
See [image configuration, runtime controls and admission](docs/IMAGES.md).
Known quick-xml findings still block release; neither image is security-qualified.

RustSec admission follows the owner's 2026-11-27 fixability rule: shipped
advisories with patched versions block, no-patch advisories are reported and
tracked, and build-only/unselected crates are report-only. See
[scheduled advisory tracking](docs/RUSTSEC-TRACKING.md). The coordinator-approved
axum-server 0.9.2 refresh removes rustls-pemfile without changing TLS policy.
