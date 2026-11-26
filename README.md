# datopsis-authz (working name)

Apache-2.0 catalog authorization service, catalog slice 1 and Trino slice 2 of the owner-approved MVP
(2026-11-17). The owner will rename this repository. The four spike PRs remain
open as evidence. Native C1–C8 and dependency-gate results are recorded in the PR;
unverified work is not an acceptance pass.

The fixture pins coordinator-approved Rauthy PR #3 at
`1bedace6e61627820e0f863a86c6ccc791f5e22b` (verified FIDO serial 303).
That PR is unmerged and its SvelteKit vulnerability gate remains RED pending
an owner decision. This test pin does not claim image security qualification.
The runtime dependency gate also blocks on Lakekeeper's Azure/quick-xml path.
Owner decision 2026-11-18: "upstream Lakekeeper, Azure path, no fix yet; upstream proposal in progress".
Lint stays red with no ignore or S3-only patch; merge waits for upstream's fix.
C1–C8 results will be recorded after native Actions validation.

One Rust workspace produces the platform program (`authz-serve`, installed as
`datopsis-authz`) and a thin Lakekeeper binary containing `lakekeeper-authz`.
`serve` evaluates Cedar against a PostgreSQL relationship/grant store.
`migrate` applies the repeatable schema. `policy` validates the Cedar schema.
`sail-gateway` and `token-broker` return an explicit unsupported-role error.
Trino enforcement uses the same serve role through its OPA-compatible API; see
[Trino setup and semantics](docs/TRINO.md). Sail admission, policy bundles/analysis
and hardened release images belong to later slices. The existing C5 engine/client catalog checks remain.

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
`AUTHZ_RAUTHY_CA_FILE`, `AUTHZ_RAUTHY_KEY_FILE`. `migrate` needs the database
variables only. All secret files must be protected. `AUTHZ_LISTEN` defaults to
`0.0.0.0:8443`. The database URL is read from a file; do not put credentials on
command lines. Verification cannot be downgraded by URL options.

The adapter needs `AUTHZ_ENDPOINT=https://…`, `AUTHZ_CA_FILE`, `AUTHZ_KEY_FILE`.
`AUTHZ_BOOTSTRAP_PRINCIPAL` defaults to `oidc~operator`. Explicit machine subjects
must be provisioned in `AUTHZ_MACHINE_PRINCIPALS` (comma-separated); they never
receive group membership from a missing-user response. There are no default
service credentials. Keep serve isolated from catalog clients.
