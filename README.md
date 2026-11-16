# datopsis-authz (working name)

Apache-2.0 authorization platform spike. The owner will rename this repository.
**S1 is evaluation-only, not an MVP or a production authorizer.** An owner go/no-go
is required before MVP work.

S1 proves unmodified-source Lakekeeper composition and the Cedar catalog path on
native amd64 and arm64. C1/C2/C4/C5/C6 pass; C3/C7/C8 fail on old-token membership
revocation and volatile relationship state. The audit gate also remains red.
The report links actual runs and retained sanitized evidence.

The intended platform is one Rust program/image with `serve`, `sail-gateway`,
`token-broker`, and `policy` roles. S1 implements only `serve` and schema validation
under `policy`; other roles fail explicitly. A separate thin Lakekeeper binary
compiles the adapter into the catalog, using unmodified pinned upstream crates.

`authz-core` embeds Cedar 4.14.1, a schema, resource hierarchy and grant evaluator.
`authz-serve` is its HTTPS API with per-run service credentials and an in-memory
store. It trusts authenticated adapter assertions, not client-supplied JWT claims.
Lakekeeper verifies OIDC tokens and passes verified `groups` through its token-role
metadata. Never expose the decision/mutation API to catalog clients.

S2 adds Trino 484 OPA-compatible decisions, list filtering, row-filter and mask
endpoints to the same serve role; see [the S2 report](docs/spikes/S2-trino-opa.md).

See [the S1 report](docs/spikes/S1-lakekeeper-adapter.md) for coverage and limitations.

## Development

Install the pinned Rust toolchain and native prerequisites (`protobuf-compiler`,
`pkg-config`, `libssl-dev`). Run `git config core.hooksPath .githooks`,
`cargo test --workspace --locked`, `cargo fmt --all -- --check`, and
`python3 scripts/check-lf.py`. Use `CARGO_BUILD_JOBS=2` on small machines.

`authz-serve serve` requires `AUTHZ_TLS_CERT`, `AUTHZ_TLS_KEY`, `AUTHZ_KEY_FILE`.
The adapter requires `AUTHZ_ENDPOINT=https://…`, `AUTHZ_CA_FILE`, `AUTHZ_KEY_FILE`.
The bootstrap principal defaults to `oidc~operator` and can be set with
`AUTHZ_BOOTSTRAP_PRINCIPAL`. No default service secret exists.
TLS to Lakekeeper uses the evaluation's approved loopback nginx proxy.
