# S1: Lakekeeper authorizer adapter with Cedar

Status: **in progress; no MVP go decision**. Working name: datopsis-authz.
This is a bounded feasibility spike, not production qualification.

## Inputs and binding decisions

- [Platform plan R1–R11](https://github.com/datopsis/lakehouse-integration/blob/e8379a528bf413c05aad49e56bc8cd507b5e077a/docs/AUTHZ-PLATFORM-PLAN.md),
  [acceptance contract](https://github.com/datopsis/lakehouse-integration/blob/e8379a528bf413c05aad49e56bc8cd507b5e077a/docs/AUTHZ-EVALUATION.md),
  DECISIONS.md, IDP-BAKEOFF.md, ARCHITECTURE.md and evaluation code read at that same pin.
- [Lakekeeper 0.13.4 source](https://github.com/lakekeeper/lakekeeper/tree/9bd377162345b64a716f0a4fcffe4e7e7f3c7534),
  including service/authz, lakekeeper-bin and authz-openfga. No upstream patches.
- Rauthy image repository: `1e114b84b01988bf15306b110b040378878488d3`.
- Owner's 2026-11-15/16 instructions supersede the plan's older multi-repository
  proposal: **one monorepo, one platform program/image with roles**, plus an
  adapter compiled into a thin Lakekeeper binary. Cedar library, Apache-2.0.
  Spikes first; the owner decides go/no-go before any MVP work.

## Q1: Trait surface

The public `lakekeeper::service::authz::Authorizer` declares **38 methods**, including
one `open-api`-gated method: **37 without OpenAPI**. Nine associated action types.
`HealthExt` adds two required async methods. Default methods are included in the 38;
six have defaults, leaving 32 required with OpenAPI or 31 without. See the pinned
[trait](https://github.com/lakekeeper/lakekeeper/blob/9bd377162345b64a716f0a4fcffe4e7e7f3c7534/crates/lakekeeper/src/service/authz/mod.rs#L1569).

| Surface | Count | Methods / meaning |
| --- | ---: | --- |
| Identity/config/router | 6 | implementation_name, server_id, set_registered_idp_ids, managed_role_provider_ids, api_doc (gated), new_router |
| Decisions / discovery | 13 | check_assume_role_impl, can_bootstrap, can_search_users_impl, list_projects_impl; nine are_allowed_*_actions_impl batches (user, role, server, project, warehouse, namespace, table, view, generic_table) |
| Lifecycle writes | 16 | bootstrap; delete_user; create/delete role, project, warehouse, namespace, table, view, generic_table |
| Assignment facet | 1 | role_assignments returns optional ManagesRoleAssignments; that separate trait has three methods: add, remove, paginated list |
| Rename hierarchy | 2 | detach_tabular_parent before commit, attach_tabular_parent after commit/compensation |

No method requires an OpenFGA type. Backend errors and action types are generic.
OpenFGA's tuple model, migrations, reconciliation, permission-assignment routes,
and optional assignment-source facet are implementation-specific. The facet is
optional: returning None keeps role assignments in Lakekeeper's catalog database.
OpenFGA's default source factory selects OpenFGA or AllowAll; an arbitrary external
backend name **does not load a plugin**.

Permission-management endpoints are not free implementations in the base trait.
`new_router` supplies backend routes; upstream OpenFGA's router and API types are
its own surface. The S1 adapter supplies an empty router: no permission-management
API parity. Core catalog management checks still call the decision methods; S1
allows only Cedar self-read for user introspection and denies other user/role
checks, role assumption and delegated/other-user checks.

List filtering uses batch authorization, including `IncludeInList` and
`ListEverything`; an overly broad ListEverything would bypass item filtering.
S1 forwards item checks and never grants ListEverything to select-only readers.
`list_projects_impl` returns Unsupported, asking Lakekeeper to filter individually.

**Out-of-tree feasibility:** source-visible public trait and public serve builder
permit composition. S1 uses full pinned git dependencies, including the public
PostgreSQL backend. The thin binary selects only Cedar; it has no AllowAll fallback.
Published-crate compatibility has not been tested. S1 builds the default feature
set only; enabling upstream open-api also requires implementing the adapter’s
api_doc method. That feature combination is not qualified. This is a 0.x trait, with async
methods, generics, nine associated types and evolving hooks; treat it as a pinned
source API, not a stable plugin ABI. Every upstream bump needs a compile and
behavior gate. Local `cargo check --workspace --locked` passes with Rust 1.94.1. Runtime evidence will be linked below.

Out-of-tree builds must carry upstream’s `tracing_unstable` and `tokio_unstable`
cfgs and `SQLX_OFFLINE=true`; dependency workspace Cargo configuration does not
propagate. Source hashes and the complete method list are in
[S1-source-inventory.json](S1-source-inventory.json).

## Q2: Minimal path and boundaries

The workspace has authz-core, authz-serve, lakekeeper-authz and
lakekeeper-bin-datopsis. Core embeds Cedar 4.14.1, a JSON schema, parent graph and
owner/select grants. Lakekeeper verifies JWTs through upstream OIDC; the adapter
extracts only verified `oidc` token roles (`groups`) and user identity. Authz-serve
accepts assertions only from the trusted adapter, authenticated with a per-run
service credential over verified HTTPS. It does not independently validate JWTs.

The thin binary uses upstream configuration, PostgreSQL catalog/secrets,
core migrations and authenticator. It deliberately omits UI, event sinks and
production operational CLI parity. The relationship store is **in memory**, as
permitted for S1; restart durability and outage recovery are not implemented.
Cedar policies are currently generated from grants per request. Policy mode parses the schema; generated policies undergo Cedar strict validation
before evaluation. Full policy bundles, context-sensitive rules and analysis are
MVP gaps. Audit is sanitized stdout, not durable or tamper-evident. Generated
policy IDs currently depend on grant order; stable grant IDs and bundle hashes
are needed for durable attribution.

[Architecture SVG](../diagrams/authz-architecture.svg) shows the single program's
roles and adapter. Only serve and a minimal policy schema check are implemented;
sail-gateway, token-broker, OPA and policy analysis belong to later spikes/MVP.
No other repository was modified.

The selected public-crate graph dynamically links OpenSSL. Unlike the upstream
release binary, it cannot run in the owner-built minimal runtime without
libssl.so.3/libcrypto.so.3. The spike collects this matching pair and any additional non-glibc dependencies
reported by ldd from the same native UBI compiler environment, records their
SHA-256 values, and checks the catalog version command in the final image. A
loader probe against the pinned UBI Micro base runs before expensive fixture builds. These extra runtime RPMs are not
supply-chain-qualified; production RPM locking/scanning remains an MVP gap.

### Feasibility checks already observed

| Check | Result | Evidence |
| --- | --- | --- |
| Stable Rust out-of-tree workspace type-check | PASS locally | Rust 1.94.1, cargo check --workspace --locked |
| Workspace Clippy with warnings denied | PASS locally | cargo clippy --workspace --locked -- -D warnings |
| Cedar schema, inherited groups, write/sibling denial, revoke | PASS locally | core unit test, including strict validation |
| Verified HTTPS allow/deny/revoke, self-only identity read and API authentication | PASS locally | scripts/tls-smoke.py |
| Harness denial safety | PASS locally | four pinned upstream harness tests plus adapted denial guard |
| Native amd64 compilation, workspace tests, HTTPS smoke | PASS at 62b6be2 | [actual job logs](https://github.com/datopsis/datopsis-authz/actions/runs/43859108523/job/133270942721) |
| Native arm64 compilation, workspace tests, HTTPS smoke | PASS at 62b6be2 | [actual job logs](https://github.com/datopsis/datopsis-authz/actions/runs/43859108523/job/133270942875) |

The linked run was superseded and cancelled during fixture-image builds after
source/fixture improvements; its compile/test/smoke steps completed successfully
on both CPUs. These are not C1–C8 passes. The source at 837340f adds strict policy
validation and diagnostic forwarding and is undergoing a new complete run.

## Q3: Acceptance evidence

The local S1 harness composes the pinned fixture without editing its checkout.
`acceptance.py` and `security.py` derive from the pinned upstream tests, retaining
exact rows, typed denial rules, client checks, 30-second revocation deadline,
invalid-token controls, private-network probes and structured outage errors.
It substitutes Cedar's grant API, backend process, port and state snapshot for
OpenFGA's tuples/model/migrations. Private PostgreSQL namespace setup is reused;
the unused OpenFGA database is fixture scaffolding, not an authorization backend.

**C3 adaptation:** token groups alone deny until an explicit group-to-resource
select grant exists. Adding that grant permits exact reads without registering a
Lakekeeper role or syncing membership. Removing the mapping must deny the old,
unexpired token. These direct-claim subchecks are saved separately.

The original IdP membership-removal/old-token assertion is **also retained**:
remove lake-readers from Rauthy while its Cedar group grant exists, then require
the old unexpired token to be denied. A stateless adapter is expected to **FAIL**
this assertion, because the old JWT still contains the group. A passing mapping
revocation subcheck is not substituted for this control. S4 must establish a bound
or add an epoch/introspection mechanism. C3 may pass only when all its assertions
pass. Fresh empty-group tokens remain subject to the upstream compatibility gap.

C8 retains its restart/grant-preservation assertions. With memory storage it is
expected to fail, not be skipped or relabeled PASS. C7 similarly retains recovery
checks even though a backend process restart loses its state. Destructive cases receive an explicit fixture reset **between** C7 and C8 and
after C8, so state loss cannot prevent the next case from exercising its own
restart assertion. No state is restored inside an assertion. Catalog failures,
TLS errors and authentication failures never qualify as authorization denials.

| Case | amd64 | arm64 |
| --- | --- | --- |
| C1 namespace read/exact rows/write denials | NOT RUN | NOT RUN |
| C2 inheritance/single-table isolation | NOT RUN | NOT RUN |
| C3 direct verified groups / mapping revoke | NOT RUN | NOT RUN |
| C4 revoke within 30 seconds | NOT RUN | NOT RUN |
| C5 Trino, PyIceberg and Sail | NOT RUN | NOT RUN |
| C6 no denied storage credentials | NOT RUN | NOT RUN |
| C7 spoofing/invalid tokens/isolation/outage/recovery | NOT RUN | NOT RUN |
| C8 durable restart and repeated migrations | NOT RUN | NOT RUN |

CI uses native ubuntu-24.04 and ubuntu-24.04-arm; no QEMU. Images are compiled in
UBI 9 to avoid the runner's newer glibc being required by the UBI runtime.
The compiler environment is evaluation tooling, not supply-chain-qualified.
Per-run CA, service keys and tokens are never committed. Evidence upload is
restricted to sanitized reports; `.runtime` and environment files are excluded.
Container execution is unavailable locally; actual Actions logs are authoritative.

### C6 source boundary

Pinned [load_table](https://github.com/lakekeeper/lakekeeper/blob/9bd377162345b64a716f0a4fcffe4e7e7f3c7534/crates/lakekeeper/src/server/tables/load_table.rs)
authorizes before fetching storage secrets and generating credentials. The
[table authorization result](https://github.com/lakekeeper/lakekeeper/blob/9bd377162345b64a716f0a4fcffe4e7e7f3c7534/crates/lakekeeper/src/server/tables.rs)
maps write to ReadWriteDelete, read to Read, and metadata-only to no storage
permission. The [S3 implementation](https://github.com/lakekeeper/lakekeeper/blob/9bd377162345b64a716f0a4fcffe4e7e7f3c7534/crates/lakekeeper/src/service/storage/s3.rs)
builds the inline STS policy from table location and permissions and caches issued
temporary credentials. S1 uses the unchanged sts-enabled=false profile: read-only
loads must return no S3 keys and denied loads no credentials. No SeaweedFS STS
scope, issued-credential revocation or direct-storage isolation is qualified.

### Audit gate

[Actual lint job](https://github.com/datopsis/datopsis-authz/actions/runs/43858413647/job/133268555266)
ran cargo-audit 0.22.2 and failed with three advisories in the locked transitive graph:
`libsqlite3-sys` 0.37.0 / RUSTSEC-2026-0459, and `quick-xml` 0.40.1 /
RUSTSEC-2026-0194 and RUSTSEC-2026-0195. Five informational/unmaintained/unsoundness
warnings were also emitted. `cargo tree -i quick-xml@0.40.1` traces the XML dependency through the pinned
Azure SDK fork into Lakekeeper; `cargo tree -i libsqlite3-sys` has no selected
native-feature reverse dependency. The lock includes optional dependencies; this
is not an assertion that every advisory is reachable in the built image.
Embedding Lakekeeper pulls its cloud-storage graph, not just a small interface crate. No advisory
ignore, patch, exemption or continue-on-error was added. The lint gate stays red.

## Q4: MVP gaps and effort

Estimates below are engineering workdays for one experienced Rust engineer,
not a delivery commitment; integration/security review can reveal more work.

| Gap | Approximate effort | Required result |
| --- | --- | --- |
| Durable relationship store and consistency | 5–10 days | PostgreSQL verify-full, idempotent migrations, atomic grant changes, hierarchy reconciliation, rename/rollback/crash tests |
| Management API and delegated authorization | 5–10 days | explicit compatible grant/revoke/list/introspection routes, pagination, role/user semantics, deny unauthorized inspectors |
| Full action/schema model | 3–5 days | validated policies, context-sensitive mutations, view/definer/generic-table tests; current select/owner model is narrow |
| List performance | 3–5 days | bounded batches, avoid per-object HTTP, query budgets, large namespace/pagination benchmarks |
| Caching/revocation | 3–5 days | stated TTL/invalidation, multi-replica tests, old-token groups boundary, C4 measurements |
| Audit/operations | 4–8 days | durable every-decision audit with policy ID/reason, health, timeouts, metrics, limits, backups |
| Supply chain/deployment | 4–8 days | pinned builder/runtime digests, hardened shared role image, CVE gates, SBOM, bundle integrity, service authentication/rotation |
| Acceptance and adversarial expansion | 5–10 days | all C1–C8 on both CPUs, lifecycle/delegation/body-limit cases and production topology |

Rough S1-to-catalog-MVP total: **32–61 engineering days**, before S2/S3/S4,
OPA endpoint, Sail gateway, token broker and Phase D STS qualification. Do not
start that scope under this PR. Static storage keys remain a bypass until Phase D;
C6's STS-disabled profile only proves the catalog/vending boundary.
