> Historical feasibility evidence. Production slice 2 is implemented separately on
> top of catalog slice 1; see [production protocol, semantics and limits](../TRINO.md).
> The volatile-store and audit gaps below describe the spike, not the current serve role.
> Native MVP results must be taken from the slice-2 PR, not these earlier runs.

# S2: Trino 484 OPA enforcement backed by Cedar

Status: **S2 feasibility PASS on native amd64 and arm64 with an explicit stock-plugin
layer. The exact unmodified owner image lacks OPA (FAIL). Full C1-C8 acceptance and
audit remain FAIL. Evaluation only; no MVP qualification.**

The API is part of the existing `authz-serve serve` role, using `authz-core`'s Cedar
policies and relationship store. No external repository was modified.
[Updated architecture](../diagrams/authz-architecture.svg).

## Questions and native evidence

All enforcement rows below use the derived image: unchanged owner base at the
required pin plus the official digest-locked OPA 484 plugin. They do not claim OPA
works in the unmodified owner image.

| Question | [amd64][native-amd64] | [arm64][native-arm64] | Exact evidence |
| --- | --- | --- | --- |
| Unmodified owner pin includes OPA | FAIL | FAIL | Native inventory probe: Iceberg present, OPA absent |
| Granted SELECT; denied table hidden from SHOW/information_schema and SELECT denied | PASS | PASS | S2.1: only `allowed` listed; denied SELECT and INSERT are `PERMISSION_DENIED` |
| Region attribute yields exactly permitted rows | PASS | PASS | S2.2: `[[1,"eu"],[3,"eu"]]`; US row 2 excluded |
| Sensitive values hidden for reader, visible for privileged user | PASS | PASS | S2.3: `[[1,null],[3,null]]`; owner sees all three original sensitive values |
| Same principal/table UUID decisions at Lakekeeper and OPA; shared revoke denies both | PASS | PASS | S2.4: catalog 200/404 matches OPA true/false; revoke gives catalog 404 and Trino `PERMISSION_DENIED` |
| Serve unreachable from Trino fails closed and recovers | PASS | PASS | S2.5: explicit `OpaQueryException.QueryFailed`, no rows, positive controls before/after |
| Nonbatched lists and scalar column masks | PASS | PASS | S2.single: same exact list, filtered/masked rows and typed denied SELECT |

[native-amd64]: https://github.com/datopsis/datopsis-authz/actions/runs/43895840023/job/133399035048
[native-arm64]: https://github.com/datopsis/datopsis-authz/actions/runs/43895840023/job/133399035169

[Run 43895840023](https://github.com/datopsis/datopsis-authz/actions/runs/43895840023)
tested PR source `ff12ed4e7e6f9e5a3c95eb0fad02747b59d11f17` through merge commit
`859c60891eca723e69ab07d868f0609d2d34a1ce`. Native Actions logs, sanitized SQL
results, Cedar wire logs and scalar Trino startup logs were read on both CPUs.
Trino reported version **484**, loaded system access control **opa**, and passed
verified TLS controls. No QEMU; runners were ubuntu-24.04 and ubuntu-24.04-arm.

Durable sanitized evidence: [amd64](S2-results-amd64.json) and
[arm64](S2-results-arm64.json). These retain exact rows/denials, principal/UUID
parity, native input revisions, base/derived image IDs, ZIP/JAR hashes, labels,
platform binary/library hashes and the unchanged C-suite outcomes. Full sanitized
service artifacts remain in the run for 14 days. The final evidence-only commit
does not change runtime code or assertions from the tested source above.

The outage disconnected only Trino's private route to serve, leaving Lakekeeper
and serve alive. A fresh otherwise-allowed query failed explicitly after
**5.014674 s amd64 / 5.018196 s arm64**, matching the configured five-second OPA
request timeout. No earlier response page contained rows; reconnecting restored
exact permitted reads. This is a single-run observation, not an HA/revocation SLA.

Both CPUs' Cedar wire logs recorded `/allow` 103 calls, `/batch` 9, `/rows` 8,
`/batch_masks` 12 and `/mask` 17. Thus scalar and batched protocols were actually
exercised. The batch Trino stdout-only log was empty; its stderr was not retained.
The structured batch SQL outcomes and both-mode Cedar logs remain available;
no claim is made to have retained that missing stderr stream.

## Mandatory backend suite remains red

S2 finishes and destroys its fixture before the unchanged S1 C1-C8 fixture starts.
No acceptance assertion, denominator or original C3 adaptation was weakened.

| Case | [amd64][native-amd64] | [arm64][native-arm64] |
| --- | --- | --- |
| C1 | PASS | PASS |
| C2 | PASS | PASS |
| C3 | FAIL — old-token IdP membership removal still permits | FAIL — same |
| C4 | PASS — 26.870 ms, first fresh denial 404 | PASS — 33.123 ms, first fresh denial 404 |
| C5 | PASS — Trino, PyIceberg and Sail | PASS — all three |
| C6 | PASS | PASS |
| C7 | FAIL — empty-state backend cannot recover allowed reads | FAIL — same |
| C8 | FAIL — restart loses relationship/grant state | FAIL — same |

C7 timed out waiting for recovery after restart; C8's strict state comparison
failed. C8's repeated-migration assertions were not reached. Between-case fixture
resets and the final unchanged-row control passed. These do not turn C7/C8 into
passes. The [S1 report](S1-lakekeeper-adapter.md) documents the retained direct-claim
C3 adaptation and known durability limits. Required `test` and `lint` remain red;
this spike does not establish backend or production acceptance.

## Inputs

- [Platform plan section 4a](https://github.com/datopsis/lakehouse-integration/blob/e8379a528bf413c05aad49e56bc8cd507b5e077a/docs/AUTHZ-PLATFORM-PLAN.md#4a-consolidated-design-owner-decisions-2026-11-16)
  and [acceptance evaluation](https://github.com/datopsis/lakehouse-integration/blob/e8379a528bf413c05aad49e56bc8cd507b5e077a/docs/AUTHZ-EVALUATION.md).
  Main versions were also read when starting S2.
- Fixture `e8379a528bf413c05aad49e56bc8cd507b5e077a`, with its owner image locks.
- Required [trino-ubi](https://github.com/datopsis/trino-ubi/tree/685ff5bca0037d38e3c2e2ed47a60f2540dad7c2)
  pin already matches the fixture lock. Iceberg and verified TLS, no source edits.
- [Trino 484 source](https://github.com/trinodb/trino/tree/e2d50bb733e193607c44be84ad80ce2430ba1d01/plugin/trino-opa)
  (`484` tag resolves to `e2d50bb733e193607c44be84ad80ce2430ba1d01`).
- S1 pins Lakekeeper `9bd377162345b64a716f0a4fcffe4e7e7f3c7534` and Cedar 4.14.1.

Source hashes and immutable URLs are retained in [S2-source-inventory.json](S2-source-inventory.json).

## Supported wire features (source evidence, runtime qualification above)

The stock plugin is sufficient once packaged (see the owner-image gap below); no Rego interpreter, OPA process or Trino fork is
needed. `authz-serve serve` implements JSON `input` / `result` envelopes:

| Trino property | Endpoint | Response |
| --- | --- | --- |
| `opa.policy.uri` | `/opa/allow` | boolean |
| `opa.policy.batched-uri` | `/opa/batch` | allowed zero-based indexes |
| `opa.policy.row-filters-uri` | `/opa/rows` | list of `{expression, identity?}` |
| `opa.policy.column-masking-uri` | `/opa/mask` | expression object or null |
| `opa.policy.batch-column-masking-uri` | `/opa/batch_masks` | `{index, viewExpression}` list |

[OpaConfig](https://github.com/trinodb/trino/blob/e2d50bb733e193607c44be84ad80ce2430ba1d01/plugin/trino-opa/src/main/java/io/trino/plugin/opa/OpaConfig.java)
and [OpaHighLevelClient](https://github.com/trinodb/trino/blob/e2d50bb733e193607c44be84ad80ce2430ba1d01/plugin/trino-opa/src/main/java/io/trino/plugin/opa/OpaHighLevelClient.java)
establish that batched masking takes precedence over single masking; an absent
row/mask URI disables that feature. Masks are queried with `GetColumnMask` and
row filters with `GetRowFilters`. Expressions can carry an alternate evaluation
identity; this spike does not return one.

[OpaBatchAccessControl](https://github.com/trinodb/trino/blob/e2d50bb733e193607c44be84ad80ce2430ba1d01/plugin/trino-opa/src/main/java/io/trino/plugin/opa/OpaBatchAccessControl.java)
batches catalog/schema/table/function filtering. `FilterColumns` sends a single
table with a columns array and expects column indexes within that array. This
is different from indexes into `filterResources`. Unconfigured batch URI uses
parallel scalar decisions. Permission/role management does not call OPA: the
plugin's separate bulk option defaults to deny and remains disabled.

[OpaAccessControl](https://github.com/trinodb/trino/blob/e2d50bb733e193607c44be84ad80ce2430ba1d01/plugin/trino-opa/src/main/java/io/trino/plugin/opa/OpaAccessControl.java)
leaves `checkCanSetUser` empty; authentication belongs to Trino. The fixture uses
TLS plus file password authentication (independent per-run passwords), with exact
Cedar principal IDs as usernames. It does not claim Rauthy login/token propagation
to Trino, trusted group ingestion or arbitrary IdP attributes. The catalog engine
credential remains `oidc~lakekeeper`; it can read both S2 tables so a denied end
user's failure cannot be explained by that credential's catalog restrictions.

## Owner image packaging gap and local composition

The exact owner pin's [artifact lock](https://github.com/datopsis/trino-ubi/blob/685ff5bca0037d38e3c2e2ed47a60f2540dad7c2/artifacts/trino.lock.json)
permits only `iceberg`, `password-authenticators`, and `tpch`. Its
[acquisition script](https://github.com/datopsis/trino-ubi/blob/685ff5bca0037d38e3c2e2ed47a60f2540dad7c2/scripts/artifacts.py)
removes every other core plugin and rejects any other inventory. Thus the exact,
unmodified image cannot enable OPA. The native inventory probe records this as a
baseline feature FAIL; runtime enforcement uses an explicitly derived image.

`scripts/trino-opa-image.py` adds the official `trino-opa-484.zip` to that unchanged
base, without editing another repository. ZIP size is 15,384,527 bytes, SHA-256
`f8627b3f2da8950e8209ddcf8fd436cc0e536459dd438c81261593ab8310dc24`, matching the
[official release asset](https://github.com/trinodb/trino/releases/tag/484)'s API
digest and locally downloaded bytes. Extraction rejects traversal, symlinks,
duplicate names and non-JAR entries; the expected 62 JARs become root-owned,
read-only plugin files. No source fork or custom Java plugin is introduced.

The derived image has separate source/provenance labels. Native evidence retains
base/derived image IDs, architecture, ZIP/JAR hashes and labels in
`trino-composition.json`; the server version must equal `484`. This is digest-only
artifact verification and functional composition, not signature, CVE or production
qualification of the additional plugin dependencies. The original owner image
and its strict provenance gate remain unchanged for C1-C8.

## Pinned fixture acquisition issue

[The amd64 job at dcdb4d9](https://github.com/datopsis/datopsis-authz/actions/runs/43886289001/job/133365216380)
passed all six workspace tests, HTTPS smoke and the loader probe, then was BLOCKED
by HTTP 404 acquiring PostgreSQL 18.6 RPMs. The original unmodified owner builder
failed before any runtime assertions. All S2/C cases remain BLOCKED in that job.

Three exact locked amd64 RPMs (`postgresql18`, `postgresql18-libs`,
`postgresql18-server`) are available at the official versioned `rhel-9.8-x86_64`
paths on the same `download.postgresql.org` host. Local GETs verified every size
and original pinned SHA-256. The build step alone enables a narrowly scoped
`sitecustomize` fallback: only these three exact public URLs, after 404 or an unsolicited partial response,
verified HTTPS with no credentials forwarded. The owner acquirer still validates
the original lock, response URL, size, hash, signing key and RPM signature; the
owner checkout and lock remain unmodified. Runtime requests never load the shim.
The [next amd64 attempt](https://github.com/datopsis/datopsis-authz/actions/runs/43889078338/job/133375035116)
rejected a partial original server RPM (1,048,576 versus 7,606,326 locked bytes).
The fallback now handles that response too; full-size/hash checks remain mandatory.
Source inventory retains all original/fallback URLs and hashes. This is retrieval
of identical pinned bytes, not a dependency version or acceptance change.

## One policy, two enforcement points

`authz-core` retains S1's Cedar grant/hierarchy evaluator and relationship store.
Authenticated admin mutations bind SQL `[catalog,schema,table]` names to existing
Lakekeeper table UUIDs, and set trusted principal region attributes. JSON array
keys avoid concatenation ambiguities. Trino read and discovery checks evaluate
`read_data` on the same UUID as Lakekeeper. Schema/catalog visibility is derived
from allowed bound tables. Unbound names and unsupported operations deny.
`information_schema` reads use Trino's own underlying item-filtering hooks; S2.1
requires its exact table result, not just SHOW output.

SQL obligations are a deliberately small adapter translation, not a Cedar-to-SQL
compiler. A binding can request a region column and a sensitive column. Row filters
quote the identifier and the stored region value. Missing region for an otherwise granted restricted read fails closed with an
error. Denied or unbound tables receive a constant FALSE row filter and NULL masks,
then Trino's boolean SELECT check denies. Trino fetches obligations before final
SELECT authorization, so an HTTP 403 there would misclassify a normal policy denial
as an OPA backend failure. The strict query-denial oracles remain unchanged. See the pinned
[obligation analysis](https://github.com/trinodb/trino/blob/e2d50bb733e193607c44be84ad80ce2430ba1d01/core/trino-main/src/main/java/io/trino/sql/analyzer/StatementAnalyzer.java#L2567)
and [final SELECT check](https://github.com/trinodb/trino/blob/e2d50bb733e193607c44be84ad80ce2430ba1d01/core/trino-main/src/main/java/io/trino/sql/analyzer/Analyzer.java#L101). The mask is SQL NULL, coerced by Trino to the column type. Cedar's same generated grant policies
control `unmask` and `unrestricted_rows` exceptions; an owner has both. No second
allow/deny policy database exists. Restriction templates and region attributes
live alongside relationships in the same volatile store.

The stock plugin's `opa.context-file` forwards a protected per-run serviceKey over
verified HTTPS. The adapter authenticates it before reading identity assertions.
This spike shares S1's service credential between trusted fixture callers; no
client can use the mutation API without that credential. Never enable
`opa.log-requests`: it would log context credentials. Requests/responses are not
logged wholesale by serve; audit records retain operations/results/policy IDs only.
Trino alone joins the private backend network. No ports are published.

Both observed shared-revocation outcomes were `PERMISSION_DENIED: Cannot access catalog iceberg`.
The oracle requires OPA false and catalog 403/404, plus a Trino
permission error or exactly `CATALOG_NOT_FOUND` / code 44 / `USER_ERROR` with
`line 1:15: Catalog 'iceberg' not found`. The latter can occur because revocation
removes the user's last visible table and hence its catalog visibility. Positive
reads before revocation and after restoration distinguish this from an unrelated
missing catalog. C1-C8's original denial assertions are unchanged.

## Local and lint evidence

Full workspace unit tests (six total), core/serve Clippy with warnings denied, Rust formatting,
Python compilation, YAML parsing, LF checks and the real HTTPS smoke pass locally.
The smoke additionally exercises OPA service authentication and escaped region SQL.
These are not native runtime passes.

[The actual lint job](https://github.com/datopsis/datopsis-authz/actions/runs/43895840023/job/133399035091)
passed formatting/YAML/LF and failed the unchanged Cargo audit gate: three
vulnerabilities (`RUSTSEC-2026-0459`, `RUSTSEC-2026-0195`, `RUSTSEC-2026-0194`)
in the inherited lockfile, plus five warnings. No Cargo advisory suppression or Rust dependency update
was made for this spike.

## Gaps and limits

- Fine-grained rules only protect queries through Trino. Direct Lakekeeper reads
  and the fixture's static S3 keys bypass row/mask enforcement. Lakekeeper parity
  means table authorization, not row/mask parity. Production needs the platform
  plan's engine-only restrictions and scoped credentials before using such rules.
- SQL-name bindings are admin-populated for this spike. Rename/drop synchronization,
  stale UUID bindings, multi-warehouse names and information_schema hardening beyond
  the exact tested table listing are not qualified.
- Store persistence, bundle loading, durable audit, distributed revocation, load,
  HA, OIDC Trino authentication, column-specific read grants and arbitrary SQL
  obligations are not implemented. Cedar remains the access decision engine;
  expression templates are application code. Trino mutation operations deliberately deny
  even owners; parity is qualified for table reads only. The shared service key is
  mutation-capable; decision-only engine credentials are not implemented.
- No changes to external repositories, repository settings, secrets or permissions.
  CA private keys, tokens, passwords and context credentials exist per run only.

## Earlier non-passing attempts

Early runs were cancelled before runtime as protocol/fixture corrections landed;
none are runtime passes. The documented amd64 attempts stopped on locked PostgreSQL
404/partial responses. The [first arm64 composition attempt](https://github.com/datopsis/datopsis-authz/actions/runs/43889078338/job/133375035575)
proved the baseline OPA omission but stopped because the generated `Containerfile`
was not explicitly selected by Docker. The corrected final run above built the
layer and passed every S2 assertion on both CPUs. The mode-switch fixture reuses
its protected per-run certificate, rather than trying to overwrite its root-owned
key; this does not relax key permissions or reuse secrets across runs.
