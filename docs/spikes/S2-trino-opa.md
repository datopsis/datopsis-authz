# S2: Trino 484 OPA enforcement backed by Cedar

Status: implementation prepared; native runtime results pending. Evaluation only,
stacked on the unmerged S1 branch. This is not the MVP or acceptance of S1's known
C3/C7/C8 and audit failures.

## Questions and exact oracles

| Question | amd64 | arm64 | Evidence |
| --- | --- | --- | --- |
| Granted SELECT succeeds; denied table hidden from SHOW/information_schema and SELECT denied | BLOCKED | BLOCKED | S2.1 runtime pending |
| Region attribute yields exactly rows 1 and 3, excluding US row 2 | BLOCKED | BLOCKED | S2.2 runtime pending |
| Sensitive values NULL for reader; exact original values for privileged user | BLOCKED | BLOCKED | S2.3 runtime pending |
| Same principal/table UUID allows and denies at Lakekeeper and OPA; shared revoke denies both | BLOCKED | BLOCKED | S2.4 runtime pending |
| Serve unreachable from Trino: explicit OPA query failure, no rows, recovery | BLOCKED | BLOCKED | S2.5 runtime pending |
| Nonbatched list and single-column-mask endpoints enforce exact same results | BLOCKED | BLOCKED | S2.single runtime pending |

Native ubuntu-24.04 and ubuntu-24.04-arm Actions jobs run identical assertions.
Containers cannot run in the development workspace. No unit/compile result is a
runtime PASS. Reports initialize BLOCKED before builds; actual logs and sanitized
artifacts must be read before completing this table. The unchanged C1-C8 suite
runs separately after S2, with independent disposable fixture state.

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

## Supported wire features (source evidence, runtime qualification above)

The stock plugin is sufficient; no Rego interpreter, OPA process or Trino fork is
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
quote the identifier and the stored region value. Missing region/read access
fails closed. The mask is typed SQL NULL. Cedar's same generated grant policies
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
  expression templates are application code.
- No changes to external repositories, repository settings, secrets or permissions.
  CA private keys, tokens, passwords and context credentials exist per run only.
