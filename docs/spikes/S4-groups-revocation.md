# S4: groups and revocation timing

Evaluation only, stacked on unmerged S1. No MVP acceptance or merge.

Inputs: S1 report and crates; platform plan §4a and AUTHZ-EVALUATION at
`e8379a528bf413c05aad49e56bc8cd507b5e077a` (also read main `369dbdec67445eb1c2931b39b45f3364ec71ead4` before work);
Rauthy owner image `1e114b84b01988bf15306b110b040378878488d3`;
its lock pins Rauthy 0.37.2 source `fe6bcb95192e8a83c29e2b525bf4960933bea3bd`.
No external source modifications. One platform program, Cedar and compiled adapter retained.

## Questions and provisional evidence

| Experiment | amd64 | arm64 |
| --- | --- | --- |
| A: 30-second access token, actual verifier exposure and client renewal | BLOCKED pending Actions | BLOCKED pending Actions |
| B: authoritative admin poll → monotonic per-user epoch → old-token denial | BLOCKED pending Actions | BLOCKED pending Actions |
| C: live authoritative membership; 0/250ms cache; IdP outage fails closed | BLOCKED pending Actions | BLOCKED pending Actions |
| C3 all controls, including old unexpired token | BLOCKED pending Actions | BLOCKED pending Actions |

`evaluation/s1/s4.py` runs the original C3 controls for each membership strategy:
unmapped denies, mapped exact rows, mapping removal denies, authoritative membership
removal denies the old **unexpired** token. Authentication failure is never an
authorization denial. A cannot satisfy this last assertion by expiring the token.

B passes verified `iat` from Lakekeeper's authenticated `Authentication` to the
trusted decision API. Epoch mutations are monotonic; missing `iat` denies when
an epoch exists. The admin poll experiment uses one 1s poll cycle and writes
`floor(now)+1` to reject all tokens minted in the detection second. A newly issued
token must recover after that boundary. Polling is fixture-side, not an MVP daemon.

C replaces token groups with authoritative user groups for configured users.
No stale-on-error after cache expiry; timeout 2s, HTTPS and trusted per-run CA,
redirects disabled. Unknown user gets no memberships; malformed/error responses
fail closed. The 250ms positive cache permits stale access until expiry, including
when Rauthy goes down. Outage checks occur after TTL. The added network connects
only Rauthy and the private backend namespace, not clients to the decision API.

## Rauthy change delivery at the exact source pin

- [EventType](https://github.com/sebadob/rauthy/blob/fe6bcb95192e8a83c29e2b525bf4960933bea3bd/src/api_types/src/events.rs): no membership-change event. Notification integrations are not a membership webhook contract.
- [User update](https://github.com/sebadob/rauthy/blob/fe6bcb95192e8a83c29e2b525bf4960933bea3bd/src/api/src/users.rs): writes user, then spawns outbound SCIM synchronization asynchronously; errors logged.
- [SCIM contract](https://github.com/sebadob/rauthy/blob/fe6bcb95192e8a83c29e2b525bf4960933bea3bd/book/src/work/scim.md): Rauthy pushes to an application's Users/Groups endpoints; group membership uses PATCH add/remove. Requires implementing the receiving endpoints and reconciliation. This is outbound provisioning, not a Rauthy membership-read endpoint.
- Admin `GET /auth/v1/users/{id}` returns authoritative groups using an API key scoped to Users/read. The fixture also needs Users/update for removals and Clients/read/update for lifetime experiments. Production reader credentials need only read access.

The [SCIM retry scheduler](https://github.com/sebadob/rauthy/blob/fe6bcb95192e8a83c29e2b525bf4960933bea3bd/src/schedulers/src/scim_tasks.rs) sleeps 60–90 seconds between retry scans, and eventually deletes tasks after the configured retry limit. SCIM alone cannot promise seconds during receiver outages. SCIM delivery/retry timing is not runtime verified. Source evidence supports
polling as the smallest measurable prototype, with SCIM plus reconciliation a
candidate for reducing detection delay.

## Limits

Store/epochs remain in memory: S1 C7 recovery/C8 durability failures are expected
and remain failures. Poll freshness, HA, durable epoch fanout, event replay, clock
skew, disabled users, group deletion/rename and production token-broker behavior
are not qualified. Already-issued storage credentials and fetched data are outside
catalog revocation. Full native logs and results will replace pending rows.

## Cost and failure model (before runtime numbers)

| Option | Extra load | Exposure bound | Complexity / failure modes |
| --- | --- | --- | --- |
| A short tokens | At lifetime L, roughly N/L token requests/s for N active client sessions, higher with early renewal. Trino/PyIceberg use client credentials, not human refresh-token exchange. Sail requires an external writer. | Remaining token lifetime plus verifier clock allowance; fresh membership removed from future human tokens. | Small IdP configuration change; renewal compatibility and token-file reload must be measured. IdP outage prevents renewal but leaves valid old tokens usable. Does not revoke storage credentials or cached metadata. |
| B polling + epoch | One Users GET per monitored user per poll interval; one epoch write per observed removal; local map lookup per decision. | Poll phase + network + epoch commit + propagation, **only when polling is healthy**. | Requires baseline/reconciliation, authenticated `iat`, atomic monotonic update, persistent shared epochs, freshness gate and clock budget. An undetected removal is not revoked during poll/IdP failure. Out-of-order updates cannot lower an epoch. Same-second cutoff waits until next second for recovery. |
| C live groups | One Users GET per decision with no cache (a catalog call can make multiple decisions); with TTL d roughly at most one fetch per active user/d in serial traffic. Concurrent misses can amplify this. | Cache remaining age + lookup + catalog check. | Low prototype complexity; IdP becomes a synchronous dependency. Timeout/error fails closed after TTL. Positive cache still permits access during its remaining TTL. No stale-on-error. Production needs concurrency limits, coalescing and protected read-only credentials. |

The native A experiment issues a genuine 30-second groups-bearing human token,
removes authoritative membership, and polls catalog loads through authentication
expiry. A 401 is recorded as expiry, never C3 authorization denial. It also
restarts Trino under the short lifetime, measures persisted Rauthy TokenIssued
events during isolated 0/20/40/60s workloads, and exercises PyIceberg and an
externally renewed Sail token file. Five explicit acquisitions per label are a
shared-endpoint microbenchmark; they are not counted as native client renewal.
Only sanitized counts and latency samples are retained.

The B prototype is deliberately a single observed poll cycle, not a background
service or polling-scale benchmark. Its 1s phase is chosen explicitly. Do not
turn that one sample into a distribution or availability SLA.

## Fixture acquisition correction

[Run 43885508158](https://github.com/datopsis/datopsis-authz/actions/runs/43885508158)
reached native compilation/tests/HTTPS smoke, but amd64 acceptance was BLOCKED:
PGDG's rolling `rhel-9-x86_64` alias returned 404 for three locked PostgreSQL 18.6
RPMs. The official `rhel-9.8-x86_64` path still serves exactly the locked bytes.
All four PostgreSQL packages on **both** architectures were downloaded locally
and checked against the original pinned sizes/SHA256 values.

`evaluation/artifact_transport/sitecustomize.py` supplies an HTTPS transport-only
fallback for the exact 18.6 RPM names, only after a 404 and only on the same
`download.postgresql.org` host. It is enabled for child Python acquirers during
fixture builds. Owner sources and locks are unchanged; their locked size/hash,
key-fingerprint, signature, offline-build and image-provenance checks all remain
mandatory. There is no version or trust fallback. Native runtime evidence must
come from a subsequent run that gets through this prerequisite.
