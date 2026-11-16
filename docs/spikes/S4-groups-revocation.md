# S4: groups and revocation timing

Evaluation only, stacked on unmerged S1. No MVP acceptance or merge.

Inputs: S1 report and crates; platform plan §4a and AUTHZ-EVALUATION at
`e8379a528bf413c05aad49e56bc8cd507b5e077a` (also read current main before work);
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

SCIM delivery/retry timing is not runtime verified. Source evidence supports
polling as the smallest measurable prototype, with SCIM plus reconciliation a
candidate for reducing detection delay.

## Limits

Store/epochs remain in memory: S1 C7 recovery/C8 durability failures are expected
and remain failures. Poll freshness, HA, durable epoch fanout, event replay, clock
skew, disabled users, group deletion/rename and production token-broker behavior
are not qualified. Already-issued storage credentials and fetched data are outside
catalog revocation. Full native logs and results will replace pending rows.
