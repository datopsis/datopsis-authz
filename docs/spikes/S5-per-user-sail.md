# S5: per-user Sail lifecycle and isolation

Status: **bounded S5 feasibility PASS on native amd64 and arm64. Full platform
acceptance and audit remain FAIL. This is not an MVP go decision.**

[Stacked PR #6](https://github.com/datopsis/datopsis-authz/pull/6) targets
`room/datopsis-authz-spike-s3-sail-gateway`. No merge. The owner's per-team MVP
choice is preserved.

## Result and recommendation

One Sail process per authenticated user is practical for a bounded pool in this
spike: roughly half a second for isolated first queries, roughly a quarter second for
later queries, and zero failures at 1/5/20 concurrent users. All per-user catalog,
namespace/session isolation, private token/tmpfs, lifecycle and limit assertions
passed on both architectures. Memory depends strongly on query workload; the
small SELECT 42 scale footprint must not be used to size analytical workloads.

**Retain per-team for the MVP; pursue hybrid for sensitive groups after platform
qualification.** S5 establishes the tested per-user process/catalog boundary.
Production data enforcement still needs scoped storage credentials and the
remaining platform work. The inherited shared static S3 credentials allow
admitted direct-path plans to bypass catalog grants.

## Inputs, security status and native evidence

The coordinator explicitly authorized testing with Rauthy
`01375efb2a14692a7977f2f8aa60121f3fcc2f01` from
[unmerged owner PR #3](https://github.com/datopsis/rauthy-ubi/pull/3). Its SvelteKit
security-gate finding is pending an owner decision. As with the integration
fixture's draft Trino pin, this is an evaluation input, **not a gate waiver,
security approval or production qualification**. The owner pin verifies FIDO feed
serial 302 and updates its own PostgreSQL test fixture to 18.7. The acceptance
fixture's other owner pins are unchanged.

`evaluation/owner_pins.py` supplies only the approved Rauthy revision to the
unchanged pinned harness for S1/S3/S5 build/provenance checks and runtime reports.
No external repository, acquisition lock, signature/checksum assertion, required
check, architecture or security gate was modified.

Other immutable inputs: Sail owner
`e96e068f926b8fecb3939e953389685ee4780032` (Sail 0.7.3 / upstream
`ac4690078021cf2a5402dc5c7b38a886f1916c73`), acceptance harness
`e8379a528bf413c05aad49e56bc8cd507b5e077a`, and Lakekeeper
`9bd377162345b64a716f0a4fcffe4e7e7f3c7534`.

Authoritative [run 44815134976](https://github.com/datopsis/datopsis-authz/actions/runs/44815134976)
tested PR source `01c0bfa6502077c2b88cb15c9e5859bf89477912` through merge commit
`3522fd9223827a1ee4cf3111c6b70da6e320db1f`.
Both complete native logs and sanitized artifacts were downloaded and read:

- [amd64 job](https://github.com/datopsis/datopsis-authz/actions/runs/44815134976/job/136561382321)
  / [durable exact evidence](S5-results-amd64.json).
- [arm64 job](https://github.com/datopsis/datopsis-authz/actions/runs/44815134976/job/136561382630)
  / [durable exact evidence](S5-results-arm64.json).

Each runner had four logical CPUs. amd64 reported kernel `7.0.0-1014-aws` and
16,464,306,176 B RAM; arm64 reported `7.0.0-1017-azure` and 16,715,923,456 B RAM.
The jobs assert native x86_64/aarch64 and verify image architecture/revision/lock
provenance; no QEMU. These different hosts are not a controlled CPU comparison.
Image builds, artifact acquisition, runtime tests and native validation ran
**only in the existing PR Actions jobs** under the coordinator's CI-first policy.

JSON retains raw timers/byte counts, every request/readiness sample, actual grant
assertions, image provenance, lifecycle events' results, cleanup and log digests.
Displayed conversions/timers below are rounded. The final evidence/docs follow-up
changes no tested runtime code; unchanged expensive checks are not rerun manually.

## Single instance

| Metric | amd64 | arm64 |
| --- | --- | --- |
| Prebuilt cold start to TCP ready | 0.261438 s | 0.226217 s |
| Idle Sail RSS | 64,757,760 B (61.758 MiB) | 65,073,152 B (62.059 MiB) |
| Peak sampled Sail RSS during analytical sequence | 216,776,704 B (206.734 MiB) | 226,619,392 B (216.121 MiB) |
| Kernel cgroup peak over analytical sequence | 243,163,136 B (231.898 MiB) | 161,312,768 B (153.840 MiB) |
| Million-row SUM + COUNT(DISTINCT) ExecutePlan | 0.224430 s | 0.166090 s |
| Forced stop + container/token-directory removal | 0.106638 s | 0.149353 s |
| Direct first SELECT 42 control | 202.228 ms | 207.763 ms |
| Direct later SELECT 42 median (five samples) | 157.558 ms | 162.600 ms |

Cold start includes trusted supervisor invocation, container creation and the
first successful TCP readiness probe on a prebuilt image. It excludes image
pull/build time and does not flush host/image caches. TCP readiness is not a
catalog-query readiness promise. Stop is forced SIGKILL-style removal including
the instance token directory; graceful drain/shutdown time is unverified.

The direct workload is first SELECT 42, five subsequent SELECT 42 requests, then
`SELECT sum(id) AS total, count(DISTINCT id) AS distinct_ids FROM range(1000000)`.
Both CPUs require exactly 499999500000 and 1000000. RSS polling targets 50 ms plus
inspection cost; kernel memory.peak catches between-poll allocations over the
whole sequence. The computation is representative of finite analytical CPU/hash
aggregation, not a large Iceberg scan, join or spill.

## Authenticated lifecycle latency

| CPU / user | First authenticated query ms | Later query median ms | Additional first / later ms versus direct control |
| --- | ---: | ---: | --- |
| amd64 / alice | 503.416 | 242.492 | 301.188 / 84.934 |
| amd64 / bob | 453.447 | 251.881 | 251.219 / 94.323 |
| arm64 / alice | 489.800 | 274.699 | 282.037 / 112.100 |
| arm64 / bob | 517.089 | 236.977 | 309.326 / 74.377 |

Times are ExecutePlan wall time, including a fresh TLS connection, live HTTPS
JWKS lookup, JWT validation, live HTTPS Cedar admission, lifecycle and namespace
relay. First queries start with no existing user instance; later queries reuse the
same user's instance and session, with five samples per user. The direct control
uses an insecure trusted loopback tunnel with the same Docker-exec namespace
transport and fresh session IDs. The calculated additional times are **observed
sample contrasts**, including TLS/authentication, not isolated component costs or
an SLA; warm-session reuse differs from the direct control. No p95/p99 or
production latency guarantee is inferred from these small samples.

## N concurrent authenticated users

| CPU / users | Total Sail RSS MiB | Total Sail cgroup MiB | Gateway RSS MiB | Ready min / p50 / max s | First query min / p50 / max s | Failures |
| --- | ---: | ---: | ---: | --- | --- | ---: |
| amd64 / 1 | 102.234 | 47.027 | 21.215 | 0.143697 / 0.143697 / 0.143697 | 0.416042 / 0.416042 / 0.416042 | 0 |
| amd64 / 5 | 497.305 | 216.805 | 21.215 | 0.355987 / 0.393299 / 0.491322 | 0.753273 / 0.832132 / 0.934709 | 0 |
| amd64 / 20 | 1,905.082 | 856.367 | 21.195 | 0.523205 / 1.239192 / 1.729213 | 1.573246 / 2.917102 / 3.120990 | 0 |
| arm64 / 1 | 104.867 | 44.598 | 17.188 | 0.170732 / 0.170732 / 0.170732 | 0.470613 / 0.470613 / 0.470613 | 0 |
| arm64 / 5 | 506.066 | 209.727 | 17.191 | 0.311292 / 0.378709 / 0.436204 | 0.668571 / 0.745110 / 0.795578 | 0 |
| arm64 / 20 | 2,007.875 | 841.016 | 18.211 | 0.389499 / 0.735071 / 1.211035 | 0.817732 / 2.268571 / 2.634481 | 0 |

Every user has a distinct genuine Rauthy PKCE identity and its own Sail instance.
Concurrent first requests execute SELECT 42 and require exactly `[{"answer": 42}]`.
Ready durations are the supervisor's internal container-start-to-TCP-ready
samples; first-query durations include authentication/admission/orchestration and
are the actual user-visible cold-request samples. All individual samples are in
JSON; min/p50/max are distributions within these single batches, not repeated-run
confidence estimates. Memory is sampled after the batch while all N instances
are resident. Scale is for this light workload, not 20 heavy analytical queries.

RSS sums count shared mapped pages more than once. Cgroup totals include charged
anonymous memory, tmpfs/cache and in-container relay processes. They exclude
shared Rauthy/Lakekeeper/Cedar/storage/PostgreSQL services, Docker/containerd/shims,
host-side helpers, and startup-burst peaks. Gateway RSS is shown separately;
these mixed accounting quantities are not a measurement of total host RAM.
Shared page ownership and cgroup charging depend on cache/teardown history.

## Isolation and lifecycle assertions: PASS on both CPUs

- Real Alice/Bob tokens intentionally use the **same session ID** and forged
  Spark UserContext. Each reads only its own namespace's exact rows (11/22),
  denies the other namespace and INSERT/UPDATE/DELETE/DROP/CREATE attempts,
  inherits a grant to a newly created table (row 33), then reads its granted
  single table while denying its sibling. Full assertions are per user.
- Missing tokens return gRPC 16 and a genuine ungranted machine returns 7;
  neither request starts an engine. Only verified JWT subject selects a backend.
- Every token file is UID 10001 mode 0400, readable by its own process; mounts
  are read-only and no private source directory is shared across instances.
  Host parent directories are root-owned 0700; token directories are UID 10001
  mode 0500. No Docker socket is mounted into Sail. Root/controller access is
  trusted; container isolation does not protect against a compromised host/kernel.
- No Sail ports are published. Sail binds loopback inside each separate network
  namespace. A peer instance's TCP probe to the other's bridge IP returns
  ECONNREFUSED (111). Separate private tmpfs markers are invisible to the peer.
- After inactivity the 15-second configured timeout (one-second sweep) removes
  the container and token files. Tests require absence within 60 seconds, rather
  than claiming an exact measured 15-second eviction SLA.
- Killing an instance creates a different random replacement for the same user,
  removes the old token directory, and returns a correct query. A second user's
  same-session-ID query cannot see the first user's temporary view after restart.
- Five simultaneous first requests for one identity create exactly one instance.
- The unchanged owner-paced stream outlives idle TTL: the same instance remains
  after 25 seconds and one ExecutePlan returns all 1,000,000 unique IDs, all
  SHA-512 payloads, 123 batches and sum 499999500000. Completion takes
  **88.643848 s amd64 / 88.516384 s arm64**, with no reattachment/retry/reset.
- Cleanup after every batch and after the full fixture leaves zero supervised
  containers and no instance token files; final cleanup removes the whole
  private runtime tree, including real user credentials and fixture keys.

The role's reaper uses a stream lease to protect active forwarding. The helper
receives credentials through private stdin JSON, not argv/container environment,
and updates token files atomically through read-only directory mounts. Catalog
credentials remain the verified user's token; no per-session upstream change is
needed. Atomic same-token reuse ran here; deliberate rotation to a newly minted
JWT, refresh/expiry races and issued-storage-credential revocation are unverified.

## Resource caps and behavior at the limit

Every instance has 536,870,912 B (512 MiB) memory, the same total memory+swap limit
(no additional swap), one CPU and 128 PIDs. Roots are read-only, capabilities are
dropped and no-new-privileges is enabled. `/tmp` and `/var/lib/sail` are separate
private 128 MiB tmpfs mounts.

On both CPUs a 805,306,368 B (768 MiB) allocation by an extra in-container process
is killed with **exit 137**, and `memory.events.oom_kill` increases **0 → 1**.
Docker records `OOMKilled=true` while the container remains `Running=true`.
The allocation child was killed; a successful post-OOM Sail query was not checked,
so application recovery after pressure is unverified. Four busy processes under
the one-CPU quota increase `nr_throttled` **0 → 31 amd64 / 0 → 30 arm64**.
This is real cgroup enforcement, not an authorization denial or a large-query SLA.

## Cost model and recommendation

At N=20 after SELECT 42, charged Sail memory is **42.818 MiB/user amd64** and
**42.051 MiB/user arm64**, plus the gateway and fixed shared platform services.
That is the cost of these light warmed instances, not an analytical-user budget.
The single analytical sequence reaches **231.898/153.840 MiB cgroup peak** and
**206.734/216.121 MiB sampled PID RSS** on amd64/arm64.

The earlier unchanged-Sail engine-only benchmark in run 44243517929 also remains
in JSON as historical_engine_only: 20 concurrent million-row aggregates, no
configured catalog/authenticated gateway, used **2,887.625/2,771.750 MiB** warmed
cgroup memory (144.381/138.588 MiB per engine). It is a distinct workload/profile
and is not relabeled as the current 20-user authentication test. It was not rerun
unchanged under the CI-first policy.

Use `RAM ≈ fixed services + resident users × workload memory + burst/headroom`.
Resident means retained through the idle window, not registered users or active
RPCs. A conservative initial reservation is **512 MiB per resident user plus
runtime/controller overhead**, reflecting the enforced cap: **20 caps alone total
10 GiB**. The cap is an enforcement limit, not an OS reservation or proof all
queries fit. For this particular analytical sample, multiplying the larger
232 MiB observed profile peak by 20 gives about 4.53 GiB before fixed services
and headroom; that extrapolation is not a concurrent-workload capacity guarantee.
If RAM costs P per GiB-hour, the linear user component is
`P × resident_users × per_user_MiB / 1024` per hour, plus fixed services/headroom.

Keep per-team as the owner's MVP default. The measured subsecond starts, modest
incremental warm latency and bounded memory support per-user pools for sensitive
groups as a **hybrid target after platform qualification**. Configure aggregate
admission and pressure control before scaling: per-instance caps alone do not
prevent host exhaustion. Per-user mode is opt-in per deployment here; automatic
mixed per-team/per-group routing is not implemented.

## Implemented topology and remaining limits

Upstream [PR #2929](https://github.com/lakehq/sail/pull/2929) recommended separate
lightweight servers for clients needing different catalogs. S3 found the pinned
session manager looks up sessions by ID without checking user ownership.
The same `sail-gateway` role now selects a process by verified subject **after**
JWT validation and Cedar admission. When `SAIL_LIFECYCLE_HELPER` is unset it keeps
S3's shared-backend behavior; that mode retains its session-ownership limitation.

![S5 topology: native feasibility controls pass; full platform remains red](../diagrams/s5-per-user-sail.svg)

The supervisor is a trusted absolute-path host helper and Docker administrator.
An unbuffered per-RPC Docker-exec pipe enters only the selected instance's private
loopback namespace. Its process/inspection overhead is part of the measured
latency. No new Rust crate, feature, Cargo.lock version or upstream patch was
needed. This spike controller needs a narrower production privilege boundary.

Remaining limits: shared static S3 keys/direct paths bypass catalog grants;
C3 membership revocation, C7 recovery and C8 durability remain red; admitted
streams/cached metadata/storage handles have separate revocation semantics.
Idle expiry/crash loses sessions and temporary state. Controller death mid-helper
can leave orphans until reconciliation; host restart scavenging, distributed/HA
ownership, cancellation races and aggregate startup admission are absent.
Graceful drain, post-OOM query recovery, arbitrary Spark compatibility, large
joins/spills, 20 concurrent catalog scans, sustained load and production sizing
are unverified. The 15-second fixture TTL is not a production recommendation.

## Unchanged S3 and C1–C8 regression results

All 14 S3 controls pass on each CPU, including valid human/machine tokens,
missing/expired/wrong-audience/wrong-key/denied-token rejection, revocation on a
fresh RPC, verified TLS, backend isolation, and the unchanged paced stream with
result-connection PING/ACK progress under backpressure.

| Case | amd64 | arm64 |
| --- | --- | --- |
| C1 | PASS | PASS |
| C2 | PASS | PASS |
| C3 | FAIL | FAIL |
| C4 | PASS | PASS |
| C5 | PASS | PASS |
| C6 | PASS | PASS |
| C7 | FAIL | FAIL |
| C8 | FAIL | FAIL |

C5 passes PyIceberg, Trino and Sail on each CPU. **C3 direct-claim adaptation is
unchanged**: unmapped groups deny, explicit group-to-resource mapping permits,
and removing that mapping denies the old token. The original IdP-membership
removal assertion is also retained and FAILS because the unexpired JWT still
contains the group. The three direct-claim subchecks never substitute for that
assertion. C7 fails the post-restart recovery wait; C8 fails exact durable
relationship/grant-state preservation. Between-case fixture resets remain outside
assertions. Repeated durable migrations remain unverified.

The [actual lint log](https://github.com/datopsis/datopsis-authz/actions/runs/44815134976/job/136561381940)
retains three inherited vulnerabilities: libsqlite3-sys / RUSTSEC-2026-0459,
quick-xml / RUSTSEC-2026-0194 and RUSTSEC-2026-0195, plus six warnings.
Native jobs and the required test aggregate therefore remain **FAIL**, even
though all bounded S5 and S3 assertions pass. No gate was weakened or suppressed.

Native workspace compilation/unit tests, YAML validation, formatting and the
690-package lock guard ran in the existing Actions jobs. Local work for this
update was limited to source edits, Python syntax/LF/diff checks and reading CI
logs/artifacts. Cargo.lock and workflow/required checks are unchanged. No secrets,
raw credential artifacts, GitHub settings/secrets/permissions changes, force push,
merge, sign-off or coauthor trailer.

## Historical acquisition failure

The earlier 1e114b8 Rauthy pin rejected rotated FIDO metadata before authenticated
testing. [Historical acquisition evidence](S5-rauthy-acquisition.json) retains
that failure and its hashes; it is **resolved for testing by the coordinator's
01375ef pin**, not an active blocker or a bypass of verification. Earlier
engine-only results remain labeled as such. The current native run supersedes
the old BLOCKED S5 verdict; historical S1/S3 reports retain their original inputs.
