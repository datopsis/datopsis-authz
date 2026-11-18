# S5: per-user Sail lifecycle and isolation

Status: **runtime evidence pending**. This is a bounded spike, not an MVP decision.
Stacked on `room/datopsis-authz-spike-s3-sail-gateway`; S1/S3 acceptance failures
remain failures. No upstream modification, dependency addition, or lock change.

## Question and implementation

Can an idle-reaped Sail instance per verified user be affordable? S3's shared
backend indexes sessions by session ID without enforcing user ownership. S5's
`sail-gateway` role optionally selects a distinct instance by the verified JWT
subject **after** signature/issuer/audience validation and Cedar admission.
Client-provided session IDs and UserContext never select a different subject.
The S3 shared-backend mode remains available when `SAIL_LIFECYCLE_HELPER` is unset.

[Topology](../diagrams/s5-per-user-sail.svg). The host gateway calls a trusted
absolute-path supervisor using private stdin JSON. No JWT appears in argv or
container environment. A per-user mutex coalesces simultaneous starts; a stream
lease prevents idle reaping during active result delivery. The fixture reaps
instances 15 seconds after their last stream finishes, with a one-second sweep.
The Python supervisor uses Docker on the trusted host; Sail receives no Docker
socket, added capabilities, writable root, host networking, or host PID namespace.

Each Sail process listens on 127.0.0.1:50052 **inside its own network namespace**.
There are no published Sail ports. An unbuffered `docker exec` pipe carries HTTP/2
from the host gateway into that namespace. This deliberately simple spike
transport includes per-RPC process/inspection overhead; its latency must not be
presented as a tuned production lower bound. The deployment controller is a
privileged trust boundary; the Sail containers are unprivileged UID 10001.

Each instance mounts only its own read-only token directory and configuration,
plus the public CA. Host parent directories are root-owned 0700, instance token
directories UID 10001 mode 0500, JWTs UID 10001 mode 0400. Directory binds permit
atomic refresh without exposing a truncated token. Only a validated JWT for that
same subject refreshes the instance. Private 128 MiB tmpfs mounts cover `/tmp` and
`/var/lib/sail`. The instance has a 512 MiB memory+swap cap, one CPU, and 128 PIDs.
The controller/root administrator can read tokens by design; other Sail instances
have neither a mount nor a host pathname to them. This is container isolation,
not protection from a compromised host/kernel.

The supervisor removes a crashed container and its token directory before
creating a new randomly named instance. Idle teardown removes both. Final cleanup
reconciles all fixture-labeled instances and deletes the private runtime tree.
A controller crash is not an idle-timeout guarantee: restart reconciliation and
bounded orchestration cancellation remain production work.

## Reproduction and measurement contract

GitHub Actions runs native ubuntu-24.04 (amd64) and ubuntu-24.04-arm (arm64),
asserting `uname -m`; no emulation. The existing owner fixture builds and
provenance checks are reused unchanged:

- Sail owner `e96e068f926b8fecb3939e953389685ee4780032` (Sail 0.7.3).
- Rauthy owner `1e114b84b01988bf15306b110b040378878488d3`.
- Acceptance fixture `e8379a528bf413c05aad49e56bc8cd507b5e077a`.
- Lakekeeper `9bd377162345b64a716f0a4fcffe4e7e7f3c7534`.

`evaluation/s5/run.py` composes Rauthy, Lakekeeper and Cedar with genuine PKCE
human tokens. It measures prebuilt-image process cold start (not image pulls or
builds), socket readiness, Sail PID RSS from `/proc`, total cgroup v2 memory, and
cgroup peak memory. A direct loopback tunnel establishes the same engine's
baseline `SELECT 42`; the representative finite query sums a million range rows
and counts distinct IDs, requiring exactly 499999500000 and 1000000 respectively. Polls every 50 ms are supplemented by the
kernel's peak counter. Stop time uses forced container removal and credential deletion; graceful shutdown is not measured.

Gateway latency is timed at ExecutePlan, including a fresh TLS channel, live JWKS
lookup, live Cedar call, lifecycle and relay. Later-query samples reuse the user's
instance, with five samples per isolation user. First-versus-baseline deltas are
single-run observations, not p95/p99 service guarantees. Scale uses 1, 5 and 20
distinct, genuinely authenticated users with simultaneous queries; all start cold.
It retains every per-instance readiness duration, every first-query duration,
errors, PID RSS, and cgroup totals. These are idle-after-query concurrent instances,
not twenty concurrent heavy scans or production capacity qualification.

Both users deliberately submit the **same session ID** and a forged UserContext.
Each reads only its granted namespace, denies the other's namespace and catalog
writes, inherits access to a newly created table, then moves to a single-table
grant and denies its sibling. Fresh sessions are used for fresh catalog checks
following grant changes. Separate temp-view and cross-container socket/tmpfs
controls exercise the process/session boundary. Five simultaneous first queries
for one user must create exactly one instance. The unchanged owner-paced million-row
stream must outlive the idle timeout without reaping the active instance. A 768 MiB allocation under the
512 MiB cap must increment `oom_kill`; four busy processes must increment CPU
throttling counters under the one-CPU quota. Neither failure qualifies as an
authorization denial.

## Measurements

Pending actual native Actions logs and sanitized artifacts. Missing runtime
prerequisites are BLOCKED, never passing measurements. S1 C1–C8 and S3 assertions
are retained and still run in CI; S5 does not replace their acceptance contract.

## Cost model and recommendation

Pending measured per-user RSS/cgroup totals. Budget using cgroup memory (which
includes charged filesystem/cache/tmpfs and relay overhead), not Sail PID RSS
alone. For U simultaneously active users, reserve fixed platform overhead plus
U times measured active-user memory, with headroom for queries and cold-start
bursts. A hard 512 MiB cap bounds one instance, not aggregate host admission.
Provisioning U times that cap is a conservative reservation, not observed usage.
At 20 users this is 10 GiB of instance caps before shared services and headroom.

The owner's **per-team MVP default remains the baseline decision**. A hybrid may
be appropriate for sensitive groups if the measured economics support it, but
process separation alone does not establish full per-user data enforcement.
The inherited STS-disabled fixture gives Sail shared static storage credentials:
an admitted user able to submit direct storage paths can bypass catalog grants.
Scoped storage credentials/egress and direct-path controls are required before
calling either topology a complete per-user authorization boundary.

## Failure modes and unverified scope

- A cold-start burst can exhaust host memory or PIDs despite per-instance caps;
  aggregate admission, a startup queue and pressure-aware eviction are absent.
- Idle expiry and crash destroy temporary views, sessions and query state. Clients
  need explicit expired-session/reconnect behavior; transparent state recovery is
  not promised. A running stream holds its lease, including downstream pressure.
- JWT refresh uses new authenticated RPCs; an idle session does not refresh tokens.
  Expired JWTs deny at the gateway; already admitted streams and cached engine
  metadata/storage access have separate revocation semantics. C3 remains red.
- Failed helper startup cleans up its instance; controller death during a helper
  operation can leave an orphan until reconciliation. HA ownership, host restart,
  distributed leases, cancellation races and restart scavenging are unqualified.
- Shared static S3 credentials, full plan/path authorization and STS scope remain
  gaps. C7/C8 durability/recovery and the inherited audit findings are unchanged.
- Container limits protect neighbors from a single allocation; memory pressure
  behavior of real large joins/spills and twenty heavy concurrent queries is
  unverified. No production pricing, HA or dedicated-host economics is claimed.
