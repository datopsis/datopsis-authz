# Security

Report vulnerabilities privately to the repository owner; do not post credentials
or exploit details in public issues.

Slice 1 protects catalog decisions. It does not prevent direct S3 access using
existing static engine credentials, revoke already-issued storage credentials,
or revoke data already fetched. STS and engine-side enforcement remain later work.
Slice 4a adds hardened source images with blocking admission gates; they are not
security-qualified releases while the known shipped quick-xml findings remain.

Lakekeeper validates OIDC signatures, issuer, audience and expiry. The adapter
asserts the verified principal to serve over verified TLS using a protected
service credential. Serve's mutation/snapshot APIs are trusted control-plane APIs;
never expose them to clients. Catalog grant routes bind identity to RequestMetadata,
never request headers or supplied principal JSON. Owners can grant owner/select;
readers cannot administer grants. Instance-admin bypass configuration is rejected;
use Cedar owner grants. Upstream in-process maintenance auditing is not persisted
by serve. The service key is mutation-capable: key scoping,
rotation and mTLS are not implemented.

Rauthy access is mandatory. Use a separate Users/read API key and a private CA.
No JWT-group fallback or stale-on-error exists. Positive/negative membership
responses can remain cached for 250 ms; lookup timeout is 2 seconds, concurrency
16 and cache capacity 10,000 principals. Revocation latency also includes network
and catalog work. Machine subject exceptions are explicit deployment configuration,
not inferred from arbitrary missing users. Missing/disabled humans fail closed.
Set normal access-token lifetime to 900 seconds; token expiry is a backstop.

PostgreSQL uses hostname and CA verification (`sslmode=verify-full`) even if a URL
requests weaker TLS. Use an application-only database and protected credential
files. Migrations take a transaction advisory lock and run atomically. Audit
UPDATE, DELETE and TRUNCATE are rejected by a trigger, including for the table
owner; a database administrator can alter schema/triggers. Audit is append-only
under the application interface, not independently tamper-evident against a DBA.
Backups, retention, audit export and HA recovery require operational qualification.
No permit response is returned if audit persistence fails. An unavailable database
cannot durably record its own failure; requests fail with 503 and must be recorded
by deployment access/error monitoring.

The blocking dependency gate covers normal dependencies selected for both shipped
binaries in their actual workspace feature set. Build-only/unselected findings
are reported separately. No advisory ignores are permitted. The pinned Lakekeeper
currently requires vulnerable quick-xml 0.40.1 through unconditional Azure SDK
dependencies. Owner decision 2026-11-18: "upstream Lakekeeper, Azure path, no fix yet; upstream proposal in progress". Keep lint RED with no ignore entry and no S3-only
Lakekeeper patch. Continue the other slice-1 work; merge waits for upstream's fix.


Image deployments must enforce read-only roots, UID 10001, no capabilities and
no-new-privileges. Both public service transports require TLS with operator
material and fail closed on missing configuration. Catalog plaintext API/metrics
are constrained to loopback behind its in-process TLS transport. Do not expose
these private listeners. No default encryption/service key or TLS-off switch is
accepted. See [runtime configuration](docs/IMAGES.md).

Shipped RustSec classification comes from each actual binary's cargo-auditable
runtime inventory; build/proc-macro/unselected dependencies are reported
separately. Owner policy (2026-11-27): a shipped RustSec advisory blocks when its
`versions.patched` list is nonempty, whatever its type. Shipped advisories with
no patched version are report-only and tracked; their type alone cannot grant
an exemption. Build-only/unselected findings remain report-only. Invalid or
missing patch evidence fails closed. Both image
scanners and native UBI fix queries are mandatory; no query failure can qualify
an RPM deferral. Provenance must match the PR head and the artifact lock hash.


The one [RustSec tracking issue](docs/RUSTSEC-TRACKING.md) is updated only when the
tracking set (including patch/replacement guidance) changes. Daily checks use
fresh RustSec data against the latest completed default-branch native image
inventories and their exact source lock. New patched versions make the advisory
blocking automatically in both gates, with no per-ID configuration.
