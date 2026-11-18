# Security

Report vulnerabilities privately to the repository owner; do not post credentials
or exploit details in public issues.

Slice 1 protects catalog decisions. It does not prevent direct S3 access using
existing static engine credentials, revoke already-issued storage credentials,
or revoke data already fetched. STS and engine-side enforcement remain later work.
The current images are acceptance tooling, not hardened production releases.

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
dependencies. There is no upstream Azure-disable feature; the gate must stay red
until that dependency is removed or safely updated under the owner's approval rule.
