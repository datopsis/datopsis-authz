# Changelog

## Owner decisions — 2026-11-27

- Upgrade axum-server 0.7.3 to the latest non-yanked 0.9 patch, 0.9.2, in both
  binaries; remove rustls-pemfile 2.2.0. Only the generic bind address needs an
  explicit SocketAddr type. Preserve TLS behavior and all native negative cases.
- Share a data-driven RustSec policy across source lint and shipped-binary
  gates: published patched versions for shipped crates block for every advisory
  type. No-patch advisories are reported/tracked without blocking; build-only or
  unselected crates stay report-only. No per-ID ignores or exemptions.
- Add one marked tracking issue and daily fresh-advisory tracking, with comments
  only when its set/patch/replacement guidance changes. PR CI bootstraps the same
  issue from both native image reports; daily scheduling activates on main.


## Slice 4a (in progress)

- Isolate authz's PostgreSQL-only production workspace and select its package
  explicitly. Validate the offline-pruned lock as a strict subset of approved
  identities/checksums/edges; preserve the committed lock and catalog recipe.
  Require SQLite to be absent from authz's actual embedded inventory, without
  suppressing any advisory or changing catalog findings.

- Pin cargo-auditable 0.7.8 native tool archives by official release SHA-256;
  preserve the required format-2 proc-macro distinction and qualify inventories
  before external fixture builds. Reuse release dependencies for workspace tests.


- Upgrade unmodified Lakekeeper to 0.13.9 at `a8e013b30e99e5a184486fe166c3ffb3781a7c36`.
  Carry upstream's seven SQLx 0.9.0 patches by full commit
  `2018fe72a7d64b34e7da99f13642a6a61d2af082`, fixing cancellation during BEGIN
  (transact-rs/sqlx#4393 via #4394); drop with the first SQLx release containing
  #4394. Adopt upstream Azure revision `bbdb4946ff486feec05506240358a8e4e9a074e8`.
  Record every added/removed lock identity in the slice-4a dependency review.
- Build separate authz and lakekeeper-authz source images on locked UBI 9 RPMs;
  embed cargo-auditable data and gate shipped RustSec findings separately from
  build-only reports. Trivy/Grype gates retain the organization UBI availability rule.
- Terminate catalog TLS in our composition binary; constrain unmodified upstream
  API/metrics to loopback. No Cedar authorizer behavior or interface change.
- Require C6 absence of credential-less storage entries since Lakekeeper 0.13.6.


- Pin the coordinator-approved unmerged Rauthy PR #3 test input to
  `52c3fec20beca1975467a9c955730082cef8bf46` (same verified FIDO serial 303;
  known SvelteKit gate remains RED).
- Warm the exact SHA-256-keyed feed cache once before native CI. Run the pinned
  owner's full publisher/freshness verification on every cache hit and again in
  each image build; cache only JWT bytes and save before later security gates.

## Catalog MVP slice 1 (unreleased)

- Refresh the coordinator-approved unmerged Rauthy PR #3 test pin to 1bedace6e61627820e0f863a86c6ccc791f5e22b (verified FIDO serial 303). Keep checksum/authenticated-feed guards and the red SvelteKit disclosure.

- Correct the catalog grant fixture's single-table API route and measure C4 from the mutation response acknowledgement, before readback.

- Bound FIDO publisher HTTP 429 retries and reuse each CI job's exact verified feed bytes; retain the owner's hash, signature/path/serial/date and fresh-CRL verification.

- Repin Rauthy to coordinator-approved unmerged PR #3 commit 01375efb2a14692a7977f2f8aa60121f3fcc2f01 (verified FIDO serial 302); retain its red SvelteKit gate disclosure.
- Repin the catalog PostgreSQL fixture to merged 18.7 commit 1054729c5fa934e2a801a36d81a8b2b264aa8829 without editing the external harness; retain all checksum and provenance guards.

- Preserve grant-management decision audits for invalid mutations and Cedar evaluation failures.
- Record the owner's quick-xml decision: upstream Lakekeeper, Azure path, no fix yet; upstream proposal in progress. Keep lint red without ignores or an S3-only patch; merge waits for upstream.
- Record CI-first validation: only lightweight checks locally; builds, scans, artifact acquisition and runtime/multi-architecture validation stay in existing PR jobs.

- Repin the relationship-store PostgreSQL fixture to the merged 18.7 owner commit; remove the obsolete 18.6 RPM transport fallback.

- PostgreSQL relationship/grant persistence, repeatable migrations and append-only decision audit.
- Mandatory live Rauthy membership resolution, bounded 250 ms cache and fail-closed outage behavior.
- Catalog owner grant-management API and native C1–C8 fixture coverage with 15-minute tokens.
- Runtime dependency audit classification; unconditional Azure/quick-xml remains blocking.

## Unreleased

- Start S1: pinned Lakekeeper trait analysis, Cedar core, HTTPS decision API,
  compiled authorizer adapter, thin catalog binary and native CI proof.
- Record native amd64/arm64 results: five acceptance cases pass, with strict
  membership-revocation and restart/recovery failures retained as spike findings.
- Preserve sanitized run evidence, input provenance and runtime-library hashes.
