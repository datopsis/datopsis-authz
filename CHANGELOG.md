# Changelog

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
