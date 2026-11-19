# Changelog

## Catalog MVP slice 1 (unreleased)

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
