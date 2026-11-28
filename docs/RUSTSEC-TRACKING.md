# RustSec fixability and tracking

Owner decision: 2026-11-27. Both the source lint gate and the binary-inventory
gate use `scripts/rustsec_policy.py`, with no advisory-ID or crate exceptions.

| Finding | Gate decision |
| --- | --- |
| Shipped RustSec advisory with nonempty `versions.patched` | BLOCK, whatever its type or severity |
| Shipped advisory with empty `versions.patched` | REPORT in job summary and TRACK in one issue |
| Build-only / unselected advisory | Separate report only |
| Missing / malformed evidence, scanner execution failure | Fail closed |

The binary gate reads the actual ELF's cargo-auditable runtime inventory; source
lint uses the normal dependency graph excluding procedural macros. Both retain
the raw full-lock audit and all warnings. Stable Cargo metadata may overinclude
crates (notably SQLite); no manual reachability exemption is applied.

`axum-server =0.9.2` removes rustls-pemfile. Chrono's unmaintained advisory has no
patched version and therefore becomes report-only. A type such as unmaintained
or unsound never independently controls the decision: a published patch makes
any shipped advisory blocking. The expected remaining findings include the
fixable upstream quick-xml pair, parquet, Grype's Thrift finding and SQLite when
selected by the binary inventory. Image-scanner/UBI policy is unchanged.

## The one tracking issue

The native CI follow-on job reads both complete architecture/image report sets
and upserts one issue identified by a repository-wide marker. It validates the
binary/source identities and refuses partial, mixed or malformed evidence. It
reports no-patch shipped advisories only; build-only/unselected findings remain
in CI reports. It serializes issue updates across workflows, checks all open and
closed issues for the marker, and refuses duplicate marked issues.

Issue state includes crate/version/advisory, published patched requirements,
selected image/CPU scopes, and publisher replacement guidance. No run timestamp,
source-head update or advisory-database commit alone changes that state. An
unchanged state produces neither a body edit nor a comment. A changed set
updates the same issue and comments once. A newly published patch is flagged
**FIX AVAILABLE** and remains tracked until resolved/unselected; a newly added
or changed publisher replacement recommendation is flagged for review. The
script never invents or automatically installs a replacement. State is persisted
before commenting so retries cannot duplicate a comment after a partial failure.

The daily `RustSec advisory tracking` workflow runs at 08:23 UTC (and supports
manual dispatch). GitHub schedules activate only after this workflow reaches
the default branch; no merge or repository setting change is performed here.
Before merge, internal PR CI exercises the issue publisher with actual native
reports. Fork PRs retain all security/regression gates but cannot write issues;
default-branch tracking remains authoritative after merge.

The scheduled check selects the latest **completed** default-branch CI run,
including runs honestly red on security findings. It downloads both native
report artifacts, fetches that exact image-source Cargo.lock and checks its hash
against the native reports, then runs a fresh RustSec audit. Patch/replacement
changes are therefore detected even if no new image has been built. The raw
refresh evidence is retained. If the latest run lacks complete native evidence,
tracking fails rather than treating missing reports as an empty/resolved set.

Only the tracking jobs request issues:write; normal jobs retain their existing
permissions. No pull_request_target execution, GitHub setting change, human
sign-off, advisory ignore or exemption list is involved. The issue's recorded
IDs are tracking data and are never an input to either security gate.
