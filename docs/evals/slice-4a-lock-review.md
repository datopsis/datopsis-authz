# Lakekeeper 0.13.9 dependency review

Coordinator approved 2026-11-26. No unrelated version updates.

## Added identities (replacing the approved old source identities)

| Crate | Version | Source |
| --- | --- | --- |
| azure_core | 0.21.0 | `git+https://github.com/lakekeeper/azure-sdk-for-rust.git?rev=bbdb4946ff486feec05506240358a8e4e9a074e8#bbdb4946ff486feec05506240358a8e4e9a074e8` |
| azure_identity | 0.21.0 | `git+https://github.com/lakekeeper/azure-sdk-for-rust.git?rev=bbdb4946ff486feec05506240358a8e4e9a074e8#bbdb4946ff486feec05506240358a8e4e9a074e8` |
| azure_storage | 0.21.0 | `git+https://github.com/lakekeeper/azure-sdk-for-rust.git?rev=bbdb4946ff486feec05506240358a8e4e9a074e8#bbdb4946ff486feec05506240358a8e4e9a074e8` |
| azure_storage_blobs | 0.21.0 | `git+https://github.com/lakekeeper/azure-sdk-for-rust.git?rev=bbdb4946ff486feec05506240358a8e4e9a074e8#bbdb4946ff486feec05506240358a8e4e9a074e8` |
| azure_storage_datalake | 0.21.0 | `git+https://github.com/lakekeeper/azure-sdk-for-rust.git?rev=bbdb4946ff486feec05506240358a8e4e9a074e8#bbdb4946ff486feec05506240358a8e4e9a074e8` |
| azure_svc_blobstorage | 0.21.0 | `git+https://github.com/lakekeeper/azure-sdk-for-rust.git?rev=bbdb4946ff486feec05506240358a8e4e9a074e8#bbdb4946ff486feec05506240358a8e4e9a074e8` |
| iceberg-ext | 0.13.9 | `git+https://github.com/lakekeeper/lakekeeper?rev=a8e013b30e99e5a184486fe166c3ffb3781a7c36#a8e013b30e99e5a184486fe166c3ffb3781a7c36` |
| lakekeeper | 0.13.9 | `git+https://github.com/lakekeeper/lakekeeper?rev=a8e013b30e99e5a184486fe166c3ffb3781a7c36#a8e013b30e99e5a184486fe166c3ffb3781a7c36` |
| lakekeeper-io | 0.13.9 | `git+https://github.com/lakekeeper/lakekeeper?rev=a8e013b30e99e5a184486fe166c3ffb3781a7c36#a8e013b30e99e5a184486fe166c3ffb3781a7c36` |
| lakekeeper-storage-postgres | 0.13.9 | `git+https://github.com/lakekeeper/lakekeeper?rev=a8e013b30e99e5a184486fe166c3ffb3781a7c36#a8e013b30e99e5a184486fe166c3ffb3781a7c36` |
| sqlx | 0.9.0 | `git+https://github.com/lakekeeper/sqlx.git?rev=2018fe72a7d64b34e7da99f13642a6a61d2af082#2018fe72a7d64b34e7da99f13642a6a61d2af082` |
| sqlx-core | 0.9.0 | `git+https://github.com/lakekeeper/sqlx.git?rev=2018fe72a7d64b34e7da99f13642a6a61d2af082#2018fe72a7d64b34e7da99f13642a6a61d2af082` |
| sqlx-macros | 0.9.0 | `git+https://github.com/lakekeeper/sqlx.git?rev=2018fe72a7d64b34e7da99f13642a6a61d2af082#2018fe72a7d64b34e7da99f13642a6a61d2af082` |
| sqlx-macros-core | 0.9.0 | `git+https://github.com/lakekeeper/sqlx.git?rev=2018fe72a7d64b34e7da99f13642a6a61d2af082#2018fe72a7d64b34e7da99f13642a6a61d2af082` |
| sqlx-mysql | 0.9.0 | `git+https://github.com/lakekeeper/sqlx.git?rev=2018fe72a7d64b34e7da99f13642a6a61d2af082#2018fe72a7d64b34e7da99f13642a6a61d2af082` |
| sqlx-postgres | 0.9.0 | `git+https://github.com/lakekeeper/sqlx.git?rev=2018fe72a7d64b34e7da99f13642a6a61d2af082#2018fe72a7d64b34e7da99f13642a6a61d2af082` |
| sqlx-sqlite | 0.9.0 | `git+https://github.com/lakekeeper/sqlx.git?rev=2018fe72a7d64b34e7da99f13642a6a61d2af082#2018fe72a7d64b34e7da99f13642a6a61d2af082` |

## Removed identities

| Crate | Version | Source |
| --- | --- | --- |
| async-channel | 1.9.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| azure_core | 0.21.0 | `git+https://github.com/lakekeeper/azure-sdk-for-rust.git?rev=f12d268cf04ea668d0224a1a55fc120591e50b9d#f12d268cf04ea668d0224a1a55fc120591e50b9d` |
| azure_identity | 0.21.0 | `git+https://github.com/lakekeeper/azure-sdk-for-rust.git?rev=f12d268cf04ea668d0224a1a55fc120591e50b9d#f12d268cf04ea668d0224a1a55fc120591e50b9d` |
| azure_storage | 0.21.0 | `git+https://github.com/lakekeeper/azure-sdk-for-rust.git?rev=f12d268cf04ea668d0224a1a55fc120591e50b9d#f12d268cf04ea668d0224a1a55fc120591e50b9d` |
| azure_storage_blobs | 0.21.0 | `git+https://github.com/lakekeeper/azure-sdk-for-rust.git?rev=f12d268cf04ea668d0224a1a55fc120591e50b9d#f12d268cf04ea668d0224a1a55fc120591e50b9d` |
| azure_storage_datalake | 0.21.0 | `git+https://github.com/lakekeeper/azure-sdk-for-rust.git?rev=f12d268cf04ea668d0224a1a55fc120591e50b9d#f12d268cf04ea668d0224a1a55fc120591e50b9d` |
| azure_svc_blobstorage | 0.21.0 | `git+https://github.com/lakekeeper/azure-sdk-for-rust.git?rev=f12d268cf04ea668d0224a1a55fc120591e50b9d#f12d268cf04ea668d0224a1a55fc120591e50b9d` |
| base16ct | 1.0.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| cpubits | 0.1.1 | `registry+https://github.com/rust-lang/crates.io-index` |
| crypto-bigint | 0.7.11 | `registry+https://github.com/rust-lang/crates.io-index` |
| der | 0.8.3 | `registry+https://github.com/rust-lang/crates.io-index` |
| ecdsa | 0.17.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| elliptic-curve | 0.14.3 | `registry+https://github.com/rust-lang/crates.io-index` |
| event-listener | 2.5.3 | `registry+https://github.com/rust-lang/crates.io-index` |
| fastrand | 1.9.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| ff | 0.14.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| futures-lite | 1.13.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| getrandom | 0.1.16 | `registry+https://github.com/rust-lang/crates.io-index` |
| group | 0.14.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| http-types | 2.12.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| iceberg-ext | 0.13.4 | `git+https://github.com/lakekeeper/lakekeeper?rev=9bd377162345b64a716f0a4fcffe4e7e7f3c7534#9bd377162345b64a716f0a4fcffe4e7e7f3c7534` |
| infer | 0.2.3 | `registry+https://github.com/rust-lang/crates.io-index` |
| instant | 0.1.13 | `registry+https://github.com/rust-lang/crates.io-index` |
| lakekeeper | 0.13.4 | `git+https://github.com/lakekeeper/lakekeeper?rev=9bd377162345b64a716f0a4fcffe4e7e7f3c7534#9bd377162345b64a716f0a4fcffe4e7e7f3c7534` |
| lakekeeper-io | 0.13.4 | `git+https://github.com/lakekeeper/lakekeeper?rev=9bd377162345b64a716f0a4fcffe4e7e7f3c7534#9bd377162345b64a716f0a4fcffe4e7e7f3c7534` |
| lakekeeper-storage-postgres | 0.13.4 | `git+https://github.com/lakekeeper/lakekeeper?rev=9bd377162345b64a716f0a4fcffe4e7e7f3c7534#9bd377162345b64a716f0a4fcffe4e7e7f3c7534` |
| p256 | 0.14.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| pem-rfc7468 | 1.0.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| pkcs8 | 0.11.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| primefield | 0.14.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| primeorder | 0.14.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| rand | 0.7.3 | `registry+https://github.com/rust-lang/crates.io-index` |
| rand_chacha | 0.2.2 | `registry+https://github.com/rust-lang/crates.io-index` |
| rand_core | 0.5.1 | `registry+https://github.com/rust-lang/crates.io-index` |
| rand_hc | 0.2.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| rfc6979 | 0.6.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| sec1 | 0.8.1 | `registry+https://github.com/rust-lang/crates.io-index` |
| serde_qs | 0.8.5 | `registry+https://github.com/rust-lang/crates.io-index` |
| serdect | 0.4.3 | `registry+https://github.com/rust-lang/crates.io-index` |
| signature | 3.0.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| spki | 0.8.1 | `registry+https://github.com/rust-lang/crates.io-index` |
| sqlx | 0.9.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| sqlx-core | 0.9.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| sqlx-macros | 0.9.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| sqlx-macros-core | 0.9.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| sqlx-mysql | 0.9.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| sqlx-postgres | 0.9.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| sqlx-sqlite | 0.9.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| waker-fn | 1.2.0 | `registry+https://github.com/rust-lang/crates.io-index` |
| wasi | 0.9.0+wasi-snapshot-preview1 | `registry+https://github.com/rust-lang/crates.io-index` |
| wnaf | 0.14.1 | `registry+https://github.com/rust-lang/crates.io-index` |

The removals follow upstream dropping Azure http-types and AWS sigv4a dependency paths. No new unrelated dependency tree or major version jump is selected.

Two direct transport edges were added to `lakekeeper-bin-datopsis`: already locked `axum-server 0.7.3` and `tokio-rustls 0.26.6`. No new crate/version is introduced by the TLS transport.

## Adapter interfaces

The production `crates/lakekeeper/src/service/authz/mod.rs` prefix before `pub mod tests` is byte-identical between 9bd3771 and a8e013b. The Authorizer trait and all action/lifecycle methods are unchanged. The ServeConfiguration API and authentication/composition calls used by this binary are unchanged. No Cedar authorizer behavior or adapter interface change is required. Storage-postgres pool/state and migrate_core_only signatures are unchanged.

Lakekeeper 0.13.6 (29c53e3) stopped emitting credential-less storage-credentials entries. C6 now explicitly requires absence for its static non-STS profile, retaining all denied-credential and secret-key assertions.


## Coordinator-approved TLS refresh (2026-11-27)

Baseline: PR head `56958317324edd37cac6d74ed360036b554d8565`.
Latest non-yanked 0.9 patch verified from crates.io: **axum-server 0.9.2**
(0.9.1 is yanked). Both consumers pin exactly `=0.9.2`.

Every additional Cargo.lock identity change:

| Crate | Before | After | Reason |
| --- | --- | --- | --- |
| axum-server | 0.7.3 | 0.9.2 | Approved TLS transport refresh |
| rustls-pemfile | 2.2.0 | removed | axum-server now parses PEM via already-locked rustls-pki-types |

No other crate version, checksum, git source or existing package entry changed.
The axum-server dependency-edge changes are:

- Before: `arc-swap, bytes, fs-err, http 1.5.0, http-body, hyper, hyper-util, pin-project-lite, rustls, rustls-pemfile, rustls-pki-types, tokio, tokio-rustls, tower-service`
- After: `arc-swap, bytes, either, fs-err, http 1.5.0, http-body, hyper, hyper-util, pin-project-lite, rustls, rustls-pki-types, socket2, tokio, tokio-rustls, tower-service`

API adaptation: 0.9's `bind_rustls` accepts a generic Address. The serve role's
listen-address parse now explicitly selects `std::net::SocketAddr`; the same
address/default is retained. RustlsConfig::from_pem_file and get_inner APIs used
by both binaries and the Sail gateway are unchanged, so no other Rust adaptation
is needed. TLS provider, ALPN configuration, roots, verification, role behavior,
and all negative TLS and C1-C8/Trino/Sail oracles are unchanged. rustls-pki-types
was already resolved; there is no new dependency tree.

## SQLite removal follow-up (2026-11-28)

The sole additional Cargo.lock change replaces authz-serve's `sqlx` dependency
edge with `sqlx-core` and `sqlx-postgres`. Both already exist at 0.9.0, full
reviewed SQLx fork revision 2018fe72a7d64b34e7da99f13642a6a61d2af082.
No package identity, version, source or checksum is added, removed or changed.
The authz-only derived build lock may prune unreachable packages/edges only,
with integrity validation before `--locked --offline` compilation. SQLx's facade
reexports the exact core/Postgres functions/types now imported directly; no
SQL/transaction/migration/TLS/JSON or catalog code is changed.
