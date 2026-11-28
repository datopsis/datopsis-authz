mod database;
mod gateway;
mod opa;
use authz_core::{Check, Mutation, Store, Verdict};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use database::Database;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
type MembershipCache = BTreeMap<String, (Instant, Vec<String>)>;
#[derive(Clone)]
struct Live {
    client: reqwest::Client,
    url: String,
    key: String,
    cache: Arc<RwLock<MembershipCache>>,
    machines: Vec<String>,
    limit: Arc<tokio::sync::Semaphore>,
}
impl Live {
    async fn groups(&self, principal: &str) -> Result<Option<Vec<String>>, StatusCode> {
        let ttl = 250;
        if let Some((at, groups)) = self
            .cache
            .read()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .get(principal)
            && at.elapsed() < Duration::from_millis(ttl)
        {
            return Ok(Some(groups.clone()));
        }
        // Validate before any lookup: only plain IdP subject IDs become a URL segment.
        let subject = principal
            .strip_prefix("oidc~")
            .filter(|s| valid_subject(s))
            .ok_or(StatusCode::FORBIDDEN)?;
        let _permit = self.limit.acquire().await.map_err(unavailable)?;
        // No stale-on-error path. Redirects and plaintext are disabled at construction.
        let mut url =
            reqwest::Url::parse(&self.url).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        url.path_segments_mut()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .push(subject);
        let start = Instant::now();
        let response = self
            .client
            .get(url)
            .header("authorization", &self.key)
            .send()
            .await
            .map_err(|_| {
                eprintln!("membership transport failed");
                StatusCode::SERVICE_UNAVAILABLE
            })?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return if self.machines.iter().any(|p| p == principal) {
                Ok(Some(vec![]))
            } else {
                Err(StatusCode::FORBIDDEN)
            };
        }
        let user: serde_json::Value = response
            .error_for_status()
            .map_err(|_| {
                eprintln!("membership HTTP failed");
                StatusCode::SERVICE_UNAVAILABLE
            })?
            .json()
            .await
            .map_err(|_| {
                eprintln!("membership JSON failed");
                StatusCode::SERVICE_UNAVAILABLE
            })?;
        let groups = parse_groups(&user, subject).inspect_err(|_| {
            eprintln!("membership validation failed");
        })?;
        {
            let mut cache = self.cache.write().map_err(unavailable)?;
            if cache.len() >= 10000 {
                cache.retain(|_, (at, _)| at.elapsed() < Duration::from_millis(250));
            }
            if cache.len() < 10000 {
                cache.insert(principal.into(), (start, groups.clone()));
            }
        }
        println!(
            "{}",
            serde_json::json!({"membership_lookup_ms": start.elapsed().as_secs_f64()*1000.0})
        );
        Ok(Some(groups))
    }
}
/// Rauthy user IDs and client IDs: 1-256 of `[A-Za-z0-9._@+-]`, never `.`/`..`.
/// Rejects empty values, path separators, query/fragment markers, percent
/// escapes, whitespace and control characters before a URL is built.
fn valid_subject(subject: &str) -> bool {
    !subject.is_empty()
        && subject.len() <= 256
        && subject != "."
        && subject != ".."
        && subject
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_@+".contains(&b))
}
/// Constant-time comparison for service credentials (length is not secret).
fn same_secret(presented: &[u8], expected: &[u8]) -> bool {
    if expected.is_empty() || presented.len() != expected.len() {
        return false;
    }
    let diff = presented
        .iter()
        .zip(expected)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    std::hint::black_box(diff) == 0
}
fn bearer_matches(headers: &HeaderMap, key: &str) -> bool {
    headers
        .get("authorization")
        .and_then(|v| v.as_bytes().strip_prefix(b"Bearer "))
        .is_some_and(|token| same_secret(token, key.as_bytes()))
}
/// Administrative credential (AUTHZ_KEY_FILE): graph mutation, snapshot, grant
/// management and native decisions. Process-wide so the decision-only `App.key`
/// held by the Sail gateway can never be mistaken for it. Unset denies.
static ADMIN_KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
fn authenticate_admin(headers: &HeaderMap) -> Result<(), StatusCode> {
    match ADMIN_KEY.get() {
        Some(key) if bearer_matches(headers, key) => Ok(()),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
/// Why a live lookup failed, for the durable audit. Unknown or malformed
/// principals are not an identity-provider outage.
fn membership_reason<T>(result: &Result<T, StatusCode>) -> Option<&'static str> {
    match result {
        Ok(_) => None,
        Err(StatusCode::FORBIDDEN) => Some("unknown_principal"),
        Err(_) => Some("identity_provider_unavailable"),
    }
}
fn parse_groups(user: &serde_json::Value, subject: &str) -> Result<Vec<String>, StatusCode> {
    if user.get("id").and_then(serde_json::Value::as_str) != Some(subject)
        || user.get("enabled").and_then(serde_json::Value::as_bool) != Some(true)
    {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    match user.get("groups") {
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or(StatusCode::SERVICE_UNAVAILABLE)
            })
            .collect(),
        // Rauthy 0.37.2 uses skip_serializing_if=None for empty membership.
        None | Some(serde_json::Value::Null) => Ok(vec![]),
        _ => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}
#[cfg(test)]
mod membership_tests {
    use super::*;
    #[test]
    fn pinned_rauthy_empty_membership_and_malformed_user() {
        let empty = serde_json::json!({"id":"alice", "enabled":true});
        assert_eq!(parse_groups(&empty, "alice").unwrap(), Vec::<String>::new());
        assert!(parse_groups(&empty, "bob").is_err());
        assert!(parse_groups(&serde_json::json!({}), "alice").is_err());
        assert!(parse_groups(&serde_json::json!({"id":"alice","enabled":false}), "alice").is_err());
        assert!(
            parse_groups(
                &serde_json::json!({"id":"alice","enabled":true,"groups":{}}),
                "alice"
            )
            .is_err()
        );
        assert_eq!(
            parse_groups(
                &serde_json::json!({"id":"alice","enabled":true,"groups":["readers"]}),
                "alice"
            )
            .unwrap(),
            vec!["readers"]
        );
    }
}
#[derive(Clone)]
struct App {
    key: String,
    trino_key: Option<String>,
    live: Live,
    db: Database,
}
/// Decision-only credential (AUTHZ_DECISION_KEY_FILE), held by the Sail gateway.
fn authenticate(app: &App, headers: &HeaderMap) -> Result<(), StatusCode> {
    if bearer_matches(headers, &app.key) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
fn authenticate_decision(app: &App, headers: &HeaderMap) -> Result<(), StatusCode> {
    authenticate(app, headers).or_else(|_| authenticate_admin(headers))
}
// Trusted gateway only. Membership comes from exactly the catalog/Trino live path.
// The gateway commits the final admission audit (including invalid JWTs) itself.
async fn sail_groups(
    State(app): State<App>,
    headers: HeaderMap,
    Json(principal): Json<String>,
) -> Result<Json<Vec<String>>, StatusCode> {
    authenticate(&app, &headers)?;
    app.live
        .groups(&principal)
        .await?
        .map(Json)
        .ok_or(StatusCode::FORBIDDEN)
}
async fn decide(
    State(app): State<App>,
    headers: HeaderMap,
    Json(checks): Json<Vec<Check>>,
) -> Result<Json<Vec<Verdict>>, StatusCode> {
    authenticate_decision(&app, &headers)?;
    let mut results = vec![];
    // Resolve membership before opening a database transaction.
    let mut resolved = vec![];
    for mut check in checks {
        let live = app.live.groups(&check.principal).await;
        let reason = match live {
            Ok(Some(groups)) => {
                check.groups = groups;
                None
            }
            Ok(None) => {
                check.deny = true;
                Some("unknown_principal")
            }
            Err(_) => {
                check.deny = true;
                membership_reason(&live)
            }
        };
        resolved.push((check, reason));
    }
    let (mut tx, store) = app.db.locked().await.map_err(unavailable)?;
    let mut failed = false;
    for (check, error) in resolved {
        let (verdict, reason) = match store.decide(&check) {
            Ok(v) => {
                let reason = error.unwrap_or(if v.allowed {
                    "cedar_permit"
                } else {
                    "cedar_default_deny"
                });
                (v, reason)
            }
            Err(error) => {
                eprintln!("Cedar evaluation failed: {error}");
                failed = true;
                (
                    Verdict {
                        allowed: false,
                        policies: vec![],
                    },
                    "evaluation_error",
                )
            }
        };
        failed |= error.is_some();
        Database::audit(&mut tx, &check, &verdict, reason)
            .await
            .map_err(unavailable)?;
        results.push(verdict);
    }
    // No decision leaves the service until its audit is durable.
    tx.commit().await.map_err(unavailable)?;
    if failed {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(Json(results))
}
fn unavailable<E>(_: E) -> StatusCode {
    StatusCode::SERVICE_UNAVAILABLE
}
async fn mutate(
    State(app): State<App>,
    headers: HeaderMap,
    Json(m): Json<Mutation>,
) -> Result<StatusCode, StatusCode> {
    authenticate_admin(&headers)?;
    authz_core::validate_mutation(&m).map_err(|_| StatusCode::BAD_REQUEST)?;
    app.db.mutate(m).await.map_err(unavailable)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn snapshot(State(app): State<App>, headers: HeaderMap) -> Result<Json<Store>, StatusCode> {
    authenticate_admin(&headers)?;
    Ok(Json(app.db.snapshot().await.map_err(unavailable)?))
}
#[derive(serde::Deserialize)]
struct PermissionRequest {
    check: Check,
    grant: Option<authz_core::Grant>,
    #[serde(default)]
    remove: bool,
}
async fn permissions(
    State(app): State<App>,
    headers: HeaderMap,
    Json(mut request): Json<PermissionRequest>,
) -> Result<Json<Vec<authz_core::Grant>>, StatusCode> {
    authenticate_admin(&headers)?;
    request.check.action = "manage_grants".into();
    let live = app.live.groups(&request.check.principal).await;
    let (mut tx, mut store) = app.db.locked().await.map_err(unavailable)?;
    request.check.groups = live
        .as_ref()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_default();
    request.check.deny |= live.is_err();
    let (verdict, evaluation_failed) = match store.decide(&request.check) {
        Ok(verdict) => (verdict, false),
        Err(error) => {
            eprintln!("Cedar evaluation failed: {error}");
            (
                Verdict {
                    allowed: false,
                    policies: vec![],
                },
                true,
            )
        }
    };
    Database::audit(
        &mut tx,
        &request.check,
        &verdict,
        if evaluation_failed {
            "evaluation_error"
        } else if let Some(reason) = membership_reason(&live) {
            reason
        } else if verdict.allowed {
            "grant_management_permit"
        } else {
            "grant_management_deny"
        },
    )
    .await
    .map_err(unavailable)?;
    if !verdict.allowed {
        tx.commit().await.map_err(unavailable)?;
        return Err(if live.is_err() || evaluation_failed {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::FORBIDDEN
        });
    }
    if let Some(grant) = request.grant {
        if grant.resource != request.check.resource
            || store
                .mutate(Mutation::Grant {
                    grant,
                    remove: request.remove,
                })
                .is_err()
        {
            // The authorization decision still happened. Preserve its audit
            // even though the invalid mutation must not change the graph.
            tx.commit().await.map_err(unavailable)?;
            return Err(StatusCode::BAD_REQUEST);
        }
        Database::save(&mut tx, &store).await.map_err(unavailable)?;
    }
    let grants = store
        .grants
        .into_iter()
        .filter(|g| g.resource == request.check.resource)
        .collect();
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(grants))
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let role = std::env::args().nth(1).unwrap_or_default();
    match role.as_str() {
        "policy" => {
            authz_core::validate_schema()?;
            return Ok(());
        }
        "migrate" => {
            Database::migrate_from_env().await?;
            return Ok(());
        }
        "sail-gateway" => return gateway::run().await,
        "sail-socket" => return gateway::socket().await,
        "token-broker" => anyhow::bail!("token-broker is not implemented; refusing startup"),
        "serve" => (),
        _ => anyhow::bail!(
            "supported roles: serve, migrate, policy, sail-gateway, sail-socket; token-broker is unsupported"
        ),
    }
    let admin = std::fs::read_to_string(std::env::var("AUTHZ_KEY_FILE")?)?
        .trim()
        .to_owned();
    anyhow::ensure!(admin.len() >= 32, "service credential too short");
    // The Sail gateway gets a separate decision-only credential. Without one,
    // /sail/groups rejects every request.
    let key = std::env::var("AUTHZ_DECISION_KEY_FILE")
        .ok()
        .map(std::fs::read_to_string)
        .transpose()?
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();
    anyhow::ensure!(
        key.is_empty() || (key.len() >= 32 && key != admin),
        "the gateway decision credential must be at least 32 characters and differ from AUTHZ_KEY_FILE"
    );
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        std::env::var("AUTHZ_TLS_CERT")?,
        std::env::var("AUTHZ_TLS_KEY")?,
    )
    .await?;
    let live = {
        let url = std::env::var("AUTHZ_RAUTHY_USERS_URL")?;
        anyhow::ensure!(url.starts_with("https://"), "Rauthy must use HTTPS");
        let ca = reqwest::Certificate::from_pem(&std::fs::read(std::env::var(
            "AUTHZ_RAUTHY_CA_FILE",
        )?)?)?;
        Live {
            client: reqwest::Client::builder()
                .https_only(true)
                .use_rustls_tls()
                .tls_built_in_root_certs(false)
                .add_root_certificate(ca)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()?,
            url,
            key: std::fs::read_to_string(std::env::var("AUTHZ_RAUTHY_KEY_FILE")?)?
                .trim()
                .into(),
            cache: Default::default(),
            machines: std::env::var("AUTHZ_MACHINE_PRINCIPALS")
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
            limit: Arc::new(tokio::sync::Semaphore::new(16)),
        }
    };
    let trino_key = std::env::var("AUTHZ_TRINO_KEY_FILE")
        .ok()
        .map(std::fs::read_to_string)
        .transpose()?
        .map(|s| s.trim().to_owned());
    if let Some(ref trino_key) = trino_key {
        anyhow::ensure!(
            trino_key.len() >= 32 && trino_key != &admin && trino_key != &key,
            "Trino needs a separate decision-only credential of at least 32 characters"
        );
    }
    ADMIN_KEY
        .set(admin)
        .map_err(|_| anyhow::anyhow!("credential initialised twice"))?;
    let app = App {
        trino_key,
        key,
        live,
        db: Database::from_env().await?,
    };
    let router = Router::new()
        .route("/decide", post(decide))
        .route("/sail/groups", post(sail_groups))
        .route("/opa/{endpoint}", post(opa::handle))
        .route("/permissions", post(permissions))
        .route("/mutate", post(mutate))
        .route("/snapshot", post(snapshot))
        .with_state(app);
    axum_server::bind_rustls(
        std::env::var("AUTHZ_LISTEN")
            .unwrap_or("0.0.0.0:8443".into())
            .parse::<std::net::SocketAddr>()?,
        tls,
    )
    .serve(router.into_make_service())
    .await?;
    Ok(())
}
#[cfg(test)]
mod adversarial;
#[cfg(test)]
mod fixes_4c {
    use super::*;
    use axum::extract::State as S;
    fn headers(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", value.parse().unwrap());
        h
    }
    fn app(decision: &str) -> App {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        App {
            key: decision.into(),
            trino_key: Some("t".repeat(40)),
            live: Live {
                client: reqwest::Client::new(),
                url: format!("http://127.0.0.1:{port}/auth/v1/users"),
                key: "r".into(),
                cache: Default::default(),
                machines: vec![],
                limit: Arc::new(tokio::sync::Semaphore::new(1)),
            },
            db: Database(
                sqlx_postgres::PgPoolOptions::new()
                    .acquire_timeout(Duration::from_millis(300))
                    .connect_lazy_with(
                        sqlx_postgres::PgConnectOptions::new()
                            .host("127.0.0.1")
                            .port(port),
                    ),
            ),
        }
    }
    const ADMIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    #[tokio::test]
    async fn f3_admin_and_gateway_credentials_are_separate() {
        let admin = ADMIN_KEY.get_or_init(|| ADMIN.into()).clone();
        let gateway = "g".repeat(40);
        let a_app = self::app(&gateway);
        let g = headers(&format!("Bearer {gateway}"));
        let a = headers(&format!("Bearer {admin}"));
        let m = || Mutation::SetRegion {
            principal: "oidc~x".into(),
            region: "eu".into(),
        };
        assert_eq!(
            mutate(S(a_app.clone()), g.clone(), Json(m())).await.err(),
            Some(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(
            snapshot(S(a_app.clone()), g.clone()).await.err(),
            Some(StatusCode::UNAUTHORIZED)
        );
        let request: PermissionRequest = serde_json::from_value(serde_json::json!({
            "check":{"principal":"oidc~x","groups":[],"action":"manage_grants","resource":{"kind":"Table","id":"t"}},"grant":null}))
        .unwrap();
        assert_eq!(
            permissions(S(a_app.clone()), g.clone(), Json(request))
                .await
                .err(),
            Some(StatusCode::UNAUTHORIZED)
        );
        // The admin key is not the gateway's credential, and vice versa.
        assert_eq!(
            sail_groups(S(a_app.clone()), a.clone(), Json("oidc~x".into()))
                .await
                .err(),
            Some(StatusCode::UNAUTHORIZED)
        );
        assert_ne!(
            sail_groups(S(a_app.clone()), g.clone(), Json("oidc~x".into()))
                .await
                .err(),
            Some(StatusCode::UNAUTHORIZED)
        );
        assert_ne!(
            snapshot(S(a_app.clone()), a.clone()).await.err(),
            Some(StatusCode::UNAUTHORIZED)
        );
        // Both credentials pass /decide authentication (the unreachable test
        // database then answers 503).
        for h in [g, a.clone()] {
            assert_ne!(
                decide(S(a_app.clone()), h, Json(vec![])).await.err(),
                Some(StatusCode::UNAUTHORIZED)
            );
        }
        // An absent gateway credential never matches anything.
        let none = self::app("");
        assert_eq!(
            sail_groups(S(none), headers("Bearer "), Json("oidc~x".into()))
                .await
                .err(),
            Some(StatusCode::UNAUTHORIZED)
        );
        // F1: malformed identifiers are a 400 before any database access.
        let bad = Mutation::Grant {
            grant: authz_core::Grant {
                subject: authz_core::Resource::new("User", "x\u{1}y"),
                resource: authz_core::Resource::new("Table", "t"),
                access: "select".into(),
            },
            remove: false,
        };
        assert_eq!(
            mutate(S(a_app), a, Json(bad)).await.err(),
            Some(StatusCode::BAD_REQUEST)
        );
    }
    #[test]
    fn o2_secret_comparison_is_exact_and_length_checked() {
        assert!(same_secret(b"abc", b"abc"));
        for bad in [&b"abd"[..], b"ab", b"abcd", b"", b"ABC"] {
            assert!(!same_secret(bad, b"abc"));
        }
        assert!(
            !same_secret(b"", b""),
            "an empty configured key never matches"
        );
        assert!(bearer_matches(&headers("Bearer abc"), "abc"));
        assert!(!bearer_matches(&headers("bearer abc"), "abc"));
        assert!(!bearer_matches(&headers("Bearer abc "), "abc"));
    }
    #[test]
    fn f6_only_plain_subjects_reach_the_identity_provider() {
        for good in [
            "alice",
            "8RpxQRYzVHbmX6Zs7jCi",
            "sail-team-a",
            "a.b",
            "a_b@c+d",
        ] {
            assert!(valid_subject(good), "{good}");
        }
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "a?b",
            "a#b",
            "a%2Fb",
            "a b",
            "a\nb",
            "a\u{0}",
            "\u{e9}",
            &"a".repeat(257),
        ] {
            assert!(!valid_subject(bad), "{bad:?}");
        }
    }
    #[test]
    fn o5_unknown_principals_are_not_reported_as_idp_outages() {
        assert_eq!(membership_reason::<()>(&Ok(())), None);
        assert_eq!(
            membership_reason::<()>(&Err(StatusCode::FORBIDDEN)),
            Some("unknown_principal")
        );
        assert_eq!(
            membership_reason::<()>(&Err(StatusCode::SERVICE_UNAVAILABLE)),
            Some("identity_provider_unavailable")
        );
    }
}
