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
        let _permit = self.limit.acquire().await.map_err(unavailable)?;
        let subject = principal
            .strip_prefix("oidc~")
            .ok_or(StatusCode::FORBIDDEN)?;
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
fn authenticate(app: &App, headers: &HeaderMap) -> Result<(), StatusCode> {
    if headers.get("authorization").and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {}", app.key))
    {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
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
    authenticate(&app, &headers)?;
    let mut results = vec![];
    // Resolve membership before opening a database transaction.
    let mut resolved = vec![];
    for mut check in checks {
        let reason = match app.live.groups(&check.principal).await {
            Ok(Some(groups)) => {
                check.groups = groups;
                None
            }
            _ => {
                check.deny = true;
                Some("identity_provider_unavailable")
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
    authenticate(&app, &headers)?;
    app.db.mutate(m).await.map_err(unavailable)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn snapshot(State(app): State<App>, headers: HeaderMap) -> Result<Json<Store>, StatusCode> {
    authenticate(&app, &headers)?;
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
    authenticate(&app, &headers)?;
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
        } else if live.is_err() {
            "identity_provider_unavailable"
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
            Database::from_env().await?;
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
    let key = std::fs::read_to_string(std::env::var("AUTHZ_KEY_FILE")?)?
        .trim()
        .to_owned();
    anyhow::ensure!(key.len() >= 32, "service credential too short");
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
            trino_key.len() >= 32 && trino_key != &key,
            "Trino needs a separate decision-only credential of at least 32 characters"
        );
    }
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
