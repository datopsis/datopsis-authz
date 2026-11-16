use authz_core::{Check, Mutation, Store, Verdict};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
#[derive(Clone, serde::Deserialize)]
struct Membership {
    principal: String,
    cache_ms: Option<u64>,
}
#[derive(Clone)]
struct Live {
    client: reqwest::Client,
    url: String,
    key: String,
    config: Arc<RwLock<BTreeMap<String, u64>>>,
    cache: Arc<RwLock<BTreeMap<String, (Instant, Vec<String>)>>>,
}
impl Live {
    async fn groups(&self, principal: &str) -> Result<Option<Vec<String>>, StatusCode> {
        let ttl = self
            .config
            .read()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .get(principal)
            .copied();
        let Some(ttl) = ttl else { return Ok(None) };
        if let Some((at, groups)) = self
            .cache
            .read()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .get(principal)
        {
            if at.elapsed() < Duration::from_millis(ttl) {
                return Ok(Some(groups.clone()));
            }
        }
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
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Some(vec![]));
        }
        let user: serde_json::Value = response
            .error_for_status()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .json()
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let groups: Vec<String> = match user.get("groups") {
            Some(serde_json::Value::Array(values)) => values
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or(StatusCode::SERVICE_UNAVAILABLE)
                })
                .collect::<Result<_, _>>()?,
            Some(serde_json::Value::Null) => vec![],
            _ => return Err(StatusCode::SERVICE_UNAVAILABLE),
        };
        self.cache
            .write()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .insert(principal.into(), (start, groups.clone()));
        println!(
            "{}",
            serde_json::json!({"membership_lookup_ms": start.elapsed().as_secs_f64()*1000.0})
        );
        Ok(Some(groups))
    }
}
async fn membership(
    State(app): State<App>,
    headers: HeaderMap,
    Json(m): Json<Membership>,
) -> Result<StatusCode, StatusCode> {
    authenticate(&app, &headers)?;
    let live = app.live.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let mut config = live
        .config
        .write()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if let Some(ttl) = m.cache_ms {
        config.insert(m.principal.clone(), ttl);
    } else {
        config.remove(&m.principal);
    }
    live.cache
        .write()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .remove(&m.principal);
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Clone)]
struct App {
    key: String,
    live: Option<Live>,
    store: Arc<RwLock<Store>>,
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
async fn decide(
    State(app): State<App>,
    headers: HeaderMap,
    Json(checks): Json<Vec<Check>>,
) -> Result<Json<Vec<Verdict>>, StatusCode> {
    authenticate(&app, &headers)?;
    let mut results = vec![];
    for mut check in checks {
        if let Some(live) = &app.live {
            if let Some(groups) = live.groups(&check.principal).await? {
                check.groups = groups;
            }
        }
        let store = app
            .store
            .read()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let verdict = store
            .decide(&check)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        // Sanitized decision audit: no JWTs or service credentials.
        println!(
            "{}",
            serde_json::json!({"principal":check.principal,"action":check.action,"resource":check.resource,"allowed":verdict.allowed,"policies":verdict.policies})
        );
        results.push(verdict);
    }
    Ok(Json(results))
}
async fn mutate(
    State(app): State<App>,
    headers: HeaderMap,
    Json(m): Json<Mutation>,
) -> Result<StatusCode, StatusCode> {
    authenticate(&app, &headers)?;
    app.store
        .write()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .mutate(m)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn snapshot(State(app): State<App>, headers: HeaderMap) -> Result<Json<Store>, StatusCode> {
    authenticate(&app, &headers)?;
    Ok(Json(
        app.store
            .read()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .clone(),
    ))
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let role = std::env::args().nth(1).unwrap_or_default();
    match role.as_str() {
        "policy" => {
            authz_core::validate_schema()?;
            return Ok(());
        }
        "serve" => (),
        _ => anyhow::bail!(
            "S1 supports serve and policy only; sail-gateway and token-broker are later spikes"
        ),
    }
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let key = std::fs::read_to_string(std::env::var("AUTHZ_KEY_FILE")?)?
        .trim()
        .to_owned();
    anyhow::ensure!(key.len() >= 32, "service credential too short");
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        std::env::var("AUTHZ_TLS_CERT")?,
        std::env::var("AUTHZ_TLS_KEY")?,
    )
    .await?;
    let live = if let Ok(url) = std::env::var("AUTHZ_RAUTHY_USERS_URL") {
        anyhow::ensure!(url.starts_with("https://"), "Rauthy must use HTTPS");
        let ca = reqwest::Certificate::from_pem(&std::fs::read(std::env::var(
            "AUTHZ_RAUTHY_CA_FILE",
        )?)?)?;
        Some(Live {
            client: reqwest::Client::builder()
                .https_only(true)
                .add_root_certificate(ca)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()?,
            url,
            key: std::fs::read_to_string(std::env::var("AUTHZ_RAUTHY_KEY_FILE")?)?
                .trim()
                .into(),
            config: Default::default(),
            cache: Default::default(),
        })
    } else {
        None
    };
    let app = App {
        key,
        live,
        store: Arc::new(RwLock::new(Store::default())),
    };
    let router = Router::new()
        .route("/decide", post(decide))
        .route("/membership", post(membership))
        .route("/mutate", post(mutate))
        .route("/snapshot", post(snapshot))
        .with_state(app);
    axum_server::bind_rustls(
        std::env::var("AUTHZ_LISTEN")
            .unwrap_or("0.0.0.0:8443".into())
            .parse()?,
        tls,
    )
    .serve(router.into_make_service())
    .await?;
    Ok(())
}
