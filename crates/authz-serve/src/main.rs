mod gateway;

use authz_core::{Check, Mutation, Store, Verdict};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use std::sync::{Arc, RwLock};
#[derive(Clone)]
struct App {
    key: String,
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
    let store = app
        .store
        .read()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut results = vec![];
    for check in checks {
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
        "sail-gateway" => return gateway::run().await,
        "serve" => (),
        _ => anyhow::bail!(
            "supported roles: serve, sail-gateway, policy; token-broker is not implemented"
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
    let app = App {
        key,
        store: Arc::new(RwLock::new(Store::default())),
    };
    let router = Router::new()
        .route("/decide", post(decide))
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
