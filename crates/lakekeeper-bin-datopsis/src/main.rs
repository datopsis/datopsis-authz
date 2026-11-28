//! Thin composition against unmodified pinned upstream crates; no upstream binary copy.
mod tls;
use lakekeeper::{
    serve::{ServeConfiguration, serve},
    service::{
        CatalogStore,
        authn::{BuiltInAuthenticators, get_default_authenticator_from_config},
    },
};
use lakekeeper_authz::CedarAuthorizer;
use lakekeeper_storage_postgres::{
    CatalogState, PostgresBackend, SecretsState, config::CONFIG, get_writer_pool,
};
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    if std::env::args().nth(1).as_deref() == Some("version") {
        println!(
            "datopsis Lakekeeper adapter {} / Lakekeeper 0.13.9 source a8e013b30e99e5a184486fe166c3ffb3781a7c36",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    let role = std::env::args().nth(1).unwrap_or_default();
    anyhow::ensure!(
        role == "serve" || role == "migrate",
        "use serve, migrate or version"
    );
    let secret = std::env::var("LAKEKEEPER__PG_ENCRYPTION_KEY")?;
    anyhow::ensure!(
        secret.trim().len() >= 32 && secret != "This is unsafe, please set a proper key",
        "a private encryption key of at least 32 characters is required"
    );
    let transport = if role == "serve" {
        Some(tls::Transport::from_env().await?)
    } else {
        None
    };
    let pool = get_writer_pool(CONFIG.to_pool_opts()).await?;
    if std::env::args().nth(1).as_deref() == Some("migrate") {
        lakekeeper_storage_postgres::migrations::migrate_core_only(&pool).await?;
        return Ok(());
    }
    anyhow::ensure!(
        std::env::args().nth(1).as_deref() == Some("serve"),
        "use serve or migrate"
    );
    let state = CatalogState::from_pools(pool.clone(), pool.clone());
    let server_id = PostgresBackend::get_server_info(state.clone())
        .await?
        .server_id();
    let authorizer = CedarAuthorizer::from_env(server_id)?;
    let secrets = SecretsState::from_pools(pool.clone(), pool);
    let bind =
        std::net::SocketAddr::from((lakekeeper::CONFIG.bind_ip, lakekeeper::CONFIG.listen_port));
    let transport = transport.expect("serve transport prepared");
    macro_rules! start {
        ($auth:expr) => {
            tokio::select! {
                result = transport.run(bind) => result,
                result = serve(
                ServeConfiguration::<PostgresBackend, _, _, _>::builder()
                    .bind_addr(bind)
                    .secrets_state(secrets)
                    .catalog_state(state)
                    .authorizer(authorizer)
                    .authenticator(Some($auth))
                    .build(),
                ) => result,
            }
        };
    }
    match get_default_authenticator_from_config().await? {
        Some(BuiltInAuthenticators::Single(a)) => start!(a),
        Some(BuiltInAuthenticators::Chain(a)) => start!(a),
        None => anyhow::bail!("S1 requires OIDC authentication"),
    }
}
