//! Thin composition against unmodified pinned upstream crates; no upstream binary copy.
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
    if std::env::args().nth(1).as_deref() == Some("version") {
        println!(
            "datopsis Lakekeeper adapter spike {} / Lakekeeper 0.13.4 source 9bd377162345b64a716f0a4fcffe4e7e7f3c7534",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
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
    macro_rules! start {
        ($auth:expr) => {
            serve(
                ServeConfiguration::<PostgresBackend, _, _, _>::builder()
                    .bind_addr(bind)
                    .secrets_state(secrets)
                    .catalog_state(state)
                    .authorizer(authorizer)
                    .authenticator(Some($auth))
                    .build(),
            )
            .await
        };
    }
    match get_default_authenticator_from_config().await? {
        Some(BuiltInAuthenticators::Single(a)) => start!(a),
        Some(BuiltInAuthenticators::Chain(a)) => start!(a),
        None => anyhow::bail!("S1 requires OIDC authentication"),
    }
}
