use authz_core::{Check, Mutation, Store, Verdict};
use sqlx_core::{
    query::query, query_as::query_as, raw_sql::raw_sql, transaction::Transaction, types::Json,
};
use sqlx_postgres::{PgConnectOptions, PgPool, PgPoolOptions, PgSslMode, Postgres};
use std::{str::FromStr, time::Duration};

#[derive(Clone)]
pub struct Database(pub PgPool);
impl Database {
    pub async fn from_env() -> anyhow::Result<Self> {
        // Explicitly override URL options: callers cannot downgrade verification.
        let options = PgConnectOptions::from_str(&std::fs::read_to_string(std::env::var(
            "AUTHZ_DATABASE_URL_FILE",
        )?)?)?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("AUTHZ_DATABASE_CA_FILE")?);
        let db = Self(
            PgPoolOptions::new()
                .max_connections(8)
                .acquire_timeout(Duration::from_secs(2))
                .connect_with(options)
                .await?,
        );
        db.migrate().await?;
        Ok(db)
    }
    pub async fn migrate(&self) -> anyhow::Result<()> {
        let mut tx = self.0.begin().await?;
        raw_sql(include_str!("../../../migrations/0001_catalog.sql"))
            .execute(&mut *tx)
            .await?;
        raw_sql(include_str!("../../../migrations/0002_trino.sql"))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn snapshot(&self) -> anyhow::Result<Store> {
        let (Json(store),): (Json<Store>,) =
            query_as("SELECT graph FROM authz_state WHERE singleton")
                .fetch_one(&self.0)
                .await?;
        Ok(store)
    }
    pub async fn locked(&self) -> anyhow::Result<(Transaction<'_, Postgres>, Store)> {
        let mut tx = self.0.begin().await?;
        query("SET LOCAL statement_timeout = '2s'")
            .execute(&mut *tx)
            .await?;
        let (Json(store),): (Json<Store>,) =
            query_as("SELECT graph FROM authz_state WHERE singleton FOR UPDATE")
                .fetch_one(&mut *tx)
                .await?;
        Ok((tx, store))
    }
    pub async fn mutate(&self, m: Mutation) -> anyhow::Result<()> {
        let (mut tx, mut store) = self.locked().await?;
        store.mutate(m)?;
        Self::save(&mut tx, &store).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn save(tx: &mut Transaction<'_, Postgres>, store: &Store) -> anyhow::Result<()> {
        query("UPDATE authz_state SET graph=$1 WHERE singleton")
            .bind(Json(store))
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
    pub async fn audit(
        tx: &mut Transaction<'_, Postgres>,
        check: &Check,
        verdict: &Verdict,
        reason: &str,
    ) -> anyhow::Result<()> {
        Self::audit_result(tx, check, verdict, reason, None).await
    }
    pub async fn audit_result(
        tx: &mut Transaction<'_, Postgres>,
        check: &Check,
        verdict: &Verdict,
        reason: &str,
        result: Option<&serde_json::Value>,
    ) -> anyhow::Result<()> {
        query("INSERT INTO authz_audit(principal,action,resource,decision,policy_ids,reason,result) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(&check.principal).bind(&check.action).bind(Json(&check.resource))
            .bind(verdict.allowed).bind(Json(&verdict.policies)).bind(reason).bind(result.map(Json))
            .execute(&mut **tx).await?;
        Ok(())
    }
}
