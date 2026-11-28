use authz_core::{Check, Mutation, Store, Verdict};
use sqlx_core::{
    query::query, query_as::query_as, raw_sql::raw_sql, transaction::Transaction, types::Json,
};
use sqlx_postgres::{PgConnectOptions, PgPool, PgPoolOptions, PgSslMode, Postgres};
use std::{str::FromStr, time::Duration};

#[derive(Clone)]
pub struct Database(pub PgPool);
impl Database {
    /// Runtime connection (serve, sail-gateway). Never runs DDL; refuses a login
    /// that owns or could rewrite the append-only audit (see `migrate_from_env`).
    pub async fn from_env() -> anyhow::Result<Self> {
        let db = Self::connect().await?;
        db.verify_runtime_privileges().await?;
        Ok(db)
    }
    /// Separate administrative step, run with the schema-owner login. Applies the
    /// migrations, then grants the runtime role exactly what it needs and fails
    /// closed unless the resulting privileges are least-privilege.
    pub async fn migrate_from_env() -> anyhow::Result<()> {
        let role = runtime_role(std::env::var("AUTHZ_RUNTIME_ROLE").ok())?;
        let db = Self::connect().await?;
        db.migrate().await?;
        db.grant_runtime(&role).await
    }
    async fn connect() -> anyhow::Result<Self> {
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
        Ok(db)
    }
    async fn grant_runtime(&self, role: &str) -> anyhow::Result<()> {
        let (owner,): (String,) = query_as("SELECT current_user::text")
            .fetch_one(&self.0)
            .await?;
        anyhow::ensure!(
            owner != role,
            "the runtime role must differ from the migration login"
        );
        let role = runtime_role(Some(role.to_owned()))?;
        let quoted = format!("\"{role}\"");
        let mut tx = self.0.begin().await?;
        for statement in [
            format!("REVOKE ALL ON authz_audit, authz_state FROM {quoted}"),
            format!("GRANT SELECT, INSERT ON authz_audit TO {quoted}"),
            format!("GRANT SELECT, UPDATE ON authz_state TO {quoted}"),
            format!("REVOKE CREATE ON SCHEMA public FROM PUBLIC, {quoted}"),
        ] {
            // Role name is validated by `runtime_role` ([a-z_][a-z0-9_]*) and quoted.
            raw_sql(sqlx_core::sql_str::AssertSqlSafe(statement))
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        let problems = privilege_problems(&self.0, Some(&role)).await?;
        anyhow::ensure!(
            problems.is_empty(),
            "runtime role {role} is not least-privilege after migration: {problems:?}"
        );
        Ok(())
    }
    async fn verify_runtime_privileges(&self) -> anyhow::Result<()> {
        let problems = privilege_problems(&self.0, None).await?;
        anyhow::ensure!(
            problems.is_empty(),
            "refusing to start: the runtime database login must not own or rewrite the audit; run `migrate` with the owner login and AUTHZ_RUNTIME_ROLE ({problems:?})"
        );
        Ok(())
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

/// Runtime role names are plain SQL identifiers; anything else is refused.
pub fn runtime_role(value: Option<String>) -> anyhow::Result<String> {
    let role = value.unwrap_or_default();
    anyhow::ensure!(
        !role.is_empty()
            && role.len() <= 63
            && role
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            && !role.as_bytes()[0].is_ascii_digit(),
        "AUTHZ_RUNTIME_ROLE must name the separate runtime login ([a-z_][a-z0-9_]*)"
    );
    Ok(role)
}

/// Every reason a role (default: the current login) is not a least-privilege
/// runtime login. Empty means: tables exist, it can read/append audit and
/// read/update state, and it cannot own, alter, rewrite or erase them.
async fn privilege_problems(pool: &PgPool, role: Option<&str>) -> anyhow::Result<Vec<String>> {
    let (role,): (String,) = match role {
        Some(r) => (r.to_owned(),),
        None => {
            query_as("SELECT current_user::text")
                .fetch_one(pool)
                .await?
        }
    };
    let (exist,): (bool,) = query_as(
        "SELECT to_regclass('authz_audit') IS NOT NULL AND to_regclass('authz_state') IS NOT NULL",
    )
    .fetch_one(pool)
    .await?;
    if !exist {
        return Ok(vec!["schema missing: run migrate first".into()]);
    }
    let rows: Vec<(String, bool)> = query_as(
        "SELECT c.label, c.bad FROM (VALUES
            ('superuser', (SELECT rolsuper OR rolbypassrls OR rolcreaterole FROM pg_roles WHERE rolname = $1)),
            ('owns authz_audit', pg_has_role($1, (SELECT tableowner FROM pg_tables WHERE tablename = 'authz_audit' AND schemaname = current_schema()), 'USAGE')),
            ('owns authz_state', pg_has_role($1, (SELECT tableowner FROM pg_tables WHERE tablename = 'authz_state' AND schemaname = current_schema()), 'USAGE')),
            ('audit UPDATE', has_table_privilege($1, 'authz_audit', 'UPDATE')),
            ('audit DELETE', has_table_privilege($1, 'authz_audit', 'DELETE')),
            ('audit TRUNCATE', has_table_privilege($1, 'authz_audit', 'TRUNCATE')),
            ('audit TRIGGER', has_table_privilege($1, 'authz_audit', 'TRIGGER')),
            ('audit REFERENCES', has_table_privilege($1, 'authz_audit', 'REFERENCES')),
            ('state DELETE', has_table_privilege($1, 'authz_state', 'DELETE')),
            ('state TRUNCATE', has_table_privilege($1, 'authz_state', 'TRUNCATE')),
            ('state TRIGGER', has_table_privilege($1, 'authz_state', 'TRIGGER')),
            ('schema CREATE', has_schema_privilege($1, current_schema(), 'CREATE')),
            ('missing audit INSERT', NOT has_table_privilege($1, 'authz_audit', 'INSERT')),
            ('missing audit SELECT', NOT has_table_privilege($1, 'authz_audit', 'SELECT')),
            ('missing state SELECT', NOT has_table_privilege($1, 'authz_state', 'SELECT')),
            ('missing state UPDATE', NOT has_table_privilege($1, 'authz_state', 'UPDATE'))
        ) AS c(label, bad)",
    )
    .bind(&role)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter(|(_, bad)| *bad)
        .map(|(label, _)| label)
        .collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn runtime_role_names_are_plain_identifiers() {
        for good in ["authz_runtime", "r1", "_x"] {
            assert_eq!(super::runtime_role(Some(good.into())).unwrap(), good);
        }
        for bad in ["", "Authz", "1r", "a\"b", "a;drop", "a b", &"r".repeat(64)] {
            assert!(super::runtime_role(Some(bad.into())).is_err(), "{bad:?}");
        }
        assert!(super::runtime_role(None).is_err());
    }
}
