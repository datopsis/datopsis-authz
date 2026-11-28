//! Slice 4c adversarial review of the Trino OPA wire adapter. Each test asserts
//! the REQUIRED secure behaviour of the real `evaluate` function.
//! Run with: cargo test -p authz-serve -- --ignored adversarial
use super::*;
use authz_core::{Grant, Mutation};

fn eval(store: &Store, query: &Value, endpoint: &str) -> Result<Value> {
    let query: Query = serde_json::from_value(query.clone()).unwrap();
    evaluate(
        &Evaluation {
            store,
            audits: RefCell::new(vec![]),
        },
        &query,
        endpoint,
    )
}
fn grant(store: &mut Store, user: &str, table: &str, access: &str) {
    store
        .mutate(Mutation::Grant {
            grant: Grant {
                subject: Resource::new("User", user),
                resource: Resource::new("Table", table),
                access: access.into(),
            },
            remove: false,
        })
        .unwrap();
}
fn bind(
    store: &mut Store,
    name: [&str; 3],
    id: &str,
    region: Option<&str>,
    sensitive: Option<&str>,
) {
    store
        .mutate(Mutation::Put {
            resource: Resource::new("Table", id),
            parent: None,
            owner: None,
        })
        .unwrap();
    store
        .mutate(Mutation::BindTrino {
            name: name.iter().map(|s| s.to_string()).collect(),
            binding: TrinoBinding {
                resource: Resource::new("Table", id),
                region_column: region.map(Into::into),
                sensitive_column: sensitive.map(Into::into),
            },
        })
        .unwrap();
}
/// alice reads iceberg.team_a.orders; bob reads iceberg.team_b.payroll.
fn store() -> Store {
    let mut s = Store::default();
    bind(
        &mut s,
        ["iceberg", "team_a", "orders"],
        "uuid-a",
        Some("region"),
        Some("email"),
    );
    bind(
        &mut s,
        ["iceberg", "team_b", "payroll"],
        "uuid-b",
        None,
        Some("salary"),
    );
    grant(&mut s, "oidc~alice", "uuid-a", "select");
    grant(&mut s, "oidc~bob", "uuid-b", "select");
    s.regions.insert("oidc~alice".into(), "eu".into());
    s
}
fn table(schema: &str, name: &str) -> Value {
    json!({"table":{"catalogName":"iceberg","schemaName":schema,"tableName":name,"columns":["id"]}})
}
fn column(schema: &str, name: &str, column: &str) -> Value {
    json!({"column":{"catalogName":"iceberg","schemaName":schema,"tableName":name,"columnName":column,"columnType":"varchar"}})
}
fn query(
    user: &str,
    operation: &str,
    resource: Option<Value>,
    filter: Option<Vec<Value>>,
) -> Value {
    json!({"input":{"context":{"identity":{"user":user,"groups":[]},"properties":{}},
        "action":{"operation":operation,"resource":resource,"filterResources":filter}}})
}
fn allow(s: &Store, user: &str, op: &str, resource: Value) -> bool {
    match eval(s, &query(user, op, Some(resource), None), "allow") {
        Ok(v) => v == json!({"result":true}),
        Err(_) => false,
    }
}

#[test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
fn adversarial_trino_cross_team_tables_schemas_and_catalog_metadata_deny() {
    let s = store();
    assert!(allow(
        &s,
        "oidc~alice",
        "SelectFromColumns",
        table("team_a", "orders")
    ));
    for op in [
        "SelectFromColumns",
        "ShowColumns",
        "FilterColumns",
        "FilterTables",
        "ShowTables",
    ] {
        assert!(
            !allow(&s, "oidc~alice", op, table("team_b", "payroll")),
            "{op} leaked team B"
        );
    }
    let schema = json!({"schema":{"catalogName":"iceberg","schemaName":"team_b"}});
    for op in ["ShowSchemas", "FilterSchemas", "ShowTables"] {
        assert!(
            !allow(&s, "oidc~alice", op, schema.clone()),
            "{op} leaked team B schema"
        );
    }
    // A principal without any readable binding cannot see the catalog at all.
    let catalog = json!({"catalog":{"name":"iceberg"}});
    for op in ["AccessCatalog", "FilterCatalogs", "ShowSchemas"] {
        assert!(!allow(&s, "oidc~mallory", op, catalog.clone()));
    }
    for other in ["system", "Iceberg", "iceberg ", "jmx", "tpch"] {
        assert!(
            !allow(
                &s,
                "oidc~alice",
                "AccessCatalog",
                json!({"catalog":{"name":other}})
            ),
            "{other}"
        );
    }
    let q = query("oidc~mallory", "ExecuteQuery", None, None);
    assert_eq!(eval(&s, &q, "allow").unwrap(), json!({"result":false}));
    // Batch filtering returns only the caller's own tables.
    let batch = query(
        "oidc~alice",
        "FilterTables",
        None,
        Some(vec![
            table("team_b", "payroll"),
            table("team_a", "orders"),
            table("team_a", "missing"),
        ]),
    );
    assert_eq!(eval(&s, &batch, "batch").unwrap(), json!({"result":[1]}));
}

#[test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
fn adversarial_trino_name_tricks_do_not_alias_bindings() {
    let mut s = store();
    bind(&mut s, ["iceberg", "a.b", "c"], "uuid-dots", None, None);
    grant(&mut s, "oidc~alice", "uuid-dots", "select");
    assert!(allow(
        &s,
        "oidc~alice",
        "SelectFromColumns",
        table("a.b", "c")
    ));
    for (schema, name) in [
        ("team_b", "PAYROLL"),
        ("TEAM_B", "payroll"),
        ("team_b", "payroll "),
        ("team_b", "pay\u{0440}oll"),
        ("team_b\"", "payroll"),
        ("team_a", "orders\0"),
        ("a", "b.c"),
        ("a.b.c", ""),
        ("team_b", "payroll$files"),
        ("team_b", "payroll$snapshots"),
    ] {
        assert!(
            !allow(&s, "oidc~alice", "SelectFromColumns", table(schema, name)),
            "{schema}.{name} aliased a binding"
        );
    }
    // Iceberg hidden metadata tables expose file paths and column bounds
    // (including masked/filtered columns); they must stay unbound and denied
    // even for a principal who may read the base table.
    for suffix in [
        "$files",
        "$snapshots",
        "$manifests",
        "$partitions",
        "$history",
        "$properties",
        "$refs",
        "$all_manifests",
        "$entries",
    ] {
        assert!(
            !allow(
                &s,
                "oidc~alice",
                "SelectFromColumns",
                table("team_a", &format!("orders{suffix}"))
            ),
            "orders{suffix} readable"
        );
    }
}

#[test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
fn adversarial_trino_writes_ddl_impersonation_and_admin_operations_deny_even_for_owner() {
    let mut s = store();
    grant(&mut s, "oidc~alice", "uuid-a", "owner");
    let resource = table("team_a", "orders");
    for op in [
        "InsertIntoTable",
        "DeleteFromTable",
        "TruncateTable",
        "UpdateTableColumns",
        "DropTable",
        "RenameTable",
        "CreateTable",
        "SetTableProperties",
        "SetTableComment",
        "SetColumnComment",
        "AddColumn",
        "DropColumn",
        "RenameColumn",
        "AlterColumn",
        "SetTableAuthorization",
        "CreateView",
        "CreateViewWithSelectFromColumns",
        "CreateMaterializedView",
        "RefreshMaterializedView",
        "DropView",
        "CreateSchema",
        "DropSchema",
        "RenameSchema",
        "SetSchemaAuthorization",
        "ShowCreateTable",
        "ShowCreateSchema",
        "ImpersonateUser",
        "SetSystemSessionProperty",
        "SetCatalogSessionProperty",
        "ExecuteProcedure",
        "ExecuteTableProcedure",
        "ExecuteFunction",
        "CreateFunction",
        "DropFunction",
        "KillQueryOwnedBy",
        "ViewQueryOwnedBy",
        "FilterViewQueryOwnedBy",
        "GrantTablePrivilege",
        "DenyTablePrivilege",
        "RevokeTablePrivilege",
        "CreateRole",
        "DropRole",
        "GrantRoles",
        "ReadSystemInformation",
        "WriteSystemInformation",
        "CreateCatalog",
        "DropCatalog",
        "ShowRoles",
        "ShowCurrentRoles",
        "ShowRoleGrants",
        "ShowFunctions",
    ] {
        assert!(
            !allow(&s, "oidc~alice", op, resource.clone()),
            "{op} allowed for table owner"
        );
    }
    let user = json!({"user":{"user":"oidc~bob"}});
    assert!(
        !allow(&s, "oidc~alice", "ImpersonateUser", user),
        "impersonation allowed"
    );
}

#[test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
fn adversarial_trino_row_filter_template_cannot_be_injected() {
    let mut s = Store::default();
    bind(
        &mut s,
        ["iceberg", "ns", "t"],
        "uuid",
        Some("re\"gion\" OR 1=1 --"),
        None,
    );
    grant(&mut s, "oidc~alice", "uuid", "select");
    for (region, literal) in [
        ("eu' OR '1'='1", "'eu'' OR ''1''=''1'"),
        ("eu'; DROP TABLE x; --", "'eu''; DROP TABLE x; --'"),
        ("\\'", "'\\'''"),
        ("", "''"),
        ("e\nu", "'e\nu'"),
    ] {
        s.regions.insert("oidc~alice".into(), region.into());
        let q = query("oidc~alice", "GetRowFilters", Some(table("ns", "t")), None);
        let expected = format!("\"re\"\"gion\"\" OR 1=1 --\" = {literal}");
        assert_eq!(
            eval(&s, &q, "rows").unwrap(),
            json!({"result":[{"expression":expected}]}),
            "{region:?}"
        );
    }
    // The region attribute is keyed by the exact principal, not a look-alike.
    s.regions.clear();
    s.regions.insert("oidc~ALICE".into(), "us".into());
    let q = query("oidc~alice", "GetRowFilters", Some(table("ns", "t")), None);
    assert_eq!(eval(&s, &q, "rows").unwrap_err(), StatusCode::FORBIDDEN);
}

#[test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
fn adversarial_trino_mask_applies_regardless_of_column_name_case() {
    // Trino's SPI presents column names in lower case. A binding provisioned
    // from catalog metadata may keep the Iceberg schema's original spelling.
    // A sensitive column must be masked either way (or the binding refused):
    // a case mismatch must never silently unmask it.
    let mut s = Store::default();
    let accepted = s
        .mutate(Mutation::Put {
            resource: Resource::new("Table", "uuid"),
            parent: None,
            owner: None,
        })
        .and_then(|_| {
            s.mutate(Mutation::BindTrino {
                name: vec!["iceberg".into(), "ns".into(), "people".into()],
                binding: TrinoBinding {
                    resource: Resource::new("Table", "uuid"),
                    region_column: None,
                    sensitive_column: Some("Email".into()),
                },
            })
        })
        .is_ok();
    if !accepted {
        return; // Refusing a non-canonical column binding is also secure.
    }
    grant(&mut s, "oidc~alice", "uuid", "select");
    let q = query(
        "oidc~alice",
        "GetColumnMask",
        Some(column("ns", "people", "email")),
        None,
    );
    assert_eq!(
        eval(&s, &q, "mask").unwrap(),
        json!({"result":{"expression":"NULL"}}),
        "sensitive column 'Email' served unmasked as 'email'"
    );
    let q = query(
        "oidc~alice",
        "GetColumnMask",
        None,
        Some(vec![column("ns", "people", "email")]),
    );
    assert_eq!(
        eval(&s, &q, "batch_masks").unwrap(),
        json!({"result":[{"index":0,"viewExpression":{"expression":"NULL"}}]}),
        "batch mask skipped the sensitive column"
    );
}

#[test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
fn adversarial_trino_obligations_fail_closed_for_unknown_or_unreadable() {
    let s = store();
    // Another team's table: FALSE row filter and NULL masks, then a SELECT denial.
    let q = query(
        "oidc~alice",
        "GetRowFilters",
        Some(table("team_b", "payroll")),
        None,
    );
    assert_eq!(
        eval(&s, &q, "rows").unwrap(),
        json!({"result":[{"expression":"FALSE"}]})
    );
    for col in ["salary", "id", "SALARY"] {
        let q = query(
            "oidc~alice",
            "GetColumnMask",
            Some(column("team_b", "payroll", col)),
            None,
        );
        assert_eq!(
            eval(&s, &q, "mask").unwrap(),
            json!({"result":{"expression":"NULL"}}),
            "{col}"
        );
    }
    // Wrong operation on an obligation endpoint is a request error, never a pass.
    for (endpoint, op) in [
        ("rows", "SelectFromColumns"),
        ("mask", "GetRowFilters"),
        ("batch_masks", "FilterColumns"),
    ] {
        let q = query(
            "oidc~alice",
            op,
            Some(column("team_a", "orders", "email")),
            Some(vec![]),
        );
        assert!(eval(&s, &q, endpoint).is_err(), "{endpoint}/{op}");
    }
    assert_eq!(
        eval(
            &s,
            &query(
                "oidc~alice",
                "SelectFromColumns",
                Some(table("team_a", "orders")),
                None
            ),
            "unknown"
        )
        .unwrap_err(),
        StatusCode::NOT_FOUND
    );
    // Missing name parts are a request error, not an unbound-allow.
    let partial = json!({"table":{"catalogName":"iceberg","schemaName":"team_a"}});
    assert!(
        eval(
            &s,
            &query("oidc~alice", "SelectFromColumns", Some(partial), None),
            "allow"
        )
        .is_err()
    );
    // A batch FilterColumns over two tables is refused rather than merged.
    let q = query(
        "oidc~alice",
        "FilterColumns",
        None,
        Some(vec![table("team_a", "orders"), table("team_b", "payroll")]),
    );
    assert!(eval(&s, &q, "batch").is_err());
}
