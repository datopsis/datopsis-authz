//! Trino 484 wire adapter. Cedar decisions and bounded SQL obligation templates.
use crate::database::Database;
use authz_core::{Check, Resource, Store, TrinoBinding, Verdict};
use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::BTreeMap;

use crate::App;

#[derive(Deserialize)]
pub struct Query {
    input: Input,
}
#[derive(Deserialize)]
struct Input {
    context: Context,
    action: Action,
}
#[derive(Deserialize)]
struct Context {
    identity: Identity,
    #[serde(default)]
    properties: BTreeMap<String, String>,
}
#[derive(Deserialize)]
struct Identity {
    user: String,
    #[serde(default)]
    groups: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Action {
    operation: String,
    resource: Option<Value>,
    filter_resources: Option<Vec<Value>>,
}

struct Evaluation<'a> {
    store: &'a Store,
    audits: RefCell<Vec<(Check, Verdict)>>,
}
impl std::ops::Deref for Evaluation<'_> {
    type Target = Store;
    fn deref(&self) -> &Store {
        self.store
    }
}
impl Evaluation<'_> {
    fn decide(&self, check: &Check) -> anyhow::Result<Verdict> {
        let verdict = self.store.decide(check)?;
        self.audits
            .borrow_mut()
            .push((check.clone(), verdict.clone()));
        Ok(verdict)
    }
}
type Result<T> = std::result::Result<T, StatusCode>;
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name].as_str().ok_or(StatusCode::BAD_REQUEST)
}
fn binding<'a>(store: &'a Evaluation<'_>, resource: &Value) -> Result<&'a TrinoBinding> {
    let object = resource
        .get("table")
        .or_else(|| resource.get("column"))
        .ok_or(StatusCode::BAD_REQUEST)?;
    let name = [
        field(object, "catalogName")?,
        field(object, "schemaName")?,
        field(object, "tableName")?,
    ];
    store
        .trino
        .get(&serde_json::to_string(&name).unwrap())
        .ok_or(StatusCode::FORBIDDEN)
}
fn check(
    store: &Evaluation<'_>,
    identity: &Identity,
    binding: &TrinoBinding,
    operation: &str,
) -> Result<bool> {
    let verdict = store
        .decide(&Check {
            deny: false,
            principal: identity.user.clone(),
            groups: identity.groups.clone(),
            action: operation.into(),
            resource: binding.resource.clone(),
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(verdict.allowed)
}
fn metadata(resource: &Value) -> bool {
    let r = resource.get("table").or_else(|| resource.get("column"));
    r.is_some_and(|r| r["catalogName"] == "iceberg" && r["schemaName"] == "information_schema")
}
fn allowed(store: &Evaluation<'_>, input: &Input, resource: &Value) -> Result<bool> {
    let op = input.action.operation.as_str();
    if op == "ExecuteQuery" {
        for b in store.trino.values() {
            if check(store, &input.context.identity, b, "read_data")? {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    if ![
        "AccessCatalog",
        "FilterCatalogs",
        "ShowSchemas",
        "FilterSchemas",
        "ShowTables",
        "FilterTables",
        "ShowColumns",
        "FilterColumns",
        "SelectFromColumns",
    ]
    .contains(&op)
    {
        return Ok(false);
    }
    if resource.get("table").is_some() {
        // Trino's information_schema connector performs item-level filtering itself.
        if metadata(resource) {
            return Ok(true);
        }
        return match binding(store, resource) {
            Ok(b) => check(store, &input.context.identity, b, "read_data"),
            Err(StatusCode::FORBIDDEN) => Ok(false),
            Err(e) => Err(e),
        };
    }
    let (catalog, schema) = if let Some(s) = resource.get("schema") {
        (field(s, "catalogName")?, Some(field(s, "schemaName")?))
    } else if let Some(c) = resource.get("catalog") {
        (field(c, "name")?, None)
    } else {
        return Ok(false);
    };
    for (name, b) in &store.trino {
        let parts: [String; 3] =
            serde_json::from_str(name).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if parts[0] == catalog
            && schema.is_none_or(|s| s == parts[1])
            && check(store, &input.context.identity, b, "read_data")?
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn quote_identifier(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}
fn mask(store: &Evaluation<'_>, input: &Input, resource: &Value) -> Result<Value> {
    if metadata(resource) {
        return Ok(Value::Null);
    }
    let b = match binding(store, resource) {
        Ok(b) => b,
        Err(StatusCode::FORBIDDEN) => return Ok(json!({"expression":"NULL"})),
        Err(e) => return Err(e),
    };
    // Trino fetches masks before its final SELECT check. Restrict, then let that
    // boolean check produce the authorization denial rather than a backend error.
    if !check(store, &input.context.identity, b, "read_data")? {
        return Ok(json!({"expression":"NULL"}));
    }
    let column = field(&resource["column"], "columnName")?;
    if b.sensitive_column.as_deref() == Some(column)
        && !check(store, &input.context.identity, b, "unmask")?
    {
        // NULL is valid for every column type; no client-provided SQL is interpolated.
        Ok(json!({"expression":"NULL"}))
    } else {
        Ok(Value::Null)
    }
}
fn evaluate(store: &Evaluation<'_>, query: &Query, endpoint: &str) -> Result<Value> {
    let input = &query.input;
    let resource = input.action.resource.as_ref().unwrap_or(&Value::Null);
    let result = match endpoint {
        "allow" => json!(allowed(store, input, resource)?),
        "batch" => {
            let resources = input
                .action
                .filter_resources
                .as_ref()
                .ok_or(StatusCode::BAD_REQUEST)?;
            if input.action.operation == "FilterColumns" {
                // This endpoint returns COLUMN indexes within the sole table resource.
                if resources.len() != 1 {
                    return Err(StatusCode::BAD_REQUEST);
                }
                let columns = resources[0]["table"]["columns"]
                    .as_array()
                    .ok_or(StatusCode::BAD_REQUEST)?;
                if allowed(store, input, &resources[0])? {
                    json!((0..columns.len()).collect::<Vec<_>>())
                } else {
                    json!([])
                }
            } else {
                let mut indexes = vec![];
                for (i, r) in resources.iter().enumerate() {
                    if allowed(store, input, r)? {
                        indexes.push(i);
                    }
                }
                json!(indexes)
            }
        }
        "rows" => {
            if input.action.operation != "GetRowFilters" {
                return Err(StatusCode::BAD_REQUEST);
            }
            if metadata(resource) {
                return Ok(json!({"result":[]}));
            }
            let b = match binding(store, resource) {
                Ok(b) => b,
                Err(StatusCode::FORBIDDEN) => {
                    return Ok(json!({"result":[{"expression":"FALSE"}]}));
                }
                Err(e) => return Err(e),
            };
            if !check(store, &input.context.identity, b, "read_data")? {
                return Ok(json!({"result":[{"expression":"FALSE"}]}));
            }
            if let Some(column) = &b.region_column {
                if check(store, &input.context.identity, b, "unrestricted_rows")? {
                    json!([])
                } else {
                    let region = store
                        .regions
                        .get(&input.context.identity.user)
                        .ok_or(StatusCode::FORBIDDEN)?;
                    json!([{"expression":format!("{} = '{}'", quote_identifier(column), region.replace('\'', "''"))}])
                }
            } else {
                json!([])
            }
        }
        "mask" => {
            if input.action.operation != "GetColumnMask" {
                return Err(StatusCode::BAD_REQUEST);
            }
            mask(store, input, resource)?
        }
        "batch_masks" => {
            if input.action.operation != "GetColumnMask" {
                return Err(StatusCode::BAD_REQUEST);
            }
            let mut masks = vec![];
            for (i, r) in input
                .action
                .filter_resources
                .as_ref()
                .ok_or(StatusCode::BAD_REQUEST)?
                .iter()
                .enumerate()
            {
                let m = mask(store, input, r)?;
                if !m.is_null() {
                    masks.push(json!({"index":i,"viewExpression":m}));
                }
            }
            json!(masks)
        }
        _ => return Err(StatusCode::NOT_FOUND),
    };
    Ok(json!({"result":result}))
}
pub async fn handle(
    State(app): State<App>,
    axum::extract::Path(endpoint): axum::extract::Path<String>,
    Json(mut query): Json<Query>,
) -> Result<Json<Value>> {
    // A separate decision-only credential: it cannot call mutation/native APIs.
    // Never enable opa.log-requests, which exposes this protected property.
    if app
        .trino_key
        .as_ref()
        .is_none_or(|key| query.input.context.properties.get("serviceKey") != Some(key))
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let live = app.live.groups(&query.input.context.identity.user).await;
    query.input.context.identity.groups = live
        .as_ref()
        .ok()
        .and_then(Clone::clone)
        .unwrap_or_default();
    let (mut tx, store) = app.db.locked().await.map_err(crate::unavailable)?;
    let evaluation = Evaluation {
        store: &store,
        audits: RefCell::new(vec![]),
    };
    let result = if live.is_err() {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    } else {
        evaluate(&evaluation, &query, &endpoint)
    };
    let mut policies = vec![];
    for (check, verdict) in evaluation.audits.into_inner() {
        policies.extend(verdict.policies.clone());
        Database::audit(
            &mut tx,
            &check,
            &verdict,
            if verdict.allowed {
                "trino_cedar_permit"
            } else {
                "trino_cedar_deny"
            },
        )
        .await
        .map_err(crate::unavailable)?;
    }
    policies.sort();
    policies.dedup();
    let check = Check { deny: false, principal: query.input.context.identity.user.clone(),
        groups: vec![], action: format!("trino:{}:{}", endpoint, query.input.action.operation),
        resource: Resource::new("Table", serde_json::to_string(&json!({
            "resource":query.input.action.resource, "filterResources":query.input.action.filter_resources
        })).map_err(crate::unavailable)?) };
    let verdict = Verdict {
        allowed: result.as_ref().is_ok_and(|v| v["result"] != false),
        policies,
    };
    Database::audit_result(
        &mut tx,
        &check,
        &verdict,
        if live.is_err() {
            "identity_provider_unavailable"
        } else if result.is_err() {
            "trino_invalid_or_failed_request"
        } else {
            "trino_wire_result"
        },
        Some(
            &result
                .as_ref()
                .cloned()
                .unwrap_or_else(|status| json!({"error_status":status.as_u16()})),
        ),
    )
    .await
    .map_err(crate::unavailable)?;
    tx.commit().await.map_err(crate::unavailable)?;
    result.map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_core::{Grant, Mutation, Resource};

    fn evaluate(store: &Store, query: &Query, endpoint: &str) -> Result<Value> {
        super::evaluate(
            &Evaluation {
                store,
                audits: RefCell::new(vec![]),
            },
            query,
            endpoint,
        )
    }
    fn fixture() -> (Store, Query) {
        let mut store = Store::default();
        let table = Resource::new("Table", "uuid-one");
        store
            .mutate(Mutation::Put {
                resource: table.clone(),
                parent: None,
                owner: None,
            })
            .unwrap();
        store
            .mutate(Mutation::Grant {
                grant: Grant {
                    subject: Resource::new("User", "alice"),
                    resource: table.clone(),
                    access: "select".into(),
                },
                remove: false,
            })
            .unwrap();
        store
            .mutate(Mutation::BindTrino {
                name: vec!["iceberg".into(), "ns".into(), "one".into()],
                binding: TrinoBinding {
                    resource: table,
                    region_column: Some("re\"gion".into()),
                    sensitive_column: Some("secret".into()),
                },
            })
            .unwrap();
        store.regions.insert("alice".into(), "e'u".into());
        let query = serde_json::from_value(json!({"input":{
            "context":{"identity":{"user":"alice","groups":[]},"properties":{}},
            "action":{"operation":"SelectFromColumns","resource":{"table":{"catalogName":"iceberg","schemaName":"ns","tableName":"one","columns":["id","secret"]}}}
        }})).unwrap();
        (store, query)
    }
    #[test]
    fn same_cedar_grant_and_revoke_drive_both_apis() {
        let (mut store, query) = fixture();
        assert_eq!(
            evaluate(&store, &query, "allow").unwrap(),
            json!({"result":true})
        );
        store.grants.clear();
        assert_eq!(
            evaluate(&store, &query, "allow").unwrap(),
            json!({"result":false})
        );
    }
    #[test]
    fn unknown_operations_and_unbound_names_deny() {
        let (store, mut query) = fixture();
        query.input.action.operation = "DropTable".into();
        assert_eq!(
            evaluate(&store, &query, "allow").unwrap(),
            json!({"result":false})
        );
        query.input.action.operation = "SelectFromColumns".into();
        query.input.action.resource.as_mut().unwrap()["table"]["tableName"] = json!("sibling");
        assert_eq!(
            evaluate(&store, &query, "allow").unwrap(),
            json!({"result":false})
        );
    }
    #[test]
    fn row_template_quotes_trusted_attributes_and_requires_read() {
        let (mut store, mut query) = fixture();
        query.input.action.operation = "GetRowFilters".into();
        assert_eq!(
            evaluate(&store, &query, "rows").unwrap(),
            json!({"result":[{"expression":"\"re\"\"gion\" = 'e''u'"}]})
        );
        store.regions.clear();
        assert_eq!(
            evaluate(&store, &query, "rows").unwrap_err(),
            StatusCode::FORBIDDEN
        );
        store.grants.clear();
        assert_eq!(
            evaluate(&store, &query, "rows").unwrap(),
            json!({"result":[{"expression":"FALSE"}]})
        );
        query.input.action.resource.as_mut().unwrap()["table"]["tableName"] = json!("unbound");
        assert_eq!(
            evaluate(&store, &query, "rows").unwrap(),
            json!({"result":[{"expression":"FALSE"}]})
        );
    }
    #[test]
    fn batch_columns_indexes_and_mask_shapes() {
        let (mut store, mut query) = fixture();
        query.input.action.operation = "FilterColumns".into();
        query.input.action.filter_resources =
            Some(vec![query.input.action.resource.take().unwrap()]);
        assert_eq!(
            evaluate(&store, &query, "batch").unwrap(),
            json!({"result":[0,1]})
        );
        query.input.action.operation = "GetColumnMask".into();
        query.input.action.filter_resources = Some(vec![
            json!({"column":{"catalogName":"iceberg","schemaName":"ns","tableName":"one","columnName":"secret","columnType":"varchar"}}),
        ]);
        assert_eq!(
            evaluate(&store, &query, "batch_masks").unwrap(),
            json!({"result":[{"index":0,"viewExpression":{"expression":"NULL"}}]})
        );
        query.input.action.resource =
            Some(query.input.action.filter_resources.as_ref().unwrap()[0].clone());
        assert_eq!(
            evaluate(&store, &query, "mask").unwrap(),
            json!({"result":{"expression":"NULL"}})
        );
        let mut unmask = store.grants[0].clone();
        unmask.access = "unmask".into();
        store
            .mutate(Mutation::Grant {
                grant: unmask,
                remove: false,
            })
            .unwrap();
        assert_eq!(
            evaluate(&store, &query, "mask").unwrap(),
            json!({"result":null})
        );
        assert_eq!(
            evaluate(&store, &query, "batch_masks").unwrap(),
            json!({"result":[]})
        );
    }
}
