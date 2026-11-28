//! Cedar evaluation of a transactionally loaded relationship graph.
use anyhow::{Result, bail};
use cedar_policy::{
    Authorizer, Context, Decision, Entities, Policy, PolicyId, PolicySet, Request, Schema,
    ValidationMode, Validator,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Resource {
    pub kind: String,
    pub id: String,
}
impl Resource {
    pub fn new(kind: &str, id: impl ToString) -> Self {
        Self {
            kind: kind.into(),
            id: id.to_string(),
        }
    }
    pub fn uid(&self) -> Value {
        json!({"type": self.kind, "id": self.id})
    }
    pub fn key(&self) -> String {
        format!("{}:{}", self.kind, self.id)
    }
    fn cedar(&self) -> String {
        format!(
            "{}::{}",
            self.kind,
            serde_json::to_string(&self.id).unwrap()
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Check {
    #[serde(default)]
    pub deny: bool,
    pub principal: String,
    pub groups: Vec<String>,
    pub action: String,
    pub resource: Resource,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verdict {
    pub allowed: bool,
    pub policies: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Grant {
    pub subject: Resource,
    pub resource: Resource,
    pub access: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Store {
    pub parents: BTreeMap<String, (Resource, Option<Resource>)>,
    pub grants: Vec<Grant>,
    /// Durable SQL-name bindings and bounded obligations; trusted administration only.
    #[serde(default)]
    pub trino: BTreeMap<String, TrinoBinding>,
    #[serde(default)]
    pub regions: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrinoBinding {
    pub resource: Resource,
    pub region_column: Option<String>,
    pub sensitive_column: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Mutation {
    BindTrino {
        name: Vec<String>,
        binding: TrinoBinding,
    },
    SetRegion {
        principal: String,
        region: String,
    },
    Put {
        resource: Resource,
        parent: Option<Resource>,
        owner: Option<String>,
    },
    Delete {
        resource: Resource,
    },
    Grant {
        grant: Grant,
        remove: bool,
    },
}
impl Store {
    pub fn mutate(&mut self, mutation: Mutation) -> Result<()> {
        match mutation {
            Mutation::BindTrino { name, binding } => {
                anyhow::ensure!(
                    name.len() == 3
                        && name.iter().all(|s| !s.is_empty())
                        && binding.resource.kind == "Table"
                        && self.parents.contains_key(&binding.resource.key()),
                    "invalid binding"
                );
                anyhow::ensure!(
                    [&binding.region_column, &binding.sensitive_column]
                        .iter()
                        .all(|s| s
                            .as_ref()
                            .is_none_or(|s| !s.is_empty() && !s.contains('\0'))),
                    "invalid column"
                );
                self.trino.insert(serde_json::to_string(&name)?, binding);
            }
            Mutation::SetRegion { principal, region } => {
                anyhow::ensure!(
                    !principal.is_empty() && !region.contains('\0'),
                    "invalid region"
                );
                self.regions.insert(principal, region);
            }
            Mutation::Put {
                resource,
                parent,
                owner,
            } => {
                let allowed_parent = match resource.kind.as_str() {
                    "Server" => None,
                    "Project" => Some(&["Server"][..]),
                    "Warehouse" => Some(&["Project"][..]),
                    "Namespace" => Some(&["Warehouse", "Namespace"][..]),
                    "Table" | "View" | "GenericTable" => Some(&["Namespace"][..]),
                    _ => bail!("unsupported hierarchy resource"),
                };
                if let Some(p) = &parent {
                    anyhow::ensure!(
                        allowed_parent.is_some_and(|kinds| kinds.contains(&p.kind.as_str())),
                        "invalid parent type"
                    );
                }
                if let Some(p) = &parent
                    && (p == &resource || self.ancestors(p).contains(&resource))
                {
                    bail!("hierarchy cycle");
                }
                // Detach/rename invalidates SQL names. Rebinding is explicit and fail closed.
                if parent.is_none() {
                    self.trino.retain(|_, b| b.resource != resource);
                }
                self.parents
                    .insert(resource.key(), (resource.clone(), parent));
                if let Some(id) = owner {
                    let grant = Grant {
                        subject: Resource::new("User", id),
                        resource,
                        access: "owner".into(),
                    };
                    if !self.grants.contains(&grant) {
                        self.grants.push(grant);
                    }
                }
            }
            Mutation::Delete { resource } => {
                self.trino.retain(|_, b| b.resource != resource);
                self.parents.remove(&resource.key());
                self.grants
                    .retain(|g| g.resource != resource && g.subject != resource);
            }
            Mutation::Grant { grant, remove } => {
                anyhow::ensure!(
                    ["User", "Group"].contains(&grant.subject.kind.as_str()),
                    "unsupported subject"
                );
                anyhow::ensure!(
                    [
                        "Server",
                        "Project",
                        "Warehouse",
                        "Namespace",
                        "Table",
                        "View",
                        "GenericTable"
                    ]
                    .contains(&grant.resource.kind.as_str()),
                    "unsupported resource"
                );
                if !["owner", "select", "unmask", "unrestricted_rows"]
                    .contains(&grant.access.as_str())
                {
                    bail!("unsupported grant");
                }
                if remove {
                    self.grants.retain(|g| g != &grant);
                } else if !self.grants.contains(&grant) {
                    self.grants.push(grant);
                }
            }
        }
        Ok(())
    }
    fn ancestors(&self, resource: &Resource) -> Vec<Resource> {
        let mut result = vec![];
        let mut current = resource;
        while let Some((_, Some(parent))) = self.parents.get(&current.key()) {
            if result.contains(parent) {
                break;
            }
            result.push(parent.clone());
            current = parent;
        }
        result
    }
    pub fn decide(&self, check: &Check) -> Result<Verdict> {
        if check.deny || check.principal.is_empty() {
            return Ok(Verdict {
                allowed: false,
                policies: vec![],
            });
        }
        let mut entities: Vec<Value> = self.parents.values().map(|(r, p)| json!({
            "uid": r.uid(), "attrs": {}, "parents": p.iter().map(Resource::uid).collect::<Vec<_>>()
        })).collect();
        entities.push(json!({"uid": {"type":"User", "id":check.principal}, "attrs":{},
            "parents":check.groups.iter().map(|id| json!({"type":"Group", "id":id})).collect::<Vec<_>>() }));
        for group in &check.groups {
            entities.push(json!({"uid":{"type":"Group","id":group},"attrs":{},"parents":[]}));
        }
        let mut policies = PolicySet::new();
        policies.add(Policy::parse(Some(PolicyId::new("self-read")), "permit(principal, action, resource) when { context.operation == \"read_self\" && resource == principal };")?)?;
        for g in &self.grants {
            use sha2::{Digest, Sha256};
            let i = format!("{:x}", Sha256::digest(serde_json::to_vec(g)?));
            // Visibility travels up only for discovery, never for data or mutations.
            let discover = ["include_in_list", "use", "get_config", "list_namespaces"]
                .contains(&check.action.as_str());
            let upward = discover && self.ancestors(&g.resource).contains(&check.resource);
            let actions = if g.access == "owner" {
                "true"
            } else if g.access == "unmask" {
                "context.operation == \"unmask\""
            } else if g.access == "unrestricted_rows" {
                "context.operation == \"unrestricted_rows\""
            } else {
                "[\"read_data\", \"get_metadata\", \"list_tables\", \"list_views\", \"list_namespaces\", \"include_in_list\", \"use\", \"get_config\"].contains(context.operation)"
            };
            policies.add(Policy::parse(Some(PolicyId::new(format!("grant-{i}"))), format!("@id(\"grant-{i}\") permit(principal in {}, action, resource) when {{ ({actions}) && (resource in {} || {}) }};\n", g.subject.cedar(), g.resource.cedar(), upward))?)?;
        }
        let validation = Validator::new(schema()?).validate(&policies, ValidationMode::Strict);
        anyhow::ensure!(
            validation.validation_passed(),
            "generated policy failed schema validation"
        );
        let request = Request::new(
            Resource::new("User", &check.principal).cedar().parse()?,
            "Action::\"check\"".parse()?,
            check.resource.cedar().parse()?,
            Context::from_json_value(json!({"operation":check.action}), None)?,
            None,
        )?;
        let response = Authorizer::new().is_authorized(
            &request,
            &policies,
            &Entities::from_json_value(json!(entities), None)?,
        );
        if response.diagnostics().errors().next().is_some() {
            bail!("Cedar evaluation error");
        }
        Ok(Verdict {
            allowed: response.decision() == Decision::Allow,
            policies: response
                .diagnostics()
                .reason()
                .map(ToString::to_string)
                .collect(),
        })
    }
}
fn schema() -> Result<Schema> {
    Ok(Schema::from_json_value(serde_json::from_str(
        include_str!("../../../policies/schema.json"),
    )?)?)
}
pub fn validate_schema() -> Result<()> {
    schema()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn durable_bindings_detach_and_exception_grants() -> Result<()> {
        // An existing slice-1 graph remains readable without new fields.
        let mut store: Store = serde_json::from_value(json!({"parents":{},"grants":[]}))?;
        let table = Resource::new("Table", "one");
        let binding = TrinoBinding {
            resource: table.clone(),
            region_column: Some("region".into()),
            sensitive_column: Some("secret".into()),
        };
        let bind = Mutation::BindTrino {
            name: vec!["iceberg".into(), "ns".into(), "one".into()],
            binding,
        };
        assert!(store.mutate(bind.clone()).is_err());
        store.mutate(Mutation::Put {
            resource: table.clone(),
            parent: None,
            owner: None,
        })?;
        store.mutate(bind.clone())?;
        store.mutate(Mutation::SetRegion {
            principal: "alice".into(),
            region: "eu".into(),
        })?;
        store.mutate(Mutation::Grant {
            grant: Grant {
                subject: Resource::new("User", "alice"),
                resource: table.clone(),
                access: "unmask".into(),
            },
            remove: false,
        })?;
        let mut check = Check {
            deny: false,
            principal: "alice".into(),
            groups: vec![],
            action: "read_data".into(),
            resource: table.clone(),
        };
        assert!(!store.decide(&check)?.allowed);
        check.action = "unmask".into();
        assert!(store.decide(&check)?.allowed);
        let mut restored: Store = serde_json::from_value(serde_json::to_value(&store)?)?;
        assert_eq!(restored.trino.len(), 1);
        assert_eq!(restored.regions["alice"], "eu");
        restored.mutate(Mutation::Put {
            resource: table.clone(),
            parent: None,
            owner: None,
        })?;
        assert!(restored.trino.is_empty());
        restored.mutate(bind)?;
        restored.mutate(Mutation::Delete { resource: table })?;
        assert!(restored.trino.is_empty());
        Ok(())
    }
    #[test]
    fn malformed_graph_is_an_evaluation_error() {
        let mut store = Store::default();
        let invalid = Resource::new("Invalid!", "bad");
        store.parents.insert(invalid.key(), (invalid, None));
        let check = Check {
            deny: false,
            principal: "alice".into(),
            groups: vec![],
            action: "read_data".into(),
            resource: Resource::new("Table", "one"),
        };
        assert!(store.decide(&check).is_err());
    }
    #[test]
    fn identity_read_is_self_only() -> Result<()> {
        let store = Store::default();
        let mut check = Check {
            deny: false,
            principal: "alice".into(),
            groups: vec![],
            action: "read_self".into(),
            resource: Resource::new("User", "alice"),
        };
        assert!(store.decide(&check)?.allowed);
        check.resource = Resource::new("User", "bob");
        assert!(!store.decide(&check)?.allowed);
        check.resource = Resource::new("Table", "alice");
        assert!(!store.decide(&check)?.allowed);
        Ok(())
    }
    #[test]
    fn inherited_groups_sibling_isolation_and_revoke() -> Result<()> {
        validate_schema()?;
        let mut s = Store::default();
        let ns = Resource::new("Namespace", "a");
        let table = Resource::new("Table", "one");
        s.mutate(Mutation::Put {
            resource: table.clone(),
            parent: Some(ns.clone()),
            owner: None,
        })?;
        let grant = Grant {
            subject: Resource::new("Group", "readers"),
            resource: ns,
            access: "select".into(),
        };
        let mut c = Check {
            deny: false,
            principal: "alice".into(),
            groups: vec!["readers".into()],
            action: "read_data".into(),
            resource: table,
        };
        assert!(!s.decide(&c)?.allowed);
        s.mutate(Mutation::Grant {
            grant: grant.clone(),
            remove: false,
        })?;
        assert!(s.decide(&c)?.allowed);
        let policy_ids = s.decide(&c)?.policies;
        s.grants.insert(
            0,
            Grant {
                subject: Resource::new("User", "unrelated"),
                resource: Resource::new("Table", "elsewhere"),
                access: "select".into(),
            },
        );
        assert_eq!(s.decide(&c)?.policies, policy_ids);
        c.action = "write_data".into();
        assert!(!s.decide(&c)?.allowed);
        c.action = "read_data".into();
        c.resource = Resource::new("Table", "sibling");
        assert!(!s.decide(&c)?.allowed);
        s.mutate(Mutation::Grant {
            grant,
            remove: true,
        })?;
        c.resource = Resource::new("Table", "one");
        assert!(!s.decide(&c)?.allowed);
        Ok(())
    }
}
