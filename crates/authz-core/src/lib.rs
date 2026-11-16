//! S1 only: trusted adapter assertions, an in-memory graph, and Cedar evaluation.
use anyhow::{Result, bail};
use cedar_policy::{
    Authorizer, Context, Decision, Entities, PolicySet, Request, Schema, ValidationMode, Validator,
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
    /// Trusted SQL-name bindings and obligations; populated only by fixture/admin.
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
                    name.len() == 3 && binding.resource.kind == "Table",
                    "invalid binding"
                );
                self.trino.insert(serde_json::to_string(&name)?, binding);
            }
            Mutation::SetRegion { principal, region } => {
                self.regions.insert(principal, region);
            }
            Mutation::Put {
                resource,
                parent,
                owner,
            } => {
                if let Some(p) = &parent
                    && (p == &resource || self.ancestors(p).contains(&resource))
                {
                    bail!("hierarchy cycle");
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
                self.parents.remove(&resource.key());
                self.grants
                    .retain(|g| g.resource != resource && g.subject != resource);
            }
            Mutation::Grant { grant, remove } => {
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
        let mut entities: Vec<Value> = self.parents.values().map(|(r, p)| json!({
            "uid": r.uid(), "attrs": {}, "parents": p.iter().map(Resource::uid).collect::<Vec<_>>()
        })).collect();
        entities.push(json!({"uid": {"type":"User", "id":check.principal}, "attrs":{},
            "parents":check.groups.iter().map(|id| json!({"type":"Group", "id":id})).collect::<Vec<_>>() }));
        for group in &check.groups {
            entities.push(json!({"uid":{"type":"Group","id":group},"attrs":{},"parents":[]}));
        }
        let mut text = String::from(
            "@id(\"self-read\") permit(principal, action, resource) when { context.operation == \"read_self\" && resource == principal };\n",
        );
        for (i, g) in self.grants.iter().enumerate() {
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
            text.push_str(&format!("@id(\"grant-{i}\") permit(principal in {}, action, resource) when {{ ({actions}) && (resource in {} || {}) }};\n", g.subject.cedar(), g.resource.cedar(), upward));
        }
        let policies: PolicySet = text.parse()?;
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
    fn identity_read_is_self_only() -> Result<()> {
        let store = Store::default();
        let mut check = Check {
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
