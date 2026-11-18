// Adapted from Lakekeeper AllowAllAuthorizer (Apache-2.0), pinned source; all decisions replaced.
use std::collections::HashMap;

use async_trait::async_trait;
use axum::Router;

use lakekeeper::{
    api::RequestMetadata,
    api::{ApiContext, iceberg::v1::Result},
    service::{
        ArcProjectId, AuthZGenericTableInfo, AuthZNamespaceInfo, AuthZTableInfo, AuthZViewInfo,
        CatalogStore, GenericTableId, NamespaceId, NamespaceWithParent, ProjectId,
        ResolvedWarehouse, Role, RoleId, SecretStore, ServerId, State, TableId, ViewId,
        WarehouseId,
        authn::UserId,
        authz::{
            ActionOnGenericTable, ActionOnTable, ActionOnView, AuthorizationDecision, Authorizer,
            AuthzBackendErrorOrBadRequest, CatalogGenericTableAction, CatalogNamespaceAction,
            CatalogProjectAction, CatalogRoleAction, CatalogServerAction, CatalogTableAction,
            CatalogUserAction, CatalogViewAction, CatalogWarehouseAction, IsAllowedActionError,
            ListProjectsResponse, NamespaceParent, UserOrRole,
        },
        health::{Health, HealthExt},
    },
};

#[derive(Clone)]
pub struct CedarAuthorizer {
    pub server_id: ServerId,
    client: reqwest::Client,
    endpoint: String,
    key: String,
}

#[async_trait]
impl HealthExt for CedarAuthorizer {
    async fn health(&self) -> Vec<Health> {
        vec![]
    }
    async fn update_health(&self) {
        // Do nothing
    }
}

#[async_trait]
impl Authorizer for CedarAuthorizer {
    type ServerAction = CatalogServerAction;
    type ProjectAction = CatalogProjectAction;
    type WarehouseAction = CatalogWarehouseAction;
    type NamespaceAction = CatalogNamespaceAction;
    type TableAction = CatalogTableAction;
    type ViewAction = CatalogViewAction;
    type GenericTableAction = CatalogGenericTableAction;
    type UserAction = CatalogUserAction;
    type RoleAction = CatalogRoleAction;

    fn implementation_name() -> &'static str {
        "datopsis-cedar"
    }

    fn server_id(&self) -> ServerId {
        self.server_id
    }

    fn new_router<C: CatalogStore, S: SecretStore>(&self) -> Router<ApiContext<State<Self, C, S>>> {
        use axum::routing::get;
        Router::new()
            .route(
                "/permissions/{kind}/{id}/grants",
                get(read_grants::<C, S>).post(write_grants::<C, S>),
            )
            .route(
                "/permissions/{*unsupported}",
                axum::routing::any(unsupported_permission::<C, S>),
            )
    }

    async fn check_assume_role_impl(
        &self,
        _principal: &UserId,
        _assumed_role: &Role,
        _request_metadata: &RequestMetadata,
    ) -> Result<bool, AuthzBackendErrorOrBadRequest> {
        self.check_denied(
            _request_metadata,
            vec![(
                Resource::new("Role", _assumed_role.id),
                "assume_role".into(),
            )],
        )
        .await
        .map_err(|_| {
            AuthorizationBackendUnavailable::new(std::io::Error::other(
                "decision audit unavailable",
            ))
        })?;
        Ok(false)
    }

    async fn can_bootstrap(&self, metadata: &RequestMetadata) -> Result<()> {
        use lakekeeper::service::events::AuthorizationFailureSource;
        let server = Resource::new("Server", self.server_id);
        if metadata.user_id().map(ToString::to_string).as_deref()
            != Some(&std::env::var("AUTHZ_BOOTSTRAP_PRINCIPAL").unwrap_or("oidc~operator".into()))
        {
            self.check_denied(metadata, vec![(server, "bootstrap".into())])
                .await
                .map_err(|e| e.into_error_model())?;
            return Err(lakekeeper::api::ErrorModel::forbidden(
                "Bootstrap principal required",
                "Forbidden",
                None,
            )
            .into());
        }
        // Initialize the designated bootstrap owner's graph before checking it;
        // the hook repeats this idempotently after Lakekeeper commits bootstrap.
        self.put(metadata, server.clone(), None).await?;
        self.check(metadata, None, vec![(server, "bootstrap".into())])
            .await
            .map_err(|e| e.into_error_model())?;
        Ok(())
    }

    async fn bootstrap(&self, _metadata: &RequestMetadata, _is_operator: bool) -> Result<()> {
        self.put(_metadata, Resource::new("Server", self.server_id), None)
            .await
    }

    async fn list_projects_impl(
        &self,
        _metadata: &RequestMetadata,
    ) -> Result<ListProjectsResponse, AuthzBackendErrorOrBadRequest> {
        Ok(ListProjectsResponse::Unsupported)
    }

    async fn can_search_users_impl(
        &self,
        _metadata: &RequestMetadata,
    ) -> Result<bool, AuthzBackendErrorOrBadRequest> {
        self.check_denied(
            _metadata,
            vec![(
                Resource::new("Server", self.server_id),
                "search_users".into(),
            )],
        )
        .await
        .map_err(|_| {
            AuthorizationBackendUnavailable::new(std::io::Error::other(
                "decision audit unavailable",
            ))
        })?;
        Ok(false)
    }

    async fn are_allowed_user_actions_impl(
        &self,
        _metadata: &RequestMetadata,
        _for_user: Option<&UserOrRole>,
        users_with_actions: &[(&UserId, Self::UserAction)],
    ) -> Result<Vec<AuthorizationDecision>, IsAllowedActionError> {
        self.check(
            _metadata,
            _for_user,
            users_with_actions
                .iter()
                .map(|(user, action)| {
                    (
                        Resource::new("User", user),
                        if matches!(action, CatalogUserAction::Read) {
                            "read_self".to_owned()
                        } else {
                            action.action_descriptor().action_name.to_owned()
                        },
                    )
                })
                .collect(),
        )
        .await
    }

    async fn are_allowed_role_actions_impl(
        &self,
        _metadata: &RequestMetadata,
        _for_user: Option<&UserOrRole>,
        roles_with_actions: &[(&Role, Self::RoleAction)],
    ) -> Result<Vec<AuthorizationDecision>, IsAllowedActionError> {
        self.check_denied(
            _metadata,
            roles_with_actions
                .iter()
                .map(|(role, action)| {
                    (
                        Resource::new("Role", role.id),
                        action.action_descriptor().action_name.to_owned(),
                    )
                })
                .collect(),
        )
        .await
    }

    async fn are_allowed_server_actions_impl(
        &self,
        _metadata: &RequestMetadata,
        _for_user: Option<&UserOrRole>,
        actions: &[Self::ServerAction],
    ) -> Result<Vec<AuthorizationDecision>, IsAllowedActionError> {
        self.check(
            _metadata,
            _for_user,
            actions
                .iter()
                .map(|a| {
                    (
                        Resource::new("Server", self.server_id),
                        a.action_descriptor().action_name.to_owned(),
                    )
                })
                .collect(),
        )
        .await
    }

    async fn are_allowed_project_actions_impl(
        &self,
        _metadata: &RequestMetadata,
        _for_user: Option<&UserOrRole>,
        projects_with_actions: &[(&ArcProjectId, Self::ProjectAction)],
    ) -> Result<Vec<AuthorizationDecision>, IsAllowedActionError> {
        self.check(
            _metadata,
            _for_user,
            projects_with_actions
                .iter()
                .map(|(p, a)| {
                    (
                        Resource::new("Project", p),
                        a.action_descriptor().action_name.to_owned(),
                    )
                })
                .collect(),
        )
        .await
    }

    async fn are_allowed_warehouse_actions_impl(
        &self,
        _metadata: &RequestMetadata,
        _for_user: Option<&UserOrRole>,
        warehouses_with_actions: &[(&ResolvedWarehouse, Self::WarehouseAction)],
    ) -> Result<Vec<AuthorizationDecision>, IsAllowedActionError> {
        self.check(
            _metadata,
            _for_user,
            warehouses_with_actions
                .iter()
                .map(|(w, a)| {
                    (
                        Resource::new("Warehouse", w.warehouse_id),
                        a.action_descriptor().action_name.to_owned(),
                    )
                })
                .collect(),
        )
        .await
    }

    async fn are_allowed_namespace_actions_impl(
        &self,
        _metadata: &RequestMetadata,
        _for_user: Option<&UserOrRole>,
        _warehouse: &ResolvedWarehouse,
        _parent_namespaces: &HashMap<NamespaceId, NamespaceWithParent>,
        actions: &[(&impl AuthZNamespaceInfo, Self::NamespaceAction)],
    ) -> Result<Vec<AuthorizationDecision>, IsAllowedActionError> {
        self.check(
            _metadata,
            _for_user,
            actions
                .iter()
                .map(|(n, a)| {
                    (
                        Resource::new("Namespace", n.namespace_id()),
                        a.action_descriptor().action_name.to_owned(),
                    )
                })
                .collect(),
        )
        .await
    }

    async fn are_allowed_table_actions_impl<A: Into<Self::TableAction> + Send + Clone + Sync>(
        &self,
        _metadata: &RequestMetadata,
        _warehouse: &ResolvedWarehouse,
        _parent_namespaces: &HashMap<NamespaceId, NamespaceWithParent>,
        actions: &[(
            &NamespaceWithParent,
            ActionOnTable<'_, '_, impl AuthZTableInfo, A>,
        )],
    ) -> Result<Vec<AuthorizationDecision>, IsAllowedActionError> {
        if actions.iter().any(|(_, a)| a.user.is_some()) {
            return self
                .check_denied(
                    _metadata,
                    actions
                        .iter()
                        .map(|(_, a)| {
                            (
                                Resource::new("Table", a.info.table_id()),
                                a.action
                                    .clone()
                                    .into()
                                    .action_descriptor()
                                    .action_name
                                    .to_owned(),
                            )
                        })
                        .collect(),
                )
                .await;
        }
        self.check(
            _metadata,
            None,
            actions
                .iter()
                .map(|(_, a)| {
                    (
                        Resource::new("Table", a.info.table_id()),
                        a.action
                            .clone()
                            .into()
                            .action_descriptor()
                            .action_name
                            .to_owned(),
                    )
                })
                .collect(),
        )
        .await
    }

    async fn are_allowed_view_actions_impl<A: Into<Self::ViewAction> + Send + Clone + Sync>(
        &self,
        _metadata: &RequestMetadata,
        _warehouse: &ResolvedWarehouse,
        _parent_namespaces: &HashMap<NamespaceId, NamespaceWithParent>,
        actions: &[(
            &NamespaceWithParent,
            ActionOnView<'_, '_, impl AuthZViewInfo, A>,
        )],
    ) -> Result<Vec<AuthorizationDecision>, IsAllowedActionError> {
        if actions.iter().any(|(_, a)| a.user.is_some()) {
            return self
                .check_denied(
                    _metadata,
                    actions
                        .iter()
                        .map(|(_, a)| {
                            (
                                Resource::new("View", a.info.view_id()),
                                a.action
                                    .clone()
                                    .into()
                                    .action_descriptor()
                                    .action_name
                                    .to_owned(),
                            )
                        })
                        .collect(),
                )
                .await;
        }
        self.check(
            _metadata,
            None,
            actions
                .iter()
                .map(|(_, a)| {
                    (
                        Resource::new("View", a.info.view_id()),
                        a.action
                            .clone()
                            .into()
                            .action_descriptor()
                            .action_name
                            .to_owned(),
                    )
                })
                .collect(),
        )
        .await
    }

    async fn are_allowed_generic_table_actions_impl<
        A: Into<Self::GenericTableAction> + Send + Clone + Sync,
    >(
        &self,
        _metadata: &RequestMetadata,
        _warehouse: &ResolvedWarehouse,
        _parent_namespaces: &HashMap<NamespaceId, NamespaceWithParent>,
        actions: &[(
            &NamespaceWithParent,
            ActionOnGenericTable<'_, '_, impl AuthZGenericTableInfo, A>,
        )],
    ) -> Result<Vec<AuthorizationDecision>, IsAllowedActionError> {
        if actions.iter().any(|(_, a)| a.user.is_some()) {
            return self
                .check_denied(
                    _metadata,
                    actions
                        .iter()
                        .map(|(_, a)| {
                            (
                                Resource::new("GenericTable", a.info.generic_table_id()),
                                a.action
                                    .clone()
                                    .into()
                                    .action_descriptor()
                                    .action_name
                                    .to_owned(),
                            )
                        })
                        .collect(),
                )
                .await;
        }
        self.check(
            _metadata,
            None,
            actions
                .iter()
                .map(|(_, a)| {
                    (
                        Resource::new("GenericTable", a.info.generic_table_id()),
                        a.action
                            .clone()
                            .into()
                            .action_descriptor()
                            .action_name
                            .to_owned(),
                    )
                })
                .collect(),
        )
        .await
    }

    async fn detach_tabular_parent(
        &self,
        _metadata: &RequestMetadata,
        _warehouse: WarehouseId,
        tabular: lakekeeper::service::TabularId,
        _parent: NamespaceId,
    ) -> Result<()> {
        self.mutate(Mutation::Put {
            resource: tabular_resource(tabular),
            parent: None,
            owner: None,
        })
        .await
    }
    async fn attach_tabular_parent(
        &self,
        _metadata: &RequestMetadata,
        _warehouse: WarehouseId,
        tabular: lakekeeper::service::TabularId,
        parent: NamespaceId,
    ) -> Result<()> {
        self.mutate(Mutation::Put {
            resource: tabular_resource(tabular),
            parent: Some(Resource::new("Namespace", parent)),
            owner: None,
        })
        .await
    }

    async fn delete_user(&self, _metadata: &RequestMetadata, _user_id: UserId) -> Result<()> {
        self.mutate(Mutation::Delete {
            resource: Resource::new("User", _user_id),
        })
        .await
    }

    async fn create_role(
        &self,
        _metadata: &RequestMetadata,
        _role_id: RoleId,
        _parent_project_id: ArcProjectId,
    ) -> Result<()> {
        Err(lakekeeper::api::ErrorModel::forbidden(
            "Role management is not implemented",
            "Forbidden",
            None,
        )
        .into())
    }

    async fn delete_role(&self, _metadata: &RequestMetadata, _role_id: RoleId) -> Result<()> {
        Err(lakekeeper::api::ErrorModel::forbidden(
            "Role management is not implemented",
            "Forbidden",
            None,
        )
        .into())
    }

    async fn create_project(
        &self,
        _metadata: &RequestMetadata,
        _project_id: &ProjectId,
    ) -> Result<()> {
        self.put(
            _metadata,
            Resource::new("Project", _project_id),
            Some(Resource::new("Server", self.server_id)),
        )
        .await
    }

    async fn delete_project(
        &self,
        _metadata: &RequestMetadata,
        _project_id: &ProjectId,
    ) -> Result<()> {
        self.mutate(Mutation::Delete {
            resource: Resource::new("Project", _project_id),
        })
        .await
    }

    async fn create_warehouse(
        &self,
        _metadata: &RequestMetadata,
        _warehouse_id: WarehouseId,
        _parent_project_id: &ProjectId,
    ) -> Result<()> {
        self.put(
            _metadata,
            Resource::new("Warehouse", _warehouse_id),
            Some(Resource::new("Project", _parent_project_id)),
        )
        .await
    }

    async fn delete_warehouse(
        &self,
        _metadata: &RequestMetadata,
        _warehouse_id: WarehouseId,
    ) -> Result<()> {
        self.mutate(Mutation::Delete {
            resource: Resource::new("Warehouse", _warehouse_id),
        })
        .await
    }

    async fn create_namespace(
        &self,
        _metadata: &RequestMetadata,
        _namespace_id: NamespaceId,
        _parent: NamespaceParent,
    ) -> Result<()> {
        let parent = match _parent {
            NamespaceParent::Warehouse(id) => Resource::new("Warehouse", id),
            NamespaceParent::Namespace(id) => Resource::new("Namespace", id),
        };
        self.put(
            _metadata,
            Resource::new("Namespace", _namespace_id),
            Some(parent),
        )
        .await
    }

    async fn delete_namespace(
        &self,
        _metadata: &RequestMetadata,
        _namespace_id: NamespaceId,
    ) -> Result<()> {
        self.mutate(Mutation::Delete {
            resource: Resource::new("Namespace", _namespace_id),
        })
        .await
    }

    async fn create_table(
        &self,
        _metadata: &RequestMetadata,
        _warehouse_id: WarehouseId,
        _table_id: TableId,
        _parent: NamespaceId,
    ) -> Result<()> {
        self.put(
            _metadata,
            Resource::new("Table", _table_id),
            Some(Resource::new("Namespace", _parent)),
        )
        .await
    }

    async fn delete_table(&self, _warehouse_id: WarehouseId, _table_id: TableId) -> Result<()> {
        self.mutate(Mutation::Delete {
            resource: Resource::new("Table", _table_id),
        })
        .await
    }

    async fn create_view(
        &self,
        _metadata: &RequestMetadata,
        _warehouse_id: WarehouseId,
        _view_id: ViewId,
        _parent: NamespaceId,
    ) -> Result<()> {
        self.put(
            _metadata,
            Resource::new("View", _view_id),
            Some(Resource::new("Namespace", _parent)),
        )
        .await
    }

    async fn delete_view(&self, _warehouse_id: WarehouseId, _view_id: ViewId) -> Result<()> {
        self.mutate(Mutation::Delete {
            resource: Resource::new("View", _view_id),
        })
        .await
    }

    async fn create_generic_table(
        &self,
        _metadata: &RequestMetadata,
        _warehouse_id: WarehouseId,
        _generic_table_id: GenericTableId,
        _parent: NamespaceId,
    ) -> Result<()> {
        self.put(
            _metadata,
            Resource::new("GenericTable", _generic_table_id),
            Some(Resource::new("Namespace", _parent)),
        )
        .await
    }

    async fn delete_generic_table(
        &self,
        _warehouse_id: WarehouseId,
        _generic_table_id: GenericTableId,
    ) -> Result<()> {
        self.mutate(Mutation::Delete {
            resource: Resource::new("GenericTable", _generic_table_id),
        })
        .await
    }
}

use authz_core::{Check, Mutation, Resource, Verdict};
use lakekeeper::service::authz::{
    AuthorizationBackendUnavailable, AuthorizationCountMismatch, CatalogAction,
};
impl CedarAuthorizer {
    pub fn from_env(server_id: ServerId) -> anyhow::Result<Self> {
        let endpoint = std::env::var("AUTHZ_ENDPOINT")?;
        anyhow::ensure!(endpoint.starts_with("https://"), "verified HTTPS required");
        let ca = reqwest::Certificate::from_pem(&std::fs::read(std::env::var("AUTHZ_CA_FILE")?)?)?;
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .build()?;
        let key = std::fs::read_to_string(std::env::var("AUTHZ_KEY_FILE")?)?
            .trim()
            .to_owned();
        Ok(Self {
            server_id,
            client,
            endpoint,
            key,
        })
    }
    async fn mutate(&self, m: Mutation) -> Result<()> {
        use lakekeeper::service::events::AuthorizationFailureSource;
        self.client
            .post(format!("{}/mutate", self.endpoint))
            .bearer_auth(&self.key)
            .json(&m)
            .send()
            .await
            .map_err(|e| AuthorizationBackendUnavailable::new(e).into_error_model())?
            .error_for_status()
            .map_err(|e| AuthorizationBackendUnavailable::new(e).into_error_model())?;
        Ok(())
    }
    async fn put(
        &self,
        metadata: &RequestMetadata,
        resource: Resource,
        parent: Option<Resource>,
    ) -> Result<()> {
        self.mutate(Mutation::Put {
            resource,
            parent,
            owner: metadata.user_id().map(ToString::to_string),
        })
        .await
    }
    async fn check(
        &self,
        metadata: &RequestMetadata,
        for_user: Option<&UserOrRole>,
        actions: Vec<(Resource, String)>,
    ) -> Result<Vec<AuthorizationDecision>, IsAllowedActionError> {
        let deny = for_user.is_some()
            || !matches!(metadata.actor(), lakekeeper::service::Actor::Principal(_));
        let principal = metadata
            .user_id()
            .map(ToString::to_string)
            .unwrap_or_default();
        let checks: Vec<_> = actions
            .into_iter()
            .map(|(resource, action)| Check {
                deny,
                principal: principal.clone(),
                groups: vec![],
                action,
                resource,
            })
            .collect();
        self.send_checks(checks).await
    }
    async fn check_denied(
        &self,
        metadata: &RequestMetadata,
        actions: Vec<(Resource, String)>,
    ) -> Result<Vec<AuthorizationDecision>, IsAllowedActionError> {
        let checks = actions
            .into_iter()
            .map(|(resource, action)| Check {
                deny: true,
                principal: metadata
                    .user_id()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                groups: vec![],
                action,
                resource,
            })
            .collect();
        self.send_checks(checks).await
    }
    async fn send_checks(
        &self,
        checks: Vec<Check>,
    ) -> Result<Vec<AuthorizationDecision>, IsAllowedActionError> {
        let results: Vec<Verdict> = self
            .client
            .post(format!("{}/decide", self.endpoint))
            .bearer_auth(&self.key)
            .json(&checks)
            .send()
            .await
            .map_err(AuthorizationBackendUnavailable::new)?
            .error_for_status()
            .map_err(AuthorizationBackendUnavailable::new)?
            .json()
            .await
            .map_err(AuthorizationBackendUnavailable::new)?;
        if results.len() != checks.len() {
            return Err(
                AuthorizationCountMismatch::new(checks.len(), results.len(), "cedar").into(),
            );
        }
        Ok(results
            .into_iter()
            .map(|v| {
                AuthorizationDecision::new(
                    v.allowed,
                    v.policies
                        .into_iter()
                        .map(
                            |policy_id| lakekeeper::service::authz::DeterminingFactor::Policy {
                                policy_id,
                                name: None,
                                effect: lakekeeper::service::authz::PolicyEffect::Permit,
                                source: Some("catalog-grants".into()),
                            },
                        )
                        .collect(),
                )
            })
            .collect())
    }
}

impl std::fmt::Debug for CedarAuthorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CedarAuthorizer")
            .field("server_id", &self.server_id)
            .finish_non_exhaustive()
    }
}

fn tabular_resource(tabular: lakekeeper::service::TabularId) -> Resource {
    use lakekeeper::service::TabularId;
    match tabular {
        TabularId::Table(id) => Resource::new("Table", id),
        TabularId::View(id) => Resource::new("View", id),
        TabularId::GenericTable(id) => Resource::new("GenericTable", id),
    }
}

#[derive(serde::Deserialize)]
struct GrantChange {
    subject: Resource,
    access: String,
    #[serde(default)]
    remove: bool,
}
async fn unsupported_permission<C: CatalogStore, S: SecretStore>(
    axum::extract::State(ctx): axum::extract::State<ApiContext<State<CedarAuthorizer, C, S>>>,
    axum::Extension(metadata): axum::Extension<RequestMetadata>,
) -> Result<axum::http::StatusCode> {
    use lakekeeper::service::events::AuthorizationFailureSource;
    ctx.v1_state
        .authz
        .check_denied(
            &metadata,
            vec![(
                Resource::new("Server", ctx.v1_state.authz.server_id),
                "unsupported_permission".into(),
            )],
        )
        .await
        .map_err(|e| e.into_error_model())?;
    Ok(axum::http::StatusCode::FORBIDDEN)
}
async fn read_grants<C: CatalogStore, S: SecretStore>(
    axum::extract::State(ctx): axum::extract::State<ApiContext<State<CedarAuthorizer, C, S>>>,
    axum::Extension(metadata): axum::Extension<RequestMetadata>,
    axum::extract::Path((kind, id)): axum::extract::Path<(String, String)>,
) -> Result<axum::Json<Vec<authz_core::Grant>>> {
    permission_request(&ctx.v1_state.authz, &metadata, kind, id, None).await
}
async fn write_grants<C: CatalogStore, S: SecretStore>(
    axum::extract::State(ctx): axum::extract::State<ApiContext<State<CedarAuthorizer, C, S>>>,
    axum::Extension(metadata): axum::Extension<RequestMetadata>,
    axum::extract::Path((kind, id)): axum::extract::Path<(String, String)>,
    axum::Json(change): axum::Json<GrantChange>,
) -> Result<axum::Json<Vec<authz_core::Grant>>> {
    permission_request(&ctx.v1_state.authz, &metadata, kind, id, Some(change)).await
}
async fn permission_request(
    authz: &CedarAuthorizer,
    metadata: &RequestMetadata,
    kind: String,
    id: String,
    change: Option<GrantChange>,
) -> Result<axum::Json<Vec<authz_core::Grant>>> {
    use lakekeeper::service::events::AuthorizationFailureSource;
    let kind = match kind.as_str() {
        "server" => "Server",
        "project" => "Project",
        "warehouse" => "Warehouse",
        "namespace" => "Namespace",
        "table" => "Table",
        "view" => "View",
        "generic-table" => "GenericTable",
        _ => {
            return Err(lakekeeper::api::ErrorModel::forbidden(
                "Unsupported resource",
                "Forbidden",
                None,
            )
            .into());
        }
    };
    let resource = Resource::new(kind, id);
    let check = Check {
        deny: !matches!(metadata.actor(), lakekeeper::service::Actor::Principal(_)),
        principal: metadata
            .user_id()
            .map(ToString::to_string)
            .unwrap_or_default(),
        groups: vec![],
        action: "manage_grants".into(),
        resource: resource.clone(),
    };
    let remove = change.as_ref().is_some_and(|c| c.remove);
    let grant = change.map(|c| authz_core::Grant {
        subject: c.subject,
        resource,
        access: c.access,
    });
    let response = authz
        .client
        .post(format!("{}/permissions", authz.endpoint))
        .bearer_auth(&authz.key)
        .json(&serde_json::json!({"check": check, "grant": grant, "remove":remove}))
        .send()
        .await
        .map_err(|e| AuthorizationBackendUnavailable::new(e).into_error_model())?;
    if response.status() == reqwest::StatusCode::FORBIDDEN {
        return Err(lakekeeper::api::ErrorModel::forbidden(
            "Grant owner required",
            "Forbidden",
            None,
        )
        .into());
    }
    Ok(axum::Json(
        response
            .error_for_status()
            .map_err(|e| AuthorizationBackendUnavailable::new(e).into_error_model())?
            .json()
            .await
            .map_err(|e| AuthorizationBackendUnavailable::new(e).into_error_model())?,
    ))
}
