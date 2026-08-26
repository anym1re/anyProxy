use ap_core::{
    AccessState, AdminUser, AnyAccess, Client, ClientState, Credential, KeyStore, Label, Node,
    NodeState, Role, Tag, TagName,
};
use ap_store::{AccessRepo, AuditRepo, ClientRepo, NodeRepo, TagRepo, TrafficRepo, TrafficTotals};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::ApiError;

/// Largest page any listing returns.
pub const MAX_PAGE: i64 = 200;

/// Page size when the caller does not ask for one.
pub const DEFAULT_PAGE: i64 = 50;

/// Who is making the request.
#[derive(Debug, Clone)]
pub struct Actor {
    admin: AdminUser,
}

impl Actor {
    /// Wraps an authenticated administrator.
    pub fn new(admin: AdminUser) -> Self {
        Self { admin }
    }

    /// Identifier of the administrator.
    pub fn id(&self) -> Uuid {
        self.admin.id()
    }

    /// What they are allowed to do.
    pub fn role(&self) -> Role {
        self.admin.role()
    }

    /// Name they signed in with.
    pub fn login(&self) -> &str {
        self.admin.login().as_str()
    }
}

/// The only way a handler reaches the database.
///
/// Every call takes the actor, so a handler that forgot to check a permission
/// cannot compile its way to the data. The checks live here rather than in the
/// handlers because a handler is written once per endpoint and forgotten,
/// while this is written once and read on every call.
pub struct Guarded<'a> {
    pool: &'a PgPool,
    key: &'a KeyStore,
    actor: &'a Actor,
}

impl<'a> Guarded<'a> {
    pub(crate) fn new(pool: &'a PgPool, key: &'a KeyStore, actor: &'a Actor) -> Self {
        Self { pool, key, actor }
    }

    fn page(limit: Option<i64>) -> i64 {
        limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE)
    }

    async fn owns(&self, client_id: Uuid) -> Result<bool, ApiError> {
        if self.actor.role().reaches_every_client() {
            return Ok(true);
        }
        let owner = ClientRepo::owner_of(self.pool, client_id).await?;
        Ok(owner == Some(self.actor.id()))
    }

    /// Records an administrative action. Bodies are never passed in.
    pub async fn record(
        &self,
        action: &str,
        target: Option<&str>,
        details: serde_json::Value,
    ) -> Result<(), ApiError> {
        AuditRepo::record(
            self.pool,
            Some(self.actor.id()),
            action,
            target,
            OffsetDateTime::now_utc(),
            details,
        )
        .await?;
        Ok(())
    }

    /// Clients this actor may see.
    pub async fn clients(&self, limit: Option<i64>) -> Result<Vec<Client>, ApiError> {
        let limit = Self::page(limit);
        if self.actor.role().reaches_every_client() {
            Ok(ClientRepo::list(self.pool, limit).await?)
        } else {
            Ok(ClientRepo::list_owned(self.pool, self.actor.id(), limit).await?)
        }
    }

    /// One client, if this actor may see it.
    ///
    /// A client that exists but belongs to someone else is reported the same
    /// way as one that does not exist.
    pub async fn client(&self, id: Uuid) -> Result<Client, ApiError> {
        let found = ClientRepo::by_id(self.pool, id).await?;
        match found {
            Some(client) if self.owns(id).await? => Ok(client),
            _ => Err(ApiError::NotFound),
        }
    }

    /// One client by the name an operator knows it by.
    pub async fn client_by_label(&self, label: &Label) -> Result<Client, ApiError> {
        let found = ClientRepo::by_label(self.pool, label).await?;
        match found {
            Some(client) if self.owns(client.id()).await? => Ok(client),
            _ => Err(ApiError::NotFound),
        }
    }

    /// Registers a client. A reseller owns what it creates.
    pub async fn create_client(&self, client: &Client) -> Result<(), ApiError> {
        let owner = match self.actor.role() {
            Role::Reseller => Some(self.actor.id()),
            _ => None,
        };
        ClientRepo::insert(self.pool, client, owner).await?;
        Ok(())
    }

    /// Moves a client to a new state.
    pub async fn set_client_state(&self, id: Uuid, state: ClientState) -> Result<(), ApiError> {
        self.client(id).await?;
        ClientRepo::set_state(self.pool, id, state).await?;
        Ok(())
    }

    /// What a client has spent.
    pub async fn client_traffic(&self, id: Uuid) -> Result<TrafficTotals, ApiError> {
        self.client(id).await?;
        Ok(TrafficRepo::for_client(self.pool, id).await?)
    }

    /// Accesses a client holds.
    pub async fn accesses(&self, client_id: Uuid) -> Result<Vec<AnyAccess>, ApiError> {
        self.client(client_id).await?;
        Ok(AccessRepo::by_client(self.pool, client_id).await?)
    }

    /// One access, if this actor may see its client.
    pub async fn access(&self, id: Uuid) -> Result<AnyAccess, ApiError> {
        let found = AccessRepo::by_id(self.pool, id)
            .await?
            .ok_or(ApiError::NotFound)?;
        if self.owns(found.common().client_id()).await? {
            Ok(found)
        } else {
            Err(ApiError::NotFound)
        }
    }

    /// Issues an access.
    pub async fn create_access(
        &self,
        access: &AnyAccess,
        credential: &Credential,
    ) -> Result<(), ApiError> {
        if !self.owns(access.common().client_id()).await? {
            return Err(ApiError::NotFound);
        }
        AccessRepo::insert(self.pool, access, credential, self.key).await?;
        Ok(())
    }

    /// Moves an access to a new state.
    pub async fn set_access_state(&self, id: Uuid, state: AccessState) -> Result<bool, ApiError> {
        self.access(id).await?;
        Ok(AccessRepo::set_state(self.pool, id, state).await?)
    }

    /// Opens the credential of an access, for rendering a link.
    pub async fn credential(&self, id: Uuid) -> Result<Credential, ApiError> {
        self.access(id).await?;
        AccessRepo::credential(self.pool, id, self.key)
            .await?
            .ok_or(ApiError::NotFound)
    }

    /// Withdraws every access under a tag that this actor may reach.
    pub async fn revoke_by_tag(&self, tag_id: Uuid) -> Result<u64, ApiError> {
        if !self.actor.role().reaches_every_client() {
            return Err(ApiError::Forbidden);
        }
        Ok(AccessRepo::revoke_by_tag(self.pool, tag_id).await?)
    }

    /// Tags.
    pub async fn tags(&self) -> Result<Vec<Tag>, ApiError> {
        Ok(TagRepo::list(self.pool).await?)
    }

    /// One tag by name.
    pub async fn tag_by_name(&self, name: &TagName) -> Result<Tag, ApiError> {
        TagRepo::by_name(self.pool, name)
            .await?
            .ok_or(ApiError::NotFound)
    }

    /// Creates a tag.
    pub async fn create_tag(&self, tag: &Tag) -> Result<(), ApiError> {
        TagRepo::insert(self.pool, tag).await?;
        Ok(())
    }

    /// Nodes, for roles that may know they exist.
    ///
    /// A reseller is told there is nothing rather than told it may not look:
    /// the number of nodes is itself part of what the network looks like.
    pub async fn nodes(&self) -> Result<Vec<Node>, ApiError> {
        if !self.actor.role().sees_nodes() {
            return Err(ApiError::NotFound);
        }
        Ok(NodeRepo::list(self.pool).await?)
    }

    /// One node by the name an operator knows it by.
    pub async fn node_by_label(&self, label: &Label) -> Result<Node, ApiError> {
        if !self.actor.role().sees_nodes() {
            return Err(ApiError::NotFound);
        }
        NodeRepo::by_label(self.pool, label)
            .await?
            .ok_or(ApiError::NotFound)
    }

    /// One node by identifier.
    pub async fn node(&self, id: Uuid) -> Result<Node, ApiError> {
        if !self.actor.role().sees_nodes() {
            return Err(ApiError::NotFound);
        }
        NodeRepo::list(self.pool)
            .await?
            .into_iter()
            .find(|node| node.id() == id)
            .ok_or(ApiError::NotFound)
    }

    /// Registers a node.
    pub async fn create_node(&self, node: &Node) -> Result<(), ApiError> {
        if !self.actor.role().manages_nodes() {
            return Err(ApiError::NotFound);
        }
        NodeRepo::insert(self.pool, node).await?;
        Ok(())
    }

    /// Destroys a node.
    pub async fn burn_node(&self, id: Uuid) -> Result<(), ApiError> {
        if !self.actor.role().manages_nodes() {
            return Err(ApiError::NotFound);
        }
        self.node(id).await?;
        NodeRepo::set_state(self.pool, id, NodeState::Burned).await?;
        Ok(())
    }

    /// The audit log.
    pub async fn audit(&self, limit: Option<i64>) -> Result<Vec<ap_store::AuditEntry>, ApiError> {
        if !self.actor.role().reads_audit() {
            return Err(ApiError::NotFound);
        }
        Ok(AuditRepo::recent(self.pool, Self::page(limit)).await?)
    }
}
