use ap_core::{
    AccessState, AdTag, AdminUser, AnyAccess, Client, ClientState, Credential, Domain, Holder,
    KeyStore, Label, Node, NodeState, Role, Tag, TagName,
};
use ap_store::{
    AccessRepo, AuditRepo, BotRepo, ClientRepo, DailyTraffic, NodeRepo, TagRepo, TrafficRepo,
    TrafficTotals,
};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::ApiError;

/// Largest page any listing returns.
pub const MAX_PAGE: i64 = 200;

/// Page size when the caller does not ask for one.
pub const DEFAULT_PAGE: i64 = 50;

/// Whom an operator's message is addressed to (0102).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recipients {
    /// Every client the operator may see.
    All,
    /// One client.
    Client(Uuid),
    /// Clients holding an access under a tag.
    Tag(Uuid),
}

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

    /// Whether this actor may see a link, by who holds it.
    ///
    /// A public link belongs to nobody, so there is no ownership to check: it
    /// is shown to whoever may see every client and hidden from a reseller,
    /// who may see only what is theirs. Hidden rather than refused, the same
    /// way a client they do not own is hidden.
    async fn may_see(&self, holder: &Holder) -> Result<bool, ApiError> {
        match holder {
            Holder::Client(client_id) => self.owns(*client_id).await,
            Holder::Public(_) => Ok(self.actor.role().reaches_every_client()),
        }
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

    /// Whom an operator's message would reach: clients this actor may see
    /// that the bot can write to (0102). A reseller reaches only their own,
    /// whichever way the message is addressed.
    pub async fn message_recipients(&self, to: Recipients) -> Result<Vec<Uuid>, ApiError> {
        let owner = (!self.actor.role().reaches_every_client()).then(|| self.actor.id());
        Ok(match to {
            Recipients::All => BotRepo::reachable(self.pool, owner)
                .await?
                .iter()
                .map(Client::id)
                .collect(),
            Recipients::Client(id) => {
                let client = self.client(id).await?;
                if client.telegram_account().is_some() {
                    vec![id]
                } else {
                    Vec::new()
                }
            }
            Recipients::Tag(tag) => BotRepo::reachable_with_tag(self.pool, tag, owner).await?,
        })
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

    /// Records a code that ties a Telegram account to a client (0082).
    ///
    /// The digest and nothing else: the code is shown once by the caller.
    /// Only for a client this actor may see, and the client comes back so
    /// the journal can name it.
    pub async fn issue_bot_code(
        &self,
        client_id: Uuid,
        code_hash: &[u8],
        expires_at: OffsetDateTime,
        at: OffsetDateTime,
    ) -> Result<Client, ApiError> {
        let client = self.client(client_id).await?;
        ap_store::BotRepo::issue_code(self.pool, client_id, code_hash, expires_at, at).await?;
        Ok(client)
    }

    /// Takes the Telegram account off a client this actor may see. The
    /// client, and whether there was an account to take off.
    pub async fn unlink_telegram(&self, client_id: Uuid) -> Result<(Client, bool), ApiError> {
        let client = self.client(client_id).await?;
        let had = ap_store::BotRepo::unlink(self.pool, client_id).await?;
        Ok((client, had))
    }

    /// Accesses a client holds.
    pub async fn accesses(&self, client_id: Uuid) -> Result<Vec<AnyAccess>, ApiError> {
        self.client(client_id).await?;
        Ok(AccessRepo::by_client(self.pool, client_id).await?)
    }

    /// Accesses across the clients this actor may see, newest first.
    pub async fn all_accesses(&self, limit: Option<i64>) -> Result<Vec<AnyAccess>, ApiError> {
        let limit = Self::page(limit);
        if self.actor.role().reaches_every_client() {
            Ok(AccessRepo::list(self.pool, limit).await?)
        } else {
            Ok(AccessRepo::list_owned(self.pool, self.actor.id(), limit).await?)
        }
    }

    /// What the fleet carried in each of the last hours (0072).
    pub async fn traffic_hourly(
        &self,
        hours: i64,
    ) -> Result<Vec<(time::OffsetDateTime, i64, i64)>, ApiError> {
        let hours = hours.clamp(1, 72);
        let since = time::OffsetDateTime::now_utc() - time::Duration::hours(hours);
        let owner = (!self.actor.role().reaches_every_client()).then(|| self.actor.id());
        Ok(ap_store::TrafficRepo::by_hour(self.pool, since, owner).await?)
    }

    /// What every access this actor may see has carried over a window, and
    /// the last day each was busy (0066).
    pub async fn carried(
        &self,
        days: i64,
    ) -> Result<std::collections::HashMap<Uuid, (i64, String)>, ApiError> {
        let days = days.clamp(1, 400);
        let since = time::OffsetDateTime::now_utc().date() - time::Duration::days(days - 1);
        let owner = (!self.actor.role().reaches_every_client()).then(|| self.actor.id());
        let rows = ap_store::TrafficRepo::by_access(self.pool, since, owner).await?;
        Ok(rows
            .into_iter()
            .map(|(id, bytes, last_day)| (id, (bytes, last_day.to_string())))
            .collect())
    }

    /// One access, if this actor may see its client.
    pub async fn access(&self, id: Uuid) -> Result<AnyAccess, ApiError> {
        let found = AccessRepo::by_id(self.pool, id)
            .await?
            .ok_or(ApiError::NotFound)?;
        if self.may_see(found.common().holder()).await? {
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
        if !self.may_see(access.common().holder()).await? {
            return Err(ApiError::NotFound);
        }
        self.refuse_full_node(access).await?;
        AccessRepo::insert(self.pool, access, credential, self.key).await?;
        Ok(())
    }

    /// Refuses an access a node has no room for (0105).
    ///
    /// A WEB node is configured with every access it keeps, and one too many
    /// takes it away from everybody on it. Whose the access is does not
    /// matter: a node carries public links and clients together (0107).
    async fn refuse_full_node(&self, access: &AnyAccess) -> Result<(), ApiError> {
        if !crate::issue::is_web(access) {
            return Ok(());
        }
        let kept = AccessRepo::by_node(self.pool, access.common().node_id())
            .await?
            .iter()
            .filter(|one| one.common().state() != AccessState::Revoked)
            .count() as i64;
        if crate::issue::is_full(true, kept) {
            return Err(ApiError::Conflict("node_full"));
        }
        Ok(())
    }

    /// Puts a public link on the landing page or takes it off (0108).
    pub async fn set_access_listed(&self, id: Uuid, listed: bool) -> Result<(), ApiError> {
        let access = self.access(id).await?;
        if !matches!(access.common().holder(), Holder::Public(_)) {
            return Err(ApiError::Unprocessable("not_a_public_link"));
        }
        AccessRepo::set_listed(self.pool, id, listed).await?;
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

    /// What is running on the nodes this actor may see.
    pub async fn processes(
        &self,
        nodes: &[Uuid],
    ) -> Result<Vec<(Uuid, ap_core::Process)>, ApiError> {
        if !self.actor.role().sees_nodes() {
            return Err(ApiError::NotFound);
        }
        Ok(ap_store::PresenceRepo::processes_of(self.pool, nodes).await?)
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
    ///
    /// The accesses go first. A node marked burned whose accesses still stand
    /// would keep serving them until its cache ran out, which is the opposite
    /// of what the button is for.
    pub async fn burn_node(&self, id: Uuid) -> Result<u64, ApiError> {
        if !self.actor.role().manages_nodes() {
            return Err(ApiError::NotFound);
        }
        self.node(id).await?;
        let withdrawn = AccessRepo::revoke_by_node(self.pool, id).await?;
        NodeRepo::set_state(self.pool, id, NodeState::Burned).await?;
        Ok(withdrawn)
    }

    /// What a node carries, for whoever is about to delete it (0104).
    pub async fn node_carries(&self, id: Uuid) -> Result<ap_store::NodeCarries, ApiError> {
        self.node(id).await?;
        let since = (OffsetDateTime::now_utc() - time::Duration::days(30)).date();
        Ok(AccessRepo::carried_by_node(self.pool, id, since).await?)
    }

    /// Changes the name a node answers to.
    ///
    /// The kind stays what it was: a node serving a recognisable method has no
    /// name to give, and one that hides cannot be left without one. Both are
    /// refused here rather than written and found out later.
    pub async fn rename_node(&self, id: Uuid, domain: Option<Domain>) -> Result<(), ApiError> {
        if !self.actor.role().manages_nodes() {
            return Err(ApiError::NotFound);
        }
        let node = self.node(id).await?;
        // Built and thrown away: what it is for is the refusal it gives when
        // the name does not go with the kind.
        ap_core::NodeKind::from_parts(node.kind().tag(), domain.clone())?;
        NodeRepo::set_name(self.pool, id, domain.as_ref()).await?;
        Ok(())
    }

    /// Sets or clears the address clients reach a node at (0091).
    pub async fn set_node_address(
        &self,
        id: Uuid,
        address: Option<std::net::IpAddr>,
    ) -> Result<(), ApiError> {
        if !self.actor.role().manages_nodes() {
            return Err(ApiError::NotFound);
        }
        self.node(id).await?;
        NodeRepo::set_address(self.pool, id, address).await?;
        Ok(())
    }

    /// Links the operator hands out themselves, which belong to no client.
    ///
    /// Only for roles that reach every client: a reseller sees what is theirs,
    /// and these are nobody's.
    pub async fn public_accesses(&self) -> Result<Vec<AnyAccess>, ApiError> {
        if !self.actor.role().reaches_every_client() {
            return Err(ApiError::NotFound);
        }
        Ok(AccessRepo::public(self.pool).await?)
    }

    /// Sets or clears the sponsorship tag a node carries.
    ///
    /// Separate from registering the node because the tag arrives later:
    /// @MTProxybot issues one for a proxy it can already reach, so the node is
    /// serving before there is a tag to record.
    pub async fn sponsor_node(&self, id: Uuid, ad_tag: Option<AdTag>) -> Result<(), ApiError> {
        if !self.actor.role().manages_nodes() {
            return Err(ApiError::NotFound);
        }
        self.node(id).await?;
        NodeRepo::set_ad_tag(self.pool, id, ad_tag.as_ref()).await?;
        Ok(())
    }

    /// Traffic by day over the last `days`, summed over what this actor may
    /// see.
    ///
    /// A reseller gets the clients they created and nothing else; the public
    /// links, which are nobody's, are not in that sum.
    pub async fn traffic_daily(&self, days: i64) -> Result<Vec<DailyTraffic>, ApiError> {
        let days = days.clamp(1, 366);
        let since = OffsetDateTime::now_utc().date() - time::Duration::days(days - 1);
        let owner = if self.actor.role().reaches_every_client() {
            None
        } else {
            Some(self.actor.id())
        };
        Ok(TrafficRepo::daily(self.pool, since, owner).await?)
    }

    /// The audit log.
    pub async fn audit(&self, limit: Option<i64>) -> Result<Vec<ap_store::AuditEntry>, ApiError> {
        Ok(self.audit_page(limit, 0, None, None).await?.0)
    }

    /// A page of the journal and how many entries the filter matches (0067).
    pub async fn audit_page(
        &self,
        limit: Option<i64>,
        offset: i64,
        prefixes: Option<&[String]>,
        days: Option<i64>,
    ) -> Result<(Vec<ap_store::AuditEntry>, i64), ApiError> {
        if !self.actor.role().reads_audit() {
            return Err(ApiError::NotFound);
        }
        let since = days.map(|days| {
            time::OffsetDateTime::now_utc() - time::Duration::days(days.clamp(1, 3650))
        });
        Ok(AuditRepo::page(self.pool, Self::page(limit), offset.max(0), prefixes, since).await?)
    }

    /// How many entries of each action there have been lately (0067).
    pub async fn audit_counts(&self, days: i64) -> Result<Vec<(String, i64)>, ApiError> {
        if !self.actor.role().reads_audit() {
            return Err(ApiError::NotFound);
        }
        let since = time::OffsetDateTime::now_utc() - time::Duration::days(days.clamp(1, 3650));
        Ok(AuditRepo::counts(self.pool, since).await?)
    }
}
