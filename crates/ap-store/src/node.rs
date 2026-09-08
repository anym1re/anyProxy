use ap_core::{
    AdTag, Domain, Label, Machine, Node, NodeHealth, NodeKind, NodeKindTag, NodeState, Pressure,
};
use sqlx::{PgPool, Row};
use std::net::IpAddr;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::StoreError;

const COLUMNS: &str = "id, label, kind, domain, address, agent_version, last_seen_at, \
                       state, created_at, ad_tag, \
                       health_engine, health_site, health_reach, cert_not_after, \
                       machine_pressure, machine_cpus, machine_memory_used_mb, \
                       machine_memory_limit_mb, machine_memory_stall, machine_cpu_stall, \
                       machine_open_files, machine_file_limit, machine_cpu_percent, \
                       machine_uptime_seconds, machine_connections, machine_rx_bps, \
                       machine_tx_bps, trouble_since";

/// Reads and writes nodes.
pub struct NodeRepo;

impl NodeRepo {
    /// Registers a node.
    pub async fn insert(pool: &PgPool, node: &Node) -> Result<(), StoreError> {
        sqlx::query(
            "insert into node (id, label, kind, domain, address, agent_version, \
             last_seen_at, state, created_at, ad_tag) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(node.id())
        .bind(node.label().as_str())
        .bind(node.kind().tag().as_stored())
        .bind(node.kind().domain().map(Domain::as_str))
        .bind(node.address().map(|address| address.to_string()))
        .bind(node.agent_version())
        .bind(node.last_seen_at())
        .bind(node.state().as_stored())
        .bind(node.created_at())
        .bind(node.ad_tag().map(AdTag::as_str))
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Finds a node by the name an operator knows it by.
    pub async fn by_label(pool: &PgPool, label: &Label) -> Result<Option<Node>, StoreError> {
        let row = sqlx::query(&format!("select {COLUMNS} from node where label = $1"))
            .bind(label.as_str())
            .fetch_optional(pool)
            .await?;
        row.map(read_node).transpose()
    }

    /// One node by its identifier.
    pub async fn by_id(pool: &PgPool, id: Uuid) -> Result<Option<Node>, StoreError> {
        let row = sqlx::query(&format!("select {COLUMNS} from node where id = $1"))
            .bind(id)
            .fetch_optional(pool)
            .await?;
        row.map(read_node).transpose()
    }

    /// Every node, oldest first.
    pub async fn list(pool: &PgPool) -> Result<Vec<Node>, StoreError> {
        let rows = sqlx::query(&format!(
            "select {COLUMNS} from node order by created_at, id"
        ))
        .fetch_all(pool)
        .await?;
        rows.into_iter().map(read_node).collect()
    }

    /// Records what an agent reported during an exchange.
    pub async fn record_contact(
        pool: &PgPool,
        id: Uuid,
        at: OffsetDateTime,
        version: Option<&str>,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "update node set last_seen_at = $2, agent_version = coalesce($3, agent_version) \
             where id = $1",
        )
        .bind(id)
        .bind(at)
        .bind(version)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Changes the name a node answers to.
    ///
    /// The kind is not changed and cannot be: a node serving a recognisable
    /// method has no name to give and one that hides cannot be left without
    /// one, which is what the caller checks before arriving here.
    ///
    /// Renaming a node makes every link already issued for it wrong, because a
    /// link tells the client which name to ask for. That is the operator's
    /// call to make, and the audit log is where it is written down.
    pub async fn set_name(
        pool: &PgPool,
        id: Uuid,
        domain: Option<&Domain>,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query("update node set domain = $2 where id = $1")
            .bind(id)
            .bind(domain.map(Domain::as_str))
            .execute(pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Sets or clears the sponsorship tag a node carries.
    ///
    /// Set after the fact rather than at registration, because that is the
    /// order the tag is obtained in: @MTProxybot issues one for a proxy it can
    /// already reach, so the node has to be serving before there is a tag to
    /// record.
    ///
    /// Changing it changes how the node reaches Telegram: with a tag through
    /// the middle proxies, without one directly.
    ///
    /// It reaches the node on its next heartbeat, which the panel answers with
    /// a fresh configuration whenever what the node should serve has stopped
    /// matching what it was last told.
    pub async fn set_ad_tag(
        pool: &PgPool,
        id: Uuid,
        ad_tag: Option<&AdTag>,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query("update node set ad_tag = $2 where id = $1")
            .bind(id)
            .bind(ad_tag.map(AdTag::as_str))
            .execute(pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    /// A fingerprint of what this node should be serving now.
    ///
    /// Taken from the rows rather than from the rendered configuration, which
    /// opens every credential: this runs on every heartbeat, and opening a
    /// node's credentials twice a minute to learn that nothing changed is work
    /// done for nothing. The credential itself is stood in for by its digest,
    /// which is safe because a credential is never reissued — a different
    /// credential is a different access.
    ///
    /// It must cover everything the configuration carries. A field the
    /// rendering reads and this does not is a change that never reaches the
    /// node, which is the whole fault this exists to close.
    ///
    /// Withdrawn accesses are left out, the same way the configuration leaves
    /// them out, so withdrawing one changes the fingerprint.
    pub async fn serving_digest(pool: &PgPool, id: Uuid) -> Result<Vec<u8>, StoreError> {
        let digest: Option<Vec<u8>> = sqlx::query_scalar(
            "select sha256(convert_to(
                 n.kind || '|' || coalesce(n.domain, '') || '|' || coalesce(n.ad_tag, '')
                 || '|' || coalesce((
                     select string_agg(
                         a.id::text || ':' || a.method || ':' || a.state || ':'
                         || encode(a.credential_digest, 'hex') || ':'
                         || coalesce(a.max_devices::text, ''),
                         '|' order by a.id)
                     from access a
                     where a.node_id = n.id and a.state <> 'revoked'), ''),
                 'UTF8'))
             from node n where n.id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .flatten();
        digest.ok_or(StoreError::Impossible(format!("no node {id}")))
    }

    /// What this node was last sent, as a fingerprint.
    pub async fn served_digest(pool: &PgPool, id: Uuid) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(
            sqlx::query_scalar("select served_digest from node where id = $1")
                .bind(id)
                .fetch_optional(pool)
                .await?
                .flatten(),
        )
    }

    /// Records the fingerprint of the configuration just sent to a node.
    pub async fn set_served_digest(
        pool: &PgPool,
        id: Uuid,
        digest: &[u8],
    ) -> Result<(), StoreError> {
        sqlx::query("update node set served_digest = $2 where id = $1")
            .bind(id)
            .bind(digest)
            .execute(pool)
            .await?;
        Ok(())
    }

    /// Moves a node to a new state. A burned node is never moved out of it.
    pub async fn set_state(pool: &PgPool, id: Uuid, state: NodeState) -> Result<bool, StoreError> {
        let result = sqlx::query("update node set state = $2 where id = $1 and state <> 'burned'")
            .bind(id)
            .bind(state.as_stored())
            .execute(pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }
}

fn read_node(row: sqlx::postgres::PgRow) -> Result<Node, StoreError> {
    let label = Label::try_from(row.try_get::<String, _>("label")?)?;
    let tag = NodeKindTag::from_stored(&row.try_get::<String, _>("kind")?)?;
    let domain = row
        .try_get::<Option<String>, _>("domain")?
        .map(|text| Domain::try_from(text.as_str()))
        .transpose()?;
    let kind = NodeKind::from_parts(tag, domain)?;
    let ad_tag = row
        .try_get::<Option<String>, _>("ad_tag")?
        .map(|text| AdTag::try_from(text.as_str()))
        .transpose()?;
    let address = row
        .try_get::<Option<String>, _>("address")?
        .and_then(|text| text.parse::<IpAddr>().ok());
    // Health is there once the node has said anything at all; before that
    // every word is null and there is no report to hand over.
    let health = NodeHealth {
        engine: row.try_get("health_engine")?,
        site: row.try_get("health_site")?,
        reach: row.try_get("health_reach")?,
        cert_not_after: row.try_get::<Option<OffsetDateTime>, _>("cert_not_after")?,
    };
    let health = (health.engine.is_some() || health.site.is_some() || health.reach.is_some())
        .then_some(health);

    // The machine is known by its word; the figures around it may each be
    // missing on their own, as they are on a node without an engine.
    let machine = row
        .try_get::<Option<String>, _>("machine_pressure")?
        .as_deref()
        .and_then(Pressure::from_stored)
        .map(|pressure| -> Result<Machine, StoreError> {
            Ok(Machine {
                pressure,
                cpus: row.try_get("machine_cpus")?,
                memory_used_mb: row.try_get("machine_memory_used_mb")?,
                memory_limit_mb: row.try_get("machine_memory_limit_mb")?,
                memory_stall: row.try_get("machine_memory_stall")?,
                cpu_stall: row.try_get("machine_cpu_stall")?,
                open_files: row.try_get("machine_open_files")?,
                file_limit: row.try_get("machine_file_limit")?,
                cpu_percent: row.try_get("machine_cpu_percent")?,
                uptime_seconds: row.try_get("machine_uptime_seconds")?,
                connections: row.try_get("machine_connections")?,
                rx_bps: row.try_get("machine_rx_bps")?,
                tx_bps: row.try_get("machine_tx_bps")?,
            })
        })
        .transpose()?;

    Ok(Node::from_parts(
        row.try_get("id")?,
        label,
        kind,
        address,
        row.try_get("agent_version")?,
        row.try_get::<Option<OffsetDateTime>, _>("last_seen_at")?,
        NodeState::from_stored(&row.try_get::<String, _>("state")?)?,
        row.try_get("created_at")?,
        ad_tag,
    )
    .with_health(health)
    .with_machine(machine)
    .with_trouble_since(row.try_get("trouble_since")?))
}
