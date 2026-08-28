use ap_core::{AdTag, Domain, Label, Node, NodeKind, NodeKindTag, NodeState};
use sqlx::{PgPool, Row};
use std::net::IpAddr;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::StoreError;

const COLUMNS: &str = "id, label, kind, domain, address, agent_version, last_seen_at, \
                       state, created_at, ad_tag";

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
    /// It reaches the node when the node next opens a session, and not before.
    /// The panel sends a configuration in answer to a greeting and at no other
    /// time, so an agent holding a live channel goes on serving what it was
    /// given. That is true of every change to what a node serves, withdrawing
    /// an access included.
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
    ))
}
