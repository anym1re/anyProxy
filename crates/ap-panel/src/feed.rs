//! The feed the public site reads (0091).
//!
//! A separate listener with one route. It is not mounted on the REST router on
//! purpose: whoever can reach the feed must not thereby reach the sign-in or
//! the setup form, and the convention check refuses a `public-links` route in
//! `routes.rs` so that stays true.
//!
//! What it carries is rendered here, by the process that holds the key. The
//! site gets strings and opens nothing.

use ap_core::{AccessState, Holder, NodeState, Served, StealthMethod};
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use time::OffsetDateTime;

use crate::AppState;
use crate::handout::Handout;

/// Builds the feed router: one route and nothing else.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/public-links", get(public_links))
        .with_state(state)
}

/// One published link, as the site is told about it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(untagged)]
pub enum PublicLink {
    /// A method with a `t.me` link form.
    Link {
        /// The name the operator gave the link.
        name: String,
        /// The method, as stored: `faketls`, `web` or `mtproto`.
        method: &'static str,
        /// The link itself.
        link: String,
    },
    /// A method Telegram takes as host, port and an account.
    Account {
        /// The name the operator gave the link.
        name: String,
        /// The method, as stored: `socks5` or `http`.
        method: &'static str,
        /// The node's address.
        host: String,
        /// The port the method is served on.
        port: u16,
        /// Account name.
        user: String,
        /// Account password.
        password: String,
    },
}

/// Every link the site may show, rendered.
///
/// A link is in the feed only when everything about it says it is served:
/// public by holder, active, within its term and its allowance, on a node
/// that is active and has what the link needs. Anything else is left out
/// rather than shown with a state — the site has no use for a link that does
/// not work, and a visitor has less.
///
/// Two queries for the whole list — the links with their credentials, and
/// the nodes — and one more for each link that carries an allowance. Read
/// one link at a time it was three round trips per link, and over a tunnel
/// a few dozen links took longer than the site waits for an answer.
pub async fn published(state: &AppState) -> Result<Vec<PublicLink>, crate::ApiError> {
    let pool = state.pool();
    let now = OffsetDateTime::now_utc();
    let mut links = Vec::new();

    let nodes: std::collections::HashMap<uuid::Uuid, ap_core::Node> =
        ap_store::NodeRepo::list(pool)
            .await?
            .into_iter()
            .map(|node| (node.id(), node))
            .collect();

    for (access, credential) in
        ap_store::AccessRepo::public_active_with_credentials(pool, state.key()).await?
    {
        let common = access.common();
        let Holder::Public(name) = common.holder() else {
            continue;
        };
        if common.state() != AccessState::Active {
            continue;
        }
        if common.expires_at().is_some_and(|until| until <= now) {
            continue;
        }
        let Some(node) = nodes.get(&common.node_id()) else {
            continue;
        };
        if node.state() != NodeState::Active {
            continue;
        }
        if let Some(ceiling) = common.quota_bytes() {
            let spent = ap_store::TrafficRepo::for_access(pool, common.id())
                .await?
                .total();
            if spent >= ceiling {
                continue;
            }
        }

        // The host a visitor is told to dial. A web node is dialled by its
        // own name; every other kind by the address the operator set (0091),
        // and a forged handshake borrows its name from somebody else, so that
        // name is never the host. Without one there is no link to show.
        let host = match (node.kind().tag().served(), node.kind().domain()) {
            (Served::Masked(StealthMethod::Web), Some(domain)) => domain.as_str().to_owned(),
            _ => match node.address() {
                Some(address) => address.to_string(),
                None => continue,
            },
        };
        // Rendered where the link endpoint and the bot render theirs (0088).
        // A credential of the wrong shape for its method cannot become a link
        // that works, and is left out rather than shown.
        let Ok(handout) = crate::handout::handout(&access, &credential, node.kind(), &host) else {
            continue;
        };
        links.push(match handout {
            Handout::Link { link, method } => PublicLink::Link {
                name: name.as_str().to_owned(),
                method,
                link,
            },
            Handout::Account {
                host,
                port,
                user,
                password,
                method,
            } => PublicLink::Account {
                name: name.as_str().to_owned(),
                method,
                host,
                port,
                user,
                password,
            },
        });
    }

    Ok(links)
}

async fn public_links(State(state): State<AppState>) -> Result<Response, crate::ApiError> {
    let links = published(&state).await?;
    Ok((
        StatusCode::OK,
        [("cache-control", "no-store")],
        axum::Json(serde_json::json!({ "links": links })),
    )
        .into_response())
}
