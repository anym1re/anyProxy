//! Coming to the service through the bot (0105, 0106).
//!
//! An account that writes to the bot and belongs to nobody is given a client
//! of its own, and that client an access on every node that can take one.
//! Nothing here speaks: what the bot says about it is in `talk`.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ap_core::{AccessCommon, Client, ClientState, Holder, Label, Node, NodeKindTag, NodeState};
use ap_store::{AccessRepo, BotRepo, ClientRepo, NodeLoad, NodeRepo};
use rand::{RngCore, rng};
use time::OffsetDateTime;
use uuid::Uuid;

use super::talk::{Incoming, record, sealed_account};
use crate::handout::host_of;
use crate::issue::{for_node, is_full};
use crate::settings::Settings;
use crate::{ApiError, AppState};

/// Most clients the bot makes in an hour. A script walking through accounts
/// would otherwise make clients and accesses by the thousand.
const PER_HOUR: usize = 30;

/// How many have signed up lately (0105).
///
/// Kept in memory, by the one panel that answers the bot: what a restart
/// forgets is at most an hour of counting, and a count in the database would
/// be a query in front of every sign-up to guard against a restart.
#[derive(Debug, Default)]
pub struct Pace {
    recent: Mutex<VecDeque<Instant>>,
}

impl Pace {
    /// Whether one more may sign up now. Counted when it may.
    pub(crate) fn admit(&self) -> bool {
        self.admit_at(Instant::now())
    }

    fn admit_at(&self, now: Instant) -> bool {
        let Ok(mut recent) = self.recent.lock() else {
            return false;
        };
        while recent
            .front()
            .is_some_and(|at| now.duration_since(*at) >= Duration::from_secs(3600))
        {
            recent.pop_front();
        }
        if recent.len() >= PER_HOUR {
            return false;
        }
        recent.push_back(now);
        true
    }
}

/// What a client's name is drawn from: no letter or digit that reads as
/// another one when a person copies it by eye.
const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

/// How an account that nobody had tied came in.
pub(crate) enum Arrival {
    /// A client was made for it just now.
    Made(Client),
    /// It had signed up before, untied itself, and is with its client again.
    Back(Client),
    /// Too many have signed up this hour; nobody was made.
    Later,
}

/// Takes in an account nobody has tied: back to the client it signed up as,
/// or to a new one.
pub(crate) async fn arrive(
    state: &AppState,
    incoming: &Incoming,
    digest: &[u8],
    settings: &Settings,
) -> Result<Arrival, ApiError> {
    let now = OffsetDateTime::now_utc();
    let account = sealed_account(state, incoming)?;

    if let Some(client) = BotRepo::signed_up_as(state.pool(), digest).await? {
        BotRepo::link(state.pool(), client.id(), digest, &account, now).await?;
        record(
            state,
            "bot.linked",
            client.label().as_str(),
            serde_json::json!({ "again": true }),
        )
        .await?;
        return Ok(Arrival::Back(client));
    }

    if !state.signups().admit() {
        return Ok(Arrival::Later);
    }

    let client = make(state, digest, incoming, settings, now).await?;
    record(
        state,
        "bot.signup",
        client.label().as_str(),
        serde_json::json!({}),
    )
    .await?;
    if top_up(state, &client).await? == 0 {
        // Made, and with nothing to connect through: an operator finds the
        // person here and in the list, with no access beside the name.
        record(
            state,
            "bot.signup.waiting",
            client.label().as_str(),
            serde_json::json!({}),
        )
        .await?;
    }
    Ok(Arrival::Made(client))
}

/// Makes the client, under a name of its own. The name says nothing about
/// the account: the journal names a client by it and is not sealed (0103).
async fn make(
    state: &AppState,
    digest: &[u8],
    incoming: &Incoming,
    settings: &Settings,
    now: OffsetDateTime,
) -> Result<Client, ApiError> {
    let account = sealed_account(state, incoming)?;
    let gigabytes = settings.number("bot_signup_quota_gb");
    let days = settings.number("bot_signup_days");
    for _ in 0..5 {
        let mut client = Client::new(fresh_label()?, now).with_bot_origin(true);
        if gigabytes > 0 {
            client = client.with_quota(gigabytes.saturating_mul(1024 * 1024 * 1024))?;
        }
        if days > 0 {
            client = client.with_expiry(now + time::Duration::days(days));
        }
        match BotRepo::sign_up(state.pool(), &client, digest, &account).await {
            Ok(()) => {
                // As the database has it, with the tie and the account on it.
                return Ok(ClientRepo::by_id(state.pool(), client.id())
                    .await?
                    .unwrap_or(client));
            }
            // The name was taken: another one.
            Err(error) if error.is_constraint_violation() => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(ApiError::Internal("signup_name"))
}

fn fresh_label() -> Result<Label, ApiError> {
    let mut bytes = [0u8; 6];
    rng().fill_bytes(&mut bytes);
    let tail: String = bytes
        .iter()
        .map(|byte| ALPHABET[usize::from(*byte) % ALPHABET.len()] as char)
        .collect();
    Ok(Label::try_from(format!("tg-{tail}").as_str())?)
}

/// Gives a client the bot made an access on every node that can take one and
/// that it is not on yet (0106). How many were given.
///
/// Called whenever the person asks for their links, so a node that appeared
/// since is theirs from the next time they ask, and nobody who stopped
/// asking is carried on a node they will never use. A client an operator
/// made is left with what the operator gave it.
pub(crate) async fn top_up(state: &AppState, client: &Client) -> Result<usize, ApiError> {
    if !client.came_through_bot() || client.state() != ClientState::Active {
        return Ok(0);
    }
    let settings = Settings::read(state.pool()).await?;
    if !state.signup_open(&settings) {
        return Ok(0);
    }
    let now = OffsetDateTime::now_utc();
    let silence = time::Duration::minutes(settings.number("silence_minutes").max(1));
    let devices = settings.number("bot_signup_devices");
    let loads: HashMap<Uuid, NodeLoad> = AccessRepo::loads(state.pool(), client.id())
        .await?
        .into_iter()
        .map(|load| (load.node_id, load))
        .collect();

    let mut given = 0;
    for node in NodeRepo::list(state.pool()).await? {
        let load = loads.get(&node.id()).copied().unwrap_or_default();
        if !takes(&node, &load, now, silence) {
            continue;
        }
        let mut common = AccessCommon::new(Holder::Client(client.id()), node.id(), now);
        if let Ok(devices @ 1..) = i32::try_from(devices) {
            common = common.with_max_devices(devices)?;
        }
        let (access, credential) = for_node(&node, common, None)?;
        AccessRepo::insert(state.pool(), &access, &credential, state.key()).await?;
        record(
            state,
            "access.created",
            &access.common().id().to_string(),
            serde_json::json!({
                "method": serde_json::Value::Null,
                "holder": "client",
                "name": serde_json::Value::Null,
            }),
        )
        .await?;
        given += 1;
    }
    Ok(given)
}

/// Whether a node can be given one more client, and should be.
///
/// In service, heard from within the silence the panel allows, saying it is
/// well, with a name or an address a link can be built on; not full; and not
/// one this client is on already. What else the node carries — clients, a
/// public link, both — does not matter (0107).
fn takes(node: &Node, load: &NodeLoad, now: OffsetDateTime, silence: time::Duration) -> bool {
    node.state() == NodeState::Active
        && node
            .last_seen_at()
            .is_some_and(|seen| now - seen <= silence)
        && node.health().is_some()
        && !node.wants_attention()
        && host_of(node).is_some()
        && !load.held
        && !is_full(node.kind().tag() == NodeKindTag::Web, load.kept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ap_core::{Domain, NodeHealth, NodeKind};

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    fn well() -> NodeHealth {
        NodeHealth {
            engine: Some("up".to_owned()),
            site: Some("up".to_owned()),
            reach: Some("open".to_owned()),
            cert_not_after: None,
        }
    }

    /// A node in service that called in a minute ago and says it is well.
    fn a_node(kind: NodeKind) -> Node {
        let mut node = Node::new(Label::try_from("n1").unwrap(), kind, at(0));
        node.set_state(NodeState::Active);
        node.set_address("203.0.113.7".parse().unwrap());
        node.record_contact(at(940), None);
        node.with_health(Some(well()))
    }

    fn masked() -> NodeKind {
        NodeKind::from_parts(
            NodeKindTag::FakeTls,
            Some(Domain::try_from("cover.example.com").unwrap()),
        )
        .unwrap()
    }

    fn web() -> NodeKind {
        NodeKind::from_parts(
            NodeKindTag::Web,
            Some(Domain::try_from("site.example.com").unwrap()),
        )
        .unwrap()
    }

    const FIVE_MINUTES: time::Duration = time::Duration::minutes(5);

    #[test]
    fn a_node_in_service_that_is_well_takes_a_client() {
        assert!(takes(
            &a_node(masked()),
            &NodeLoad::default(),
            at(1000),
            FIVE_MINUTES
        ));
    }

    #[test]
    fn a_node_that_is_not_in_service_or_has_gone_quiet_does_not() {
        let mut pending = a_node(masked());
        pending.set_state(NodeState::Pending);
        assert!(!takes(
            &pending,
            &NodeLoad::default(),
            at(1000),
            FIVE_MINUTES
        ));

        let mut burned = a_node(masked());
        burned.set_state(NodeState::Burned);
        assert!(!takes(
            &burned,
            &NodeLoad::default(),
            at(1000),
            FIVE_MINUTES
        ));

        // Last heard from at 940; an hour later that is silence.
        assert!(!takes(
            &a_node(masked()),
            &NodeLoad::default(),
            at(940 + 3600),
            FIVE_MINUTES
        ));
    }

    #[test]
    fn a_node_that_never_reported_or_reports_trouble_does_not() {
        let silent = a_node(masked()).with_health(None);
        assert!(!takes(
            &silent,
            &NodeLoad::default(),
            at(1000),
            FIVE_MINUTES
        ));

        let mut sick = well();
        sick.reach = Some("blocked".to_owned());
        let blocked = a_node(masked()).with_health(Some(sick));
        assert!(!takes(
            &blocked,
            &NodeLoad::default(),
            at(1000),
            FIVE_MINUTES
        ));
    }

    #[test]
    fn a_client_is_not_given_a_second_access_on_one_node() {
        let load = NodeLoad {
            held: true,
            kept: 1,
            ..NodeLoad::default()
        };
        assert!(!takes(&a_node(masked()), &load, at(1000), FIVE_MINUTES));
    }

    #[test]
    fn a_node_that_carries_a_public_link_takes_clients_too() {
        // Kept by the node, whoever holds them: a public link is one access.
        let published = NodeLoad {
            kept: 1,
            ..NodeLoad::default()
        };
        assert!(takes(&a_node(masked()), &published, at(1000), FIVE_MINUTES));
    }

    #[test]
    fn a_web_node_stops_at_its_ceiling_and_the_others_do_not() {
        let full = NodeLoad {
            kept: 32,
            ..NodeLoad::default()
        };
        assert!(!takes(&a_node(web()), &full, at(1000), FIVE_MINUTES));
        assert!(takes(&a_node(masked()), &full, at(1000), FIVE_MINUTES));
    }

    #[test]
    fn the_pace_holds_at_thirty_an_hour_and_lets_go_after_it() {
        let pace = Pace::default();
        let start = Instant::now();
        for _ in 0..PER_HOUR {
            assert!(pace.admit_at(start));
        }
        assert!(!pace.admit_at(start + Duration::from_secs(1800)));
        assert!(pace.admit_at(start + Duration::from_secs(3600)));
    }

    #[test]
    fn a_name_the_bot_makes_is_a_name_the_panel_takes() {
        for _ in 0..200 {
            let label = fresh_label().unwrap();
            assert!(label.as_str().starts_with("tg-"));
            assert_eq!(label.as_str().len(), 9);
        }
    }
}
