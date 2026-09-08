use std::net::IpAddr;

use ::time::OffsetDateTime;
use uuid::Uuid;

use crate::{AdTag, Domain, Error, Label, OpenMethod, StealthMethod};

/// What a node exposes to the network.
///
/// One node, one method. Every method is recognisable from outside by someone
/// who looks the right way: an open proxy answers as one on any port, and a
/// forged handshake speaks a name its address does not own. Putting two on one
/// address gives whoever is looking two things to correlate and one address to
/// flag, and separating them by port does not break that link — which is what
/// decision 0004 says and what this makes true of every method rather than
/// only of the masked ones.
///
/// A node that carries a name carries it in the variant, so one that needs a
/// name cannot be built without it. The name means different things by kind
/// and that is the whole of the difference: a node with a forged handshake
/// borrows somebody else's name, and a node with a site of its own answers to
/// a name it holds a certificate for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    /// MTProto behind a forged TLS handshake, on 443.
    FakeTls {
        /// The name the handshake claims, which belongs to somebody else.
        domain: Domain,
    },
    /// MTProto carried inside genuine HTTPS to a site of ours, on 443.
    Web {
        /// The node's own name, the one its certificate is issued to.
        domain: Domain,
    },
    /// Plain MTProto, on its own port and recognisable as what it is.
    Mtproto,
    /// SOCKS5, on its own port.
    Socks5,
    /// HTTP CONNECT and forwarding, on its own port.
    Http,
}

/// The variant of [`NodeKind`] without its payload, for storage and matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeKindTag {
    /// See [`NodeKind::FakeTls`].
    FakeTls,
    /// See [`NodeKind::Web`].
    Web,
    /// See [`NodeKind::Mtproto`].
    Mtproto,
    /// See [`NodeKind::Socks5`].
    Socks5,
    /// See [`NodeKind::Http`].
    Http,
}

/// The single method a node of a given kind serves, on whichever of the two
/// surfaces carries it. The masked surface hides behind a name and the open
/// one does not, which decides the credential and the link but not the rule
/// that there is one method to a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// Behind a name: a forged handshake or a site of our own.
    Masked(StealthMethod),
    /// In the open: MTProto, SOCKS5 or HTTP as themselves.
    Open(OpenMethod),
}

impl NodeKindTag {
    /// The one method this kind serves.
    pub fn served(self) -> Served {
        match self {
            Self::FakeTls => Served::Masked(StealthMethod::FakeTls),
            Self::Web => Served::Masked(StealthMethod::Web),
            Self::Mtproto => Served::Open(OpenMethod::Mtproto),
            Self::Socks5 => Served::Open(OpenMethod::Socks5),
            Self::Http => Served::Open(OpenMethod::Http),
        }
    }

    /// Whether a node of this kind hides behind a name.
    ///
    /// The two masked kinds do: a forged handshake borrows somebody else's
    /// name, and a site of our own answers to one it holds a certificate for.
    /// The other three serve as themselves.
    ///
    /// What follows from it is that their socket is part of the disguise and
    /// is kept open whether or not anyone is being carried behind it.
    pub fn hides(self) -> bool {
        matches!(self, Self::FakeTls | Self::Web)
    }

    /// How an operator chooses this kind: a transport, and whether it hides.
    ///
    /// There are five kinds and four transports, and the difference is one
    /// question. MTProto is offered both ways: behind a forged handshake it
    /// takes 443 and borrows a name, without one it is itself on a port of its
    /// own. The two are different on the wire — different port, different link,
    /// differently visible — so they stay different kinds, and one method to a
    /// host depends on their staying so. An operator does not need that split
    /// to pick a node, and is asked for a transport and a yes or no instead.
    pub fn chosen(self) -> (&'static str, bool) {
        match self {
            Self::FakeTls => ("mtproto", true),
            Self::Mtproto => ("mtproto", false),
            Self::Web => ("web", false),
            Self::Socks5 => ("socks5", false),
            Self::Http => ("http", false),
        }
    }

    /// The kind an operator's choice names.
    ///
    /// Masking is refused for everything but MTProto rather than ignored: WEB
    /// is carried inside a site that is really there and hides by construction,
    /// and SOCKS5 and HTTP do not hide at all. Accepting the word and doing
    /// nothing with it would promise cover that is not there.
    pub fn from_chosen(transport: &str, masked: bool) -> Result<Self, Error> {
        match (transport, masked) {
            ("mtproto", true) => Ok(Self::FakeTls),
            ("mtproto", false) => Ok(Self::Mtproto),
            ("web", false) => Ok(Self::Web),
            ("socks5", false) => Ok(Self::Socks5),
            ("http", false) => Ok(Self::Http),
            ("web" | "socks5" | "http", true) => Err(Error::MaskingNotOffered),
            _ => Err(Error::StoredValue),
        }
    }
}

impl NodeKind {
    /// Returns the variant without its payload.
    pub fn tag(&self) -> NodeKindTag {
        match self {
            Self::FakeTls { .. } => NodeKindTag::FakeTls,
            Self::Web { .. } => NodeKindTag::Web,
            Self::Mtproto => NodeKindTag::Mtproto,
            Self::Socks5 => NodeKindTag::Socks5,
            Self::Http => NodeKindTag::Http,
        }
    }

    /// The name this node answers to, when it answers to one.
    ///
    /// Borrowed by a node with a forged handshake, its own by a node with a
    /// site. The kind says which.
    pub fn domain(&self) -> Option<&Domain> {
        match self {
            Self::FakeTls { domain } | Self::Web { domain } => Some(domain),
            _ => None,
        }
    }

    /// Rebuilds the kind from a stored tag and name, rejecting the pairs the
    /// type itself cannot express.
    pub fn from_parts(tag: NodeKindTag, domain: Option<Domain>) -> Result<Self, Error> {
        match (tag, domain) {
            (NodeKindTag::FakeTls, Some(domain)) => Ok(Self::FakeTls { domain }),
            (NodeKindTag::Web, Some(domain)) => Ok(Self::Web { domain }),
            (NodeKindTag::FakeTls | NodeKindTag::Web, None) => Err(Error::StealthWithoutDomain),
            (_, Some(_)) => Err(Error::OpenWithDomain),
            (NodeKindTag::Mtproto, None) => Ok(Self::Mtproto),
            (NodeKindTag::Socks5, None) => Ok(Self::Socks5),
            (NodeKindTag::Http, None) => Ok(Self::Http),
        }
    }
}

/// Lifecycle of a node as the panel sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeState {
    /// Enrolment code issued, the agent has not connected yet.
    Pending,
    /// Serving clients.
    Active,
    /// Kept in the panel, serving nobody.
    Disabled,
    /// Destroyed. Certificate revoked, accesses withdrawn, not reversible.
    Burned,
}

/// How short the machine under a node is, in the node's own word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pressure {
    /// Nothing is waiting for anything.
    Calm,
    /// Something is short; the node has eased off what it can.
    Strained,
    /// The next client is the one that fails.
    Critical,
}

impl Pressure {
    /// The word as the node reports it and the panel stores it.
    pub fn as_stored(self) -> &'static str {
        match self {
            Self::Calm => "calm",
            Self::Strained => "strained",
            Self::Critical => "critical",
        }
    }

    /// Reads the word. Anything else is not a pressure and is not kept.
    pub fn from_stored(text: &str) -> Option<Self> {
        match text {
            "calm" => Some(Self::Calm),
            "strained" => Some(Self::Strained),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    /// Whether an operator should be looking at this node.
    pub fn wants_attention(self) -> bool {
        !matches!(self, Self::Calm)
    }
}

/// What a node last said about the machine under it.
#[derive(Debug, Clone, PartialEq)]
pub struct Machine {
    /// The one word.
    pub pressure: Pressure,
    /// Processors the node may run on.
    pub cpus: Option<i32>,
    /// Megabytes the node's cgroup is using.
    pub memory_used_mb: Option<i64>,
    /// Megabytes it may use before being throttled.
    pub memory_limit_mb: Option<i64>,
    /// Share of the last ten seconds spent waiting for memory, in percent.
    pub memory_stall: Option<f32>,
    /// Share of the last ten seconds spent waiting for a processor.
    pub cpu_stall: Option<f32>,
    /// Files the engine had open.
    pub open_files: Option<i64>,
    /// Files it may have open.
    pub file_limit: Option<i64>,
    /// Share of the processors the node is using, in percent.
    pub cpu_percent: Option<f32>,
    /// How long its agent has been running, in seconds.
    pub uptime_seconds: Option<i64>,
    /// Connections established on the ports it serves.
    pub connections: Option<i64>,
    /// Bytes a second on its interfaces, in and out.
    pub rx_bps: Option<i64>,
    pub tx_bps: Option<i64>,
}

/// One process on a node, as the agent last saw it.
#[derive(Debug, Clone, PartialEq)]
pub struct Process {
    /// The name the operator knows it by.
    pub name: String,
    /// Share of the processors it is using, in percent.
    pub cpu_percent: Option<f32>,
    /// Resident memory, in megabytes.
    pub memory_mb: i64,
    /// How many times the agent has started it again.
    pub restarts: i32,
}

/// The three words a node says about itself, and its certificate's life.
///
/// Each word is kept as the node said it: the panel stores them and decides
/// by them, and does not turn them into anything else on the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeHealth {
    /// Whether the proxy engine was running.
    pub engine: Option<String>,
    /// Whether the cover site answered a visitor.
    pub site: Option<String>,
    /// Whether the node could reach Telegram.
    pub reach: Option<String>,
    /// When the node's certificate stops being valid.
    pub cert_not_after: Option<OffsetDateTime>,
}

/// A server that carries client traffic.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    id: Uuid,
    label: Label,
    kind: NodeKind,
    address: Option<IpAddr>,
    agent_version: Option<String>,
    last_seen_at: Option<OffsetDateTime>,
    state: NodeState,
    created_at: OffsetDateTime,
    ad_tag: Option<AdTag>,
    health: Option<NodeHealth>,
    machine: Option<Machine>,
    /// When the health it reports stopped being well (0071).
    trouble_since: Option<OffsetDateTime>,
}

impl Node {
    /// Registers a node that has not been enrolled yet.
    pub fn new(label: Label, kind: NodeKind, created_at: OffsetDateTime) -> Self {
        Self {
            id: Uuid::now_v7(),
            label,
            kind,
            address: None,
            agent_version: None,
            last_seen_at: None,
            state: NodeState::Pending,
            created_at,
            ad_tag: None,
            health: None,
            machine: None,
            trouble_since: None,
        }
    }

    /// The same node, knowing when its trouble started (0071).
    #[must_use]
    pub fn with_trouble_since(mut self, since: Option<OffsetDateTime>) -> Self {
        self.trouble_since = since;
        self
    }

    /// When what is wrong with it started, when something is.
    pub fn trouble_since(&self) -> Option<OffsetDateTime> {
        self.trouble_since
    }

    /// The same node, carrying a sponsorship tag.
    #[must_use]
    pub fn with_ad_tag(mut self, ad_tag: Option<AdTag>) -> Self {
        self.ad_tag = ad_tag;
        self
    }

    /// Rebuilds a node from a stored row.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: Uuid,
        label: Label,
        kind: NodeKind,
        address: Option<IpAddr>,
        agent_version: Option<String>,
        last_seen_at: Option<OffsetDateTime>,
        state: NodeState,
        created_at: OffsetDateTime,
        ad_tag: Option<AdTag>,
    ) -> Self {
        Self {
            id,
            label,
            kind,
            address,
            agent_version,
            last_seen_at,
            state,
            created_at,
            ad_tag,
            health: None,
            machine: None,
            trouble_since: None,
        }
    }

    /// Adds what the node last said about itself.
    pub fn with_health(mut self, health: Option<NodeHealth>) -> Self {
        self.health = health;
        self
    }

    /// Adds what the node last said about the machine under it.
    pub fn with_machine(mut self, machine: Option<Machine>) -> Self {
        self.machine = machine;
        self
    }

    /// What the node last said about itself, if it has said anything.
    pub fn health(&self) -> Option<&NodeHealth> {
        self.health.as_ref()
    }

    /// What the node last said about the machine under it.
    pub fn machine(&self) -> Option<&Machine> {
        self.machine.as_ref()
    }

    /// Whether an operator should be looking at this node: something it
    /// reported is not right, or the machine under it is short of something.
    pub fn wants_attention(&self) -> bool {
        let health_says_so = self.health.as_ref().is_some_and(|health| {
            health.engine.as_deref() == Some("down")
                || health.site.as_deref() == Some("down")
                || health.reach.as_deref() == Some("blocked")
        });
        let machine_says_so = self
            .machine
            .as_ref()
            .is_some_and(|machine| machine.pressure.wants_attention());
        health_says_so || machine_says_so
    }

    /// The sponsorship tag this node carries, when it carries one.
    ///
    /// Absent on a node that is not sponsored, which is the ordinary case and
    /// the cheaper one: the tag is only counted when traffic goes through
    /// Telegram's middle proxies, so a node without one goes direct.
    pub fn ad_tag(&self) -> Option<&AdTag> {
        self.ad_tag.as_ref()
    }

    /// Identifier assigned at registration.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Operator-facing name.
    pub fn label(&self) -> &Label {
        &self.label
    }

    /// What the node exposes to the network.
    pub fn kind(&self) -> &NodeKind {
        &self.kind
    }

    /// Address of the node itself, never of a client.
    pub fn address(&self) -> Option<IpAddr> {
        self.address
    }

    /// Agent build the node last reported.
    pub fn agent_version(&self) -> Option<&str> {
        self.agent_version.as_deref()
    }

    /// When the agent last completed an exchange with the panel.
    pub fn last_seen_at(&self) -> Option<OffsetDateTime> {
        self.last_seen_at
    }

    /// Current lifecycle state.
    pub fn state(&self) -> NodeState {
        self.state
    }

    /// When the node was registered.
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Records what the agent reported during an exchange.
    pub fn record_contact(&mut self, at: OffsetDateTime, version: Option<String>) {
        self.last_seen_at = Some(at);
        if let Some(version) = version {
            self.agent_version = Some(version);
        }
    }

    /// Sets the address clients connect to.
    pub fn set_address(&mut self, address: IpAddr) {
        self.address = Some(address);
    }

    /// Moves the node to a new state. A burned node never leaves that state.
    pub fn set_state(&mut self, state: NodeState) {
        if self.state != NodeState::Burned {
            self.state = state;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain() -> Domain {
        Domain::try_from("cover.example.com").unwrap()
    }

    fn label() -> Label {
        Label::try_from("berlin").unwrap()
    }

    #[test]
    fn a_node_that_answers_to_a_name_always_carries_one() {
        for (kind, tag) in [
            (NodeKind::FakeTls { domain: domain() }, NodeKindTag::FakeTls),
            (NodeKind::Web { domain: domain() }, NodeKindTag::Web),
        ] {
            assert_eq!(kind.tag(), tag);
            assert_eq!(kind.domain(), Some(&domain()));
        }
    }

    #[test]
    fn every_kind_names_the_one_method_it_serves() {
        for (tag, method) in [
            (NodeKindTag::FakeTls, "faketls"),
            (NodeKindTag::Web, "web"),
            (NodeKindTag::Mtproto, "mtproto"),
            (NodeKindTag::Socks5, "socks5"),
            (NodeKindTag::Http, "http"),
        ] {
            assert_eq!(tag.as_stored(), method);
        }
    }

    #[test]
    fn a_node_that_answers_to_nobody_carries_no_name() {
        let kind = NodeKind::Socks5;
        assert_eq!(kind.tag(), NodeKindTag::Socks5);
        assert_eq!(kind.domain(), None);
    }

    #[test]
    fn a_name_a_kind_needs_is_required_at_the_boundary() {
        assert_eq!(
            NodeKind::from_parts(NodeKindTag::FakeTls, None),
            Err(Error::StealthWithoutDomain)
        );
    }

    #[test]
    fn a_name_a_kind_has_no_use_for_is_refused() {
        assert_eq!(
            NodeKind::from_parts(NodeKindTag::Socks5, Some(domain())),
            Err(Error::OpenWithDomain)
        );
    }

    #[test]
    fn valid_pairs_are_rebuilt() {
        assert_eq!(
            NodeKind::from_parts(NodeKindTag::Web, Some(domain())),
            Ok(NodeKind::Web { domain: domain() })
        );
        assert_eq!(
            NodeKind::from_parts(NodeKindTag::Socks5, None),
            Ok(NodeKind::Socks5)
        );
    }

    #[test]
    fn a_new_node_waits_for_its_agent() {
        let node = Node::new(label(), NodeKind::Socks5, OffsetDateTime::UNIX_EPOCH);
        assert_eq!(node.state(), NodeState::Pending);
        assert_eq!(node.last_seen_at(), None);
        assert_eq!(node.address(), None);
    }

    #[test]
    fn a_burned_node_stays_burned() {
        let mut node = Node::new(label(), NodeKind::Socks5, OffsetDateTime::UNIX_EPOCH);
        node.set_state(NodeState::Burned);
        node.set_state(NodeState::Active);
        assert_eq!(node.state(), NodeState::Burned);
    }
}

#[cfg(test)]
mod chosen_tests {
    use super::*;

    #[test]
    fn every_kind_survives_being_offered_and_chosen_again() {
        for tag in [
            NodeKindTag::FakeTls,
            NodeKindTag::Web,
            NodeKindTag::Mtproto,
            NodeKindTag::Socks5,
            NodeKindTag::Http,
        ] {
            let (transport, masked) = tag.chosen();
            assert_eq!(NodeKindTag::from_chosen(transport, masked), Ok(tag));
        }
    }

    #[test]
    fn the_four_transports_are_what_an_operator_picks_from() {
        // Five kinds, four transports: mtproto is the one offered both ways.
        let mut offered: Vec<&str> = [
            NodeKindTag::FakeTls,
            NodeKindTag::Web,
            NodeKindTag::Mtproto,
            NodeKindTag::Socks5,
            NodeKindTag::Http,
        ]
        .into_iter()
        .map(|tag| tag.chosen().0)
        .collect();
        offered.sort_unstable();
        offered.dedup();
        assert_eq!(offered, vec!["http", "mtproto", "socks5", "web"]);
    }

    #[test]
    fn masking_the_forged_handshake_is_what_tells_the_two_mtproto_kinds_apart() {
        assert_eq!(
            NodeKindTag::from_chosen("mtproto", true),
            Ok(NodeKindTag::FakeTls)
        );
        assert_eq!(
            NodeKindTag::from_chosen("mtproto", false),
            Ok(NodeKindTag::Mtproto)
        );
    }

    #[test]
    fn masking_is_refused_where_it_is_not_offered() {
        // Not ignored: accepting the word would promise cover that is not there.
        for transport in ["web", "socks5", "http"] {
            assert_eq!(
                NodeKindTag::from_chosen(transport, true),
                Err(Error::MaskingNotOffered),
                "{transport} accepted masking"
            );
        }
    }

    #[test]
    fn the_kinds_are_not_transports_an_operator_can_name() {
        // `faketls` is how the kind is stored, not how it is chosen.
        assert_eq!(
            NodeKindTag::from_chosen("faketls", false),
            Err(Error::StoredValue)
        );
    }
}
