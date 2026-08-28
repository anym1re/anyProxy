use std::net::IpAddr;

use ::time::OffsetDateTime;
use uuid::Uuid;

use crate::{Domain, Error, Label, OpenMethod, StealthMethod};

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

/// A server that carries client traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    id: Uuid,
    label: Label,
    kind: NodeKind,
    address: Option<IpAddr>,
    agent_version: Option<String>,
    last_seen_at: Option<OffsetDateTime>,
    state: NodeState,
    created_at: OffsetDateTime,
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
        }
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
        }
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
