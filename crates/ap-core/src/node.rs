use std::net::IpAddr;

use ::time::OffsetDateTime;
use uuid::Uuid;

use crate::{Domain, Error, Label};

/// What a node exposes to the network.
///
/// A stealth node carries its domain in the variant, so a node that hides
/// behind a cover site without having one cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    /// Port 443 only: FakeTLS, WEB and the cover site behind one domain.
    Stealth {
        /// Hostname the cover site and the clients share.
        domain: Domain,
    },
    /// Unmasked methods, each on its own port.
    Open,
}

/// The variant of [`NodeKind`] without its payload, for storage and matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeKindTag {
    /// See [`NodeKind::Stealth`].
    Stealth,
    /// See [`NodeKind::Open`].
    Open,
}

impl NodeKind {
    /// Returns the variant without its payload.
    pub fn tag(&self) -> NodeKindTag {
        match self {
            Self::Stealth { .. } => NodeKindTag::Stealth,
            Self::Open => NodeKindTag::Open,
        }
    }

    /// Borrows the domain of a stealth node.
    pub fn domain(&self) -> Option<&Domain> {
        match self {
            Self::Stealth { domain } => Some(domain),
            Self::Open => None,
        }
    }

    /// Rebuilds the kind from a stored tag and domain, rejecting the two
    /// combinations the type itself cannot express.
    pub fn from_parts(tag: NodeKindTag, domain: Option<Domain>) -> Result<Self, Error> {
        match (tag, domain) {
            (NodeKindTag::Stealth, Some(domain)) => Ok(Self::Stealth { domain }),
            (NodeKindTag::Stealth, None) => Err(Error::StealthWithoutDomain),
            (NodeKindTag::Open, None) => Ok(Self::Open),
            (NodeKindTag::Open, Some(_)) => Err(Error::OpenWithDomain),
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
    fn a_stealth_node_always_carries_a_domain() {
        let kind = NodeKind::Stealth { domain: domain() };
        assert_eq!(kind.tag(), NodeKindTag::Stealth);
        assert_eq!(kind.domain(), Some(&domain()));
    }

    #[test]
    fn an_open_node_never_carries_a_domain() {
        let kind = NodeKind::Open;
        assert_eq!(kind.tag(), NodeKindTag::Open);
        assert_eq!(kind.domain(), None);
    }

    #[test]
    fn stealth_without_a_domain_is_rejected_at_the_boundary() {
        assert_eq!(
            NodeKind::from_parts(NodeKindTag::Stealth, None),
            Err(Error::StealthWithoutDomain)
        );
    }

    #[test]
    fn open_with_a_domain_is_rejected_at_the_boundary() {
        assert_eq!(
            NodeKind::from_parts(NodeKindTag::Open, Some(domain())),
            Err(Error::OpenWithDomain)
        );
    }

    #[test]
    fn valid_pairs_are_rebuilt() {
        assert_eq!(
            NodeKind::from_parts(NodeKindTag::Stealth, Some(domain())),
            Ok(NodeKind::Stealth { domain: domain() })
        );
        assert_eq!(
            NodeKind::from_parts(NodeKindTag::Open, None),
            Ok(NodeKind::Open)
        );
    }

    #[test]
    fn a_new_node_waits_for_its_agent() {
        let node = Node::new(label(), NodeKind::Open, OffsetDateTime::UNIX_EPOCH);
        assert_eq!(node.state(), NodeState::Pending);
        assert_eq!(node.last_seen_at(), None);
        assert_eq!(node.address(), None);
    }

    #[test]
    fn a_burned_node_stays_burned() {
        let mut node = Node::new(label(), NodeKind::Open, OffsetDateTime::UNIX_EPOCH);
        node.set_state(NodeState::Burned);
        node.set_state(NodeState::Active);
        assert_eq!(node.state(), NodeState::Burned);
    }
}
