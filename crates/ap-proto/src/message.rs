use serde::{Deserialize, Serialize};

/// Highest protocol version this build implements.
pub const PROTOCOL_VERSION: u32 = 1;

/// Everything the panel and an agent say to each other.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum Message {
    /// Agent opens a connection.
    Hello(Hello),
    /// Panel accepts the connection and hands over the cache key.
    Welcome(Welcome),
    /// Agent presents an enrolment code.
    Enroll(Enroll),
    /// Panel returns a signed certificate.
    Enrolled(Enrolled),
    /// Panel sends the whole state of a node.
    Config(Config),
    /// Agent reports what it did with a revision.
    Applied(Applied),
    /// Agent reports traffic, device counts and health.
    Telemetry(Telemetry),
    /// Panel confirms a delivery of telemetry.
    Ack(Ack),
    /// Panel gives a one-off instruction.
    Command(Command),
    /// Agent reports the outcome of an instruction.
    Result(CommandResult),
    /// Panel says why it is ending the conversation.
    Refused(Refusal),
}

impl Message {
    /// The protocol version this message declares, when it declares one.
    pub fn declared_version(&self) -> Option<u32> {
        match self {
            Self::Hello(hello) => Some(hello.proto),
            Self::Welcome(welcome) => Some(welcome.proto),
            Self::Enroll(enroll) => Some(enroll.proto),
            _ => None,
        }
    }
}

/// Agent opens a connection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    /// Protocol version the agent speaks.
    pub proto: u32,
    /// Node the agent serves, as it believes it to be.
    pub node_id: uuid::Uuid,
    /// Build of the agent.
    pub agent_version: String,
    /// Revision the agent already has, if any.
    pub applied_revision: Option<uuid::Uuid>,
}

/// Panel accepts the connection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Welcome {
    /// Protocol version the exchange will use.
    pub proto: u32,
    /// Key the agent seals its cache with, as 64 hexadecimal characters.
    ///
    /// Never written to disk by either side. A fresh one is drawn for every
    /// connection, so a key recovered from a core dump ages out quickly.
    pub cache_key: String,
    /// How often the agent should speak up when it has nothing to say.
    pub heartbeat_secs: u32,
    /// How long the cache stays usable without contact.
    pub cache_ttl_secs: u32,
}

/// Agent presents an enrolment code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Enroll {
    /// Protocol version the agent speaks.
    pub proto: u32,
    /// The one-time code, shown to the operator once.
    pub code: String,
    /// Certificate signing request, PEM.
    pub csr: String,
    /// Build of the agent.
    pub agent_version: String,
}

/// Panel returns a signed certificate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Enrolled {
    /// Node the agent now serves.
    pub node_id: uuid::Uuid,
    /// Certificate for the agent, PEM.
    pub certificate: String,
    /// Certificate of the panel authority, PEM.
    pub ca: String,
    /// When the agent certificate stops being valid.
    pub not_after: String,
}

/// What a node exposes, as the panel describes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeShape {
    /// Which one of the five methods this node serves.
    pub kind: String,
    /// The name a masked node answers to, absent on one that serves in the
    /// open. Borrowed by a forged handshake, its own on a node with a site.
    pub domain: Option<String>,
    /// The sponsorship tag Telegram issued for this node, when it has one.
    ///
    /// Absent on a node that carries no sponsored channel, which is what
    /// decides whether the node goes through Telegram's middle proxies at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ad_tag: Option<String>,
}

/// One socket the node opens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Listener {
    /// Which method this socket serves.
    pub method: String,
    /// Where to bind, host and port.
    pub bind: String,
}

/// What a client presents, as it travels to the node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum WireCredential {
    /// Sixteen bytes as 32 hexadecimal characters, for the MTProto family.
    Secret {
        /// The value.
        hex: String,
    },
    /// A name and a password, for SOCKS5 and HTTP.
    Login {
        /// Account name.
        user: String,
        /// Password.
        pass: String,
    },
}

/// One connection the node should serve.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireAccess {
    /// Identifier of the access.
    pub id: uuid::Uuid,
    /// How the client reaches the node.
    pub method: String,
    /// What the client presents.
    pub credential: WireCredential,
    /// How many distinct devices may use it.
    pub max_devices: Option<i32>,
    /// Either active or disabled. Withdrawn accesses are absent entirely.
    pub state: String,
}

/// Settings that change how the node behaves rather than whom it serves.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// How much the node writes down.
    pub log_level: String,
    /// Which carrier the WEB method uses.
    pub carrier_mode: String,
}

/// The whole state of a node.
///
/// Sent complete rather than as a difference: a lost difference leaves the two
/// sides disagreeing with no way to notice from inside.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// Identifier of this state. Monotonic; an older one is refused.
    pub revision: uuid::Uuid,
    /// When the panel produced it.
    pub issued_at: String,
    /// What the node exposes.
    pub node: NodeShape,
    /// Sockets to open.
    pub listeners: Vec<Listener>,
    /// Connections to serve.
    pub accesses: Vec<WireAccess>,
    /// Behaviour settings.
    pub policy: Policy,
}

/// Agent reports what it did with a revision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Applied {
    /// The revision in question.
    pub revision: uuid::Uuid,
    /// One of ok, stale, rejected.
    pub status: String,
    /// Why, when the status is not ok.
    pub detail: Option<String>,
}

/// One day of traffic for one access.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrafficDelta {
    /// Which access.
    pub access_id: uuid::Uuid,
    /// Which day, in UTC.
    pub day: String,
    /// Bytes received by the client.
    pub bytes_in: i64,
    /// Bytes sent by the client.
    pub bytes_out: i64,
}

/// How many distinct devices used one access in a period.
///
/// A count and nothing else. The salted hashes it was derived from stay in the
/// node's memory and are never written down or sent anywhere.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceCount {
    /// Which access.
    pub access_id: uuid::Uuid,
    /// Which period, in UTC.
    pub period: String,
    /// How many.
    pub unique: i64,
}

/// What the node reports about itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Health {
    /// Whether the proxy engine is running.
    pub engine: String,
    /// Whether the cover site answers a visitor.
    pub site: String,
    /// Whether the node can still reach Telegram.
    ///
    /// A node that cannot is serving nobody, whatever its engine says about
    /// itself: the engine is up, the port is open, the link looks right, and
    /// every client fails. Defaulted so an older agent that does not say is
    /// read as not having said, rather than as a node that cannot reach.
    #[serde(default = "unknown")]
    pub reach: String,
    /// When the certificate stops being valid.
    pub cert_not_after: Option<String>,
}

/// What a report says about something it did not ask.
fn unknown() -> String {
    "unknown".to_owned()
}

/// Agent reports traffic, device counts and health.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Telemetry {
    /// Identifier of this delivery, not of a configuration.
    ///
    /// The agent repeats a delivery it was not acknowledged for, and the panel
    /// applies it once by this value.
    pub revision: uuid::Uuid,
    /// When the agent sent it.
    pub sent_at: String,
    /// Traffic since the last delivery.
    pub deltas: Vec<TrafficDelta>,
    /// Device counts for the period.
    pub devices: Vec<DeviceCount>,
    /// State of the node.
    pub health: Health,
}

/// Panel confirms a delivery of telemetry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ack {
    /// Which delivery.
    pub revision: uuid::Uuid,
}

/// Panel gives a one-off instruction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Command {
    /// Identifier, echoed back in the result.
    pub id: uuid::Uuid,
    /// What to do.
    pub action: String,
    /// Anything the action needs.
    pub args: serde_json::Value,
}

/// Agent reports the outcome of an instruction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandResult {
    /// Which instruction.
    pub id: uuid::Uuid,
    /// Either ok or failed.
    pub status: String,
    /// Why, when it failed.
    pub detail: Option<String>,
}

/// Panel says why it is ending the conversation.
///
/// A node that is refused would otherwise see a connection that simply drops,
/// which is what an unreachable panel looks like as well. The two need
/// different answers from whoever is running the node, so they must not look
/// alike.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Refusal {
    /// The stable string naming what was wrong.
    pub reason: String,
}
