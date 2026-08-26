//! Domain types shared by the panel and the node agent.

mod access;
mod client;
mod error;
mod limits;
mod name;
mod node;
mod tag;
pub mod time;

pub use access::{
    Access, AccessCommon, AccessState, AnyAccess, Open, OpenMethod, Stealth, StealthMethod, Surface,
};
pub use client::{Client, ClientState};
pub use error::Error;
pub use limits::{
    QuotaLimits, Reason, Servable, Usage, effective_expiry, effective_quota, is_servable,
};
pub use name::{Color, Domain, Label, Note, TagName};
pub use node::{Node, NodeKind, NodeKindTag, NodeState};
pub use tag::Tag;
