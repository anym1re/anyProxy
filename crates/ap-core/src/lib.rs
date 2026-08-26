//! Domain types shared by the panel and the node agent.

mod access;
mod client;
mod crypto;
mod error;
pub mod i18n;
mod limits;
mod link;
mod name;
mod node;
mod tag;
pub mod time;

pub use access::{
    Access, AccessCommon, AccessState, AnyAccess, Open, OpenMethod, Stealth, StealthMethod, Surface,
};
pub use client::{Client, ClientState};
pub use crypto::{Credential, Encrypted, KeyStore, Sealable, Secret};
pub use error::Error;
pub use i18n::{Argument, Locale};
pub use limits::{
    QuotaLimits, Reason, Servable, Usage, effective_expiry, effective_quota, is_servable,
};
pub use link::{has_link, mtproto_link, stealth_link};
pub use name::{Color, Domain, Label, Note, TagName};
pub use node::{Node, NodeKind, NodeKindTag, NodeState};
pub use tag::Tag;
