//! Domain types shared by the panel and the node agent.

mod access;
mod admin;
mod client;
mod crypto;
mod error;
pub mod i18n;
mod limits;
mod link;
mod name;
mod node;
mod stored;
mod tag;
pub mod time;

pub use access::{
    Access, AccessCommon, AccessState, AnyAccess, Holder, Open, OpenMethod, Stealth, StealthMethod,
    Surface,
};
pub use admin::{AdminState, AdminUser, Role};
pub use client::{Client, ClientState};
pub use crypto::{Credential, Encrypted, KeyStore, Sealable, Secret};
pub use error::Error;
pub use i18n::{Argument, Locale};
pub use limits::{
    QuotaLimits, Reason, Servable, Usage, effective_expiry, effective_quota, is_servable,
};
pub use link::{has_link, mtproto_link, stealth_link};
pub use name::{AdTag, AdminLogin, Color, Domain, Label, LinkName, Note, TagName};
pub use node::{Machine, Node, NodeHealth, NodeKind, NodeKindTag, NodeState, Pressure, Served};
pub use tag::Tag;
