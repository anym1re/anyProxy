//! Domain types shared by the panel and the node agent.

mod access;
mod client;
mod error;
mod name;
mod node;
mod tag;
pub mod time;

pub use access::{
    Access, AccessCommon, AccessState, AnyAccess, Open, OpenMethod, Stealth, StealthMethod, Surface,
};
pub use client::{Client, ClientState};
pub use error::Error;
pub use name::{Color, Domain, Label, Note, TagName};
pub use node::{Node, NodeKind, NodeKindTag, NodeState};
pub use tag::Tag;
