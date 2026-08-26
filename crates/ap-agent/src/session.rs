use ap_core::KeyStore;
use ap_proto::{Applied, Config, Enroll, Hello, Message, PROTOCOL_VERSION};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

use crate::cache;
use crate::identity::{self, Identity, Paths};
use crate::link::Link;
use crate::posture::{Posture, Silent};
use crate::{AGENT_VERSION, AgentError};

/// Presents the code and comes back with an identity.
///
/// The key never leaves this machine: what travels is a request to certify it.
pub async fn enrol<S>(link: &mut Link<S>, code: &str) -> Result<Identity, AgentError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = identity::request()?;
    link.send(&Message::Enroll(Enroll {
        proto: PROTOCOL_VERSION,
        code: code.to_owned(),
        csr: request.csr_pem,
        agent_version: AGENT_VERSION.to_owned(),
    }))
    .await?;

    match link.receive().await? {
        Some(Message::Enrolled(enrolled)) => Ok(Identity {
            node_id: enrolled.node_id,
            certificate_pem: enrolled.certificate,
            key_pem: request.key_pem,
            authority_pem: enrolled.ca,
        }),
        Some(_) => Err(AgentError::Unexpected("enrolled")),
        // The panel closes the connection on a code it will not accept, and
        // says nothing about why.
        None => Err(AgentError::Panel("the code was not accepted".to_owned())),
    }
}

/// What the panel granted for one connection.
pub struct Session {
    /// Key the cache is sealed with. Held here and nowhere else.
    pub cache_key: KeyStore,
    /// How long the cache may be used without contact.
    pub ttl_secs: u32,
    /// How often to speak up with nothing to say.
    pub heartbeat_secs: u32,
    /// Revision the node is running.
    pub applied_revision: Option<Uuid>,
    /// What the node should be doing.
    pub posture: Posture,
}

impl Session {
    /// Re-reads the cache to see whether what the node serves is still allowed.
    ///
    /// The panel may have been unreachable for a long time. The age lives
    /// inside the sealed file, so this answers the same way after any number
    /// of failed reconnections.
    pub fn reconsider(&mut self, paths: &Paths, now: OffsetDateTime) -> Result<(), AgentError> {
        self.posture = Posture::from_cache(cache::read(&paths.cache(), &self.cache_key, now)?);
        Ok(())
    }
}

/// What a node does when it starts and has not reached the panel yet.
///
/// The key that opens the cache came from a connection that no longer exists
/// and was never written down, so there is nothing to open the cache with and
/// no proxy path can come up. The cover site is unaffected.
pub fn posture_before_contact() -> Posture {
    Posture::SiteOnly(Silent::NoCacheKey)
}

/// Opens a session: greeting, cache key, first configuration.
pub async fn open<S>(
    link: &mut Link<S>,
    node_id: Uuid,
    paths: &Paths,
    applied_revision: Option<Uuid>,
    now: OffsetDateTime,
) -> Result<Session, AgentError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    link.send(&Message::Hello(Hello {
        proto: PROTOCOL_VERSION,
        node_id,
        agent_version: AGENT_VERSION.to_owned(),
        applied_revision,
    }))
    .await?;

    let welcome = match link.receive().await? {
        Some(Message::Welcome(welcome)) => welcome,
        Some(_) => return Err(AgentError::Unexpected("welcome")),
        None => return Err(AgentError::Panel("the panel closed the channel".to_owned())),
    };

    let mut session = Session {
        cache_key: cache::key_from_hex(&welcome.cache_key)?,
        ttl_secs: welcome.cache_ttl_secs,
        heartbeat_secs: welcome.heartbeat_secs,
        applied_revision,
        // The key is fresh, so whatever is on disk was sealed under a key that
        // no longer exists. Nothing is served until a configuration arrives.
        posture: posture_before_contact(),
    };

    if let Some(Message::Config(config)) = link.receive().await? {
        apply(link, &mut session, paths, config, now).await?;
    }

    Ok(session)
}

/// Takes a configuration, or says why it was not taken.
///
/// A revision the node already passed is refused rather than applied: the
/// panel is what moves revisions forward, so an older one arriving means a
/// replay rather than a change of mind.
pub async fn apply<S>(
    link: &mut Link<S>,
    session: &mut Session,
    paths: &Paths,
    config: Config,
    now: OffsetDateTime,
) -> Result<(), AgentError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(applied) = session.applied_revision
        && config.revision <= applied
    {
        link.send(&Message::Applied(Applied {
            revision: config.revision,
            status: "stale".to_owned(),
            detail: Some("a later revision is already running".to_owned()),
        }))
        .await?;
        return Ok(());
    }

    cache::write(
        &paths.cache(),
        &config,
        session.ttl_secs,
        &session.cache_key,
        now,
    )?;

    let revision = config.revision;
    session.applied_revision = Some(revision);
    session.posture = Posture::Serving(Box::new(config));

    link.send(&Message::Applied(Applied {
        revision,
        status: "ok".to_owned(),
        detail: None,
    }))
    .await
}
