use std::sync::Arc;

use ap_core::{AnyAccess, Credential, NodeKindTag};
use ap_proto::{
    Ack, Applied, Config, Health, Hello, Listener, Message, NodeShape, PROTOCOL_VERSION, Policy,
    Telemetry, Welcome, WireAccess, WireCredential,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::{Date, OffsetDateTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use crate::ca::Authority;
use crate::{ApiError, AppState};

/// How long the cache an agent keeps stays usable without contact.
const CACHE_TTL_SECS: u32 = 72 * 3600;

/// How often an agent speaks up when it has nothing to say.
const HEARTBEAT_SECS: u32 = 30;

/// Largest buffer held for one connection before it is dropped.
const READ_CEILING: usize = ap_proto::MAX_PAYLOAD + ap_proto::HEADER_LEN;

/// Serves agents until the process stops.
///
/// Takes the listener already bound, so a caller can learn the port it was
/// given before the first agent arrives.
pub async fn serve(
    state: AppState,
    authority: Arc<Authority>,
    listener: tokio::net::TcpListener,
) -> Result<(), String> {
    let acceptor = acceptor(&authority)?;

    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let acceptor = acceptor.clone();
        let state = state.clone();
        let authority = Arc::clone(&authority);
        tokio::spawn(async move {
            if let Ok(stream) = acceptor.accept(stream).await {
                let presented = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|chain| chain.first().cloned());
                let _ = converse(state, authority, stream, presented).await;
            }
        });
    }
}

fn acceptor(authority: &Authority) -> Result<TlsAcceptor, String> {
    let (certificate_pem, key_pem) = authority.server_certificate()?;

    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(certificate_pem.as_bytes())
            .collect::<Result<_, _>>()
            .map_err(|error| format!("server certificate: {error}"))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|error| format!("server key: {error}"))?;

    // The client certificate is optional. An agent that has not enrolled yet
    // has none, and enrolment is the one exchange it is allowed without one.
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(authority.certificate_pem().as_bytes()) {
        let certificate = certificate.map_err(|error| format!("authority: {error}"))?;
        roots
            .add(certificate)
            .map_err(|error| format!("authority: {error}"))?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
        .map_err(|error| format!("client verifier: {error}"))?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|error| format!("server config: {error}"))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

async fn converse<S>(
    state: AppState,
    authority: Arc<Authority>,
    mut stream: S,
    presented: Option<CertificateDer<'static>>,
) -> Result<(), ApiError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // The node is decided by the certificate, never by what a frame says.
    // A frame naming another node is a violation, not a request.
    let node_id = match &presented {
        Some(certificate) => {
            let digest = Sha256::digest(certificate.as_ref()).to_vec();
            ap_store::EnrollmentRepo::node_of_certificate(state.pool(), &digest)
                .await
                .map_err(ApiError::from)?
        }
        None => None,
    };

    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];

    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| ApiError::Internal("channel_read"))?;
        if read == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > READ_CEILING {
            return Err(ApiError::BadRequest("frame_too_large"));
        }

        while let Some((message, consumed)) =
            ap_proto::decode(&buffer).map_err(|_| ApiError::BadRequest("malformed_frame"))?
        {
            buffer.drain(..consumed);
            let replies = match handle(&state, &authority, node_id, message).await {
                Ok(replies) => replies,
                Err(refusal) => {
                    // Said to the node and written down here. A connection that
                    // simply drops is indistinguishable from a panel that is
                    // not running, and the two need different answers from
                    // whoever is looking after the node.
                    say_no(&mut stream, refusal.code()).await;
                    let code = refusal.code();
                    let note = match node_id {
                        Some(node) => format!("refused a frame from node {node}: {code}"),
                        None => format!("refused a frame from a stranger: {code}"),
                    };
                    eprintln!("{note}");
                    return Err(refusal);
                }
            };
            for reply in replies {
                let frame =
                    ap_proto::encode(&reply).map_err(|_| ApiError::Internal("channel_encode"))?;
                stream
                    .write_all(&frame)
                    .await
                    .map_err(|_| ApiError::Internal("channel_write"))?;
            }
        }
    }
}

/// Tells the node why the conversation is over, if it can still be told.
async fn say_no<S>(stream: &mut S, reason: &str)
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let frame = ap_proto::encode(&Message::Refused(ap_proto::Refusal {
        reason: reason.to_owned(),
    }));
    if let Ok(frame) = frame {
        let _ = stream.write_all(&frame).await;
    }
}

async fn handle(
    state: &AppState,
    authority: &Authority,
    node_id: Option<Uuid>,
    message: Message,
) -> Result<Vec<Message>, ApiError> {
    match (message, node_id) {
        (Message::Enroll(enroll), None) => {
            if enroll.proto > PROTOCOL_VERSION {
                return Err(ApiError::BadRequest("unsupported_protocol"));
            }
            let enrolled = enrol(state, authority, &enroll.code, &enroll.csr).await?;
            Ok(vec![Message::Enrolled(enrolled)])
        }
        (Message::Enroll(_), Some(_)) => Err(ApiError::BadRequest("already_enrolled")),

        (Message::Hello(hello), Some(node_id)) => {
            if hello.proto > PROTOCOL_VERSION {
                return Err(ApiError::BadRequest("unsupported_protocol"));
            }
            // The node is talking to us, so it is no longer merely registered.
            ap_store::PresenceRepo::seen(
                state.pool(),
                node_id,
                &hello.agent_version,
                None,
                OffsetDateTime::now_utc(),
            )
            .await
            .map_err(ApiError::from)?;
            let welcome = Message::Welcome(Welcome {
                proto: PROTOCOL_VERSION,
                cache_key: hex::encode(cache_key()),
                heartbeat_secs: HEARTBEAT_SECS,
                cache_ttl_secs: CACHE_TTL_SECS,
            });
            let config = build_config(state, node_id).await?;
            Ok(vec![welcome, Message::Config(config)])
        }

        (Message::Applied(applied), Some(node_id)) => {
            record_applied(state, node_id, &applied).await?;
            Ok(Vec::new())
        }

        (Message::Telemetry(telemetry), Some(node_id)) => {
            apply_telemetry(state, node_id, &telemetry).await?;
            Ok(vec![Message::Ack(Ack {
                revision: telemetry.revision,
            })])
        }

        (Message::Result(_), Some(_)) => Ok(Vec::new()),

        // Everything else without a certificate, and anything a panel does not
        // receive, ends the conversation rather than being ignored.
        _ => Err(ApiError::BadRequest("unexpected_frame")),
    }
}

fn cache_key() -> [u8; 32] {
    use rand::{RngCore, rng};
    let mut bytes = [0u8; 32];
    rng().fill_bytes(&mut bytes);
    bytes
}

async fn enrol(
    state: &AppState,
    authority: &Authority,
    code: &str,
    csr: &str,
) -> Result<ap_proto::Enrolled, ApiError> {
    let digest = Sha256::digest(code.as_bytes()).to_vec();
    let node_id = ap_store::EnrollmentRepo::claim(state.pool(), &digest, OffsetDateTime::now_utc())
        .await
        .map_err(ApiError::from)?
        // A wrong code and an expired one answer alike: telling them apart
        // would say which codes existed.
        .ok_or(ApiError::NotFound)?;

    let certificate = authority.sign(csr, node_id)?;
    let der = CertificateDer::pem_slice_iter(certificate.as_bytes())
        .next()
        .and_then(Result::ok)
        .ok_or(ApiError::Internal("signed_certificate"))?;
    ap_store::EnrollmentRepo::bind_certificate(
        state.pool(),
        node_id,
        &Sha256::digest(der.as_ref()),
    )
    .await
    .map_err(ApiError::from)?;

    Ok(ap_proto::Enrolled {
        node_id,
        certificate,
        ca: authority.certificate_pem().to_owned(),
        not_after: String::new(),
    })
}

async fn build_config(state: &AppState, node_id: Uuid) -> Result<Config, ApiError> {
    let pool = state.pool();
    let node = ap_store::NodeRepo::list(pool)
        .await
        .map_err(ApiError::from)?
        .into_iter()
        .find(|node| node.id() == node_id)
        .ok_or(ApiError::NotFound)?;

    let mut accesses = Vec::new();
    for access in ap_store::AccessRepo::by_node(pool, node_id)
        .await
        .map_err(ApiError::from)?
    {
        // Withdrawn accesses are absent entirely rather than present with a
        // state: an agent must not hold what is no longer valid.
        if access.common().state() == ap_core::AccessState::Revoked {
            continue;
        }
        let credential = ap_store::AccessRepo::credential(pool, access.common().id(), state.key())
            .await
            .map_err(ApiError::from)?
            .ok_or(ApiError::Internal("credential_missing"))?;
        accesses.push(wire_access(&access, &credential));
    }

    let revision = Uuid::now_v7();
    ap_store::EnrollmentRepo::set_revision(pool, node_id, revision)
        .await
        .map_err(ApiError::from)?;

    Ok(Config {
        revision,
        issued_at: ap_core::time::format_rfc3339(OffsetDateTime::now_utc())?,
        node: NodeShape {
            kind: node.kind().tag().as_stored().to_owned(),
            domain: node
                .kind()
                .domain()
                .map(|domain| domain.as_str().to_owned()),
        },
        listeners: listeners_for(node.kind().tag(), &accesses),
        accesses,
        policy: Policy {
            log_level: "minimal".to_owned(),
            carrier_mode: "https".to_owned(),
        },
    })
}

/// The sockets a node opens.
///
/// One method to a node, so one socket, and it opens only when there is an
/// active access to serve on it — a listener answering for nobody is a port
/// that answers for no reason.
///
/// The disguise a masked node needs does not depend on this. A node with a
/// site is fronted by a web server that answers 443 with the site whether or
/// not anything is carried behind it; a node with a forged handshake has no
/// name of its own to be caught without, and its 443 is the engine's.
fn listeners_for(kind: NodeKindTag, accesses: &[WireAccess]) -> Vec<Listener> {
    let method = kind.as_stored();
    if !serves(accesses, method) {
        return Vec::new();
    }
    vec![Listener {
        method: method.to_owned(),
        bind: bind_for(kind),
    }]
}

/// Whether any access on this node arrives by the given method.
fn serves(accesses: &[WireAccess], method: &str) -> bool {
    accesses
        .iter()
        .any(|access| access.method == method && access.state == "active")
}

/// Where the engine listens for clients arriving inside a site.
///
/// Loopback: what reaches it has already come through the front door on 443,
/// which ends the real TLS and runs on the same machine. Not 8443, which is
/// where a panel listens for its nodes: the two would collide wherever both
/// ran.
const WEB_BEHIND: u16 = 8444;

/// Where a node of each kind binds its one socket.
///
/// The masked pair diverge: a forged handshake ends its own TLS and takes 443,
/// while a site is served over real TLS that a front door ends, so the engine
/// sits behind it on the loopback. The open three take a port apiece.
fn bind_for(kind: NodeKindTag) -> String {
    match kind {
        NodeKindTag::FakeTls => "0.0.0.0:443".to_owned(),
        NodeKindTag::Web => format!("127.0.0.1:{WEB_BEHIND}"),
        NodeKindTag::Mtproto => "0.0.0.0:8443".to_owned(),
        NodeKindTag::Socks5 => "0.0.0.0:1080".to_owned(),
        NodeKindTag::Http => "0.0.0.0:3128".to_owned(),
    }
}

fn wire_access(access: &AnyAccess, credential: &Credential) -> WireAccess {
    let common = access.common();
    let method = match access {
        AnyAccess::Stealth(access) => access.method().as_stored(),
        AnyAccess::Open(access) => access.method().as_stored(),
    };
    WireAccess {
        id: common.id(),
        method: method.to_owned(),
        credential: match credential {
            Credential::Secret(secret) => WireCredential::Secret {
                hex: secret.expose_hex(),
            },
            Credential::Login { user, pass } => WireCredential::Login {
                user: user.clone(),
                pass: pass.clone(),
            },
        },
        max_devices: common.max_devices(),
        state: common.state().as_stored().to_owned(),
    }
}

async fn record_applied(
    state: &AppState,
    node_id: Uuid,
    applied: &Applied,
) -> Result<(), ApiError> {
    ap_store::AuditRepo::record(
        state.pool(),
        None,
        "node.applied",
        Some(&node_id.to_string()),
        OffsetDateTime::now_utc(),
        serde_json::json!({ "revision": applied.revision, "status": applied.status }),
    )
    .await
    .map_err(ApiError::from)?;
    Ok(())
}

async fn apply_telemetry(
    state: &AppState,
    node_id: Uuid,
    telemetry: &Telemetry,
) -> Result<(), ApiError> {
    let pool = state.pool();
    let now = OffsetDateTime::now_utc();

    // What the node says about itself travels with the traffic it reports.
    ap_store::PresenceRepo::seen(
        pool,
        node_id,
        "",
        Some((
            telemetry.health.engine.as_str(),
            telemetry.health.site.as_str(),
            telemetry
                .health
                .cert_not_after
                .as_deref()
                .and_then(|text| ap_core::time::parse_rfc3339(text).ok()),
        )),
        now,
    )
    .await
    .map_err(ApiError::from)?;

    for count in &telemetry.devices {
        // The same ownership check the traffic gets: a node may only report on
        // what it serves.
        if !ap_store::EnrollmentRepo::access_belongs(pool, count.access_id, node_id)
            .await
            .map_err(ApiError::from)?
        {
            not_ours(node_id, count.access_id);
            continue;
        }
        let period = Date::parse(
            &count.period,
            &time::format_description::well_known::Iso8601::DATE,
        )
        .map_err(|_| ApiError::BadRequest("malformed_day"))?;

        ap_store::PresenceRepo::devices(
            pool,
            telemetry.revision,
            count.access_id,
            period,
            count.unique,
            now,
        )
        .await
        .map_err(ApiError::from)?;
    }

    for delta in &telemetry.deltas {
        // An agent may only report on what it serves. Checked here rather than
        // trusted, because a compromised node would otherwise write into any
        // client's counters.
        //
        // What is not this node's is not applied, and the rest of the delivery
        // is. The panel cannot tell an access that was moved off this node
        // from one that was never on it, and treating both as a violation let
        // a single withdrawn access stop the accounting of every other access
        // the node served — for as long as the node kept reporting it.
        if !ap_store::EnrollmentRepo::access_belongs(pool, delta.access_id, node_id)
            .await
            .map_err(ApiError::from)?
        {
            not_ours(node_id, delta.access_id);
            continue;
        }
        let day = Date::parse(
            &delta.day,
            &time::format_description::well_known::Iso8601::DATE,
        )
        .map_err(|_| ApiError::BadRequest("malformed_day"))?;

        ap_store::TrafficRepo::apply_delta(
            pool,
            telemetry.revision,
            delta.access_id,
            day,
            delta.bytes_in,
            delta.bytes_out,
            now,
        )
        .await
        .map_err(ApiError::from)?;
    }

    ap_store::NodeRepo::record_contact(pool, node_id, now, None)
        .await
        .map_err(ApiError::from)?;
    Ok(())
}

/// Writes down a node reporting on something that is not its to report on.
///
/// Said out loud because it is the one thing here that is either harmless — an
/// access moved to another node, and this one has not caught up — or a node
/// that has been taken, and nothing in the report itself tells the two apart.
fn not_ours(node_id: Uuid, access_id: Uuid) {
    let note = format!("node {node_id} reported on access {access_id}, which is not on it");
    eprintln!("{note}");
}

/// Whether a health report says the node is serving.
pub fn is_serving(health: &Health) -> bool {
    health.engine == "up" && health.site != "down"
}

/// Builds the configuration a node would receive, without a channel.
pub async fn configuration_for(state: &AppState, node_id: Uuid) -> Result<Config, ApiError> {
    build_config(state, node_id).await
}

/// Applies a telemetry frame as the channel would, without a channel.
pub async fn ingest_telemetry(
    state: &AppState,
    node_id: Uuid,
    telemetry: &Telemetry,
) -> Result<(), ApiError> {
    apply_telemetry(state, node_id, telemetry).await
}

/// Claims an enrolment code and signs a request, without a channel.
pub async fn enrol_directly(
    state: &AppState,
    authority: &Authority,
    code: &str,
    csr: &str,
) -> Result<ap_proto::Enrolled, ApiError> {
    enrol(state, authority, code, csr).await
}

/// Reads a hello as the channel would, for tests.
pub fn hello_of(node_id: Uuid) -> Hello {
    Hello {
        proto: PROTOCOL_VERSION,
        node_id,
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        applied_revision: None,
    }
}

/// Serves one connection over an already-established stream, for tests.
pub async fn converse_over<S>(
    state: AppState,
    authority: Arc<Authority>,
    stream: S,
    presented: Option<CertificateDer<'static>>,
) -> Result<(), ApiError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    converse(state, authority, stream, presented).await
}

/// Reads the pool out for a caller that already holds the state, for tests.
pub fn pool_of(state: &AppState) -> &PgPool {
    state.pool()
}
