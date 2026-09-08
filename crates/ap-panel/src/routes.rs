use ap_core::{
    Access, AccessCommon, AccessState, AdTag, AdminLogin, AnyAccess, Client, ClientState,
    Credential, Domain, Holder, Label, LinkName, Locale, Node, NodeKind, NodeKindTag, Open,
    OpenMethod, Served, Stealth, StealthMethod, Tag, TagName, i18n::raw_messages,
    time::format_date, time::format_rfc3339,
};
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use sha2::Digest as _;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::{
    new_token, token_digest, verify_absent_password, verify_absent_totp, verify_password,
    verify_totp,
};
use crate::{Actor, ApiError, AppState};

/// Shortest password the panel will accept for its own owner.
///
/// A length and nothing else: rules about characters push people towards one
/// remembered word with a digit stuck on it, and the panel cannot tell a
/// passphrase from a pattern anyway.
const MINIMUM_PASSWORD: usize = 12;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/ready", get(ready))
        .route("/v1/setup", get(setup_state).post(set_up))
        .route("/v1/session", post(sign_in).get(whoami))
        .route("/v1/session", delete(sign_out))
        .route("/v1/clients", get(list_clients).post(create_client))
        .route("/v1/clients/{id}", get(read_client))
        .route("/v1/clients/{id}/state", post(set_client_state))
        .route("/v1/clients/{id}/traffic", get(client_traffic))
        .route("/v1/clients/{id}/bot-code", post(issue_bot_code))
        .route("/v1/clients/{id}/telegram", delete(unlink_telegram))
        .route("/v1/clients/{id}/accesses", get(list_accesses))
        .route("/v1/accesses", get(list_all_accesses).post(create_access))
        .route("/v1/accesses/public", get(list_public_accesses))
        .route("/v1/accesses/{id}", get(read_access))
        .route("/v1/accesses/{id}/state", post(set_access_state))
        .route("/v1/accesses/{id}/link", post(render_link))
        .route("/v1/tags", get(list_tags).post(create_tag))
        .route("/v1/nodes", get(list_nodes).post(create_node))
        .route("/v1/nodes/{id}/burn", post(burn_node))
        .route("/v1/nodes/{id}/names", post(rename_node))
        .route("/v1/nodes/{id}/sponsorship", post(sponsor_node))
        .route("/v1/nodes/{id}/address", post(set_node_address))
        .route("/v1/nodes/{id}/enrollment", post(issue_enrollment))
        .route("/v1/nodes/{id}/check", post(ask_check))
        .route("/v1/settings", get(read_settings).put(write_settings))
        .route("/v1/audit", get(read_audit))
        .route("/v1/audit/summary", get(audit_summary))
        .route("/v1/traffic", get(traffic))
        .route("/v1/i18n", get(interface_text))
        .route("/", get(interface))
        .route("/ui/app.css", get(interface_style))
        .route("/ui/fonts/{name}", get(interface_font))
        .route("/ui/app.js", get(interface_script))
        .with_state(state)
}

// ── authentication ───────────────────────────────────────────────────────

impl FromRequestParts<AppState> for Actor {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let token = parts
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthenticated)?;

        ap_store::SessionRepo::holder(
            state.pool(),
            &token_digest(token),
            OffsetDateTime::now_utc(),
        )
        .await
        .map_err(ApiError::from)?
        .map(Actor::new)
        .ok_or(ApiError::Unauthenticated)
    }
}

#[derive(Deserialize)]
struct SignIn {
    login: String,
    password: String,
    /// The one-time code, from an account that carries a second factor.
    /// Absent and empty say the same thing: none was given (0060).
    #[serde(default)]
    totp: String,
}

// ── the first administrator ──────────────────────────────────────────────

/// Whether the panel is still waiting to be set up.
///
/// Open, like the page that asks it: it says only whether an owner exists,
/// and whoever can reach this port could try to become one anyway (0062).
async fn setup_state(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let taken = ap_store::AdminRepo::count(state.pool()).await? > 0;
    let settings = crate::settings::Settings::read(state.pool()).await?;
    // Whether the sign-in screen shows a box for a code (0063). About the
    // panel: no login is named here and none is asked about.
    let second_factor = ap_store::AdminRepo::any_second_factor(state.pool()).await?;
    Ok(Json(serde_json::json!({
        "needed": !taken,
        "second_factor": second_factor,
        // Which build is answering. The interface prints it in the corner,
        // which is where an operator looks when a fix is supposed to be in.
        "version": env!("CARGO_PKG_VERSION"),
        // Where nodes dial in. The interface shows it and puts it in the
        // enrolment command, so the address is never typed from memory (0065).
        // Whatever the operator set, or the address this process was started
        // with (0069).
        "channel_address": match settings.text("channel_address") {
            "" => state.channel_address(),
            said => said,
        },
        // How long this process has been answering, which the foot of the
        // dashboard was drawn to show.
        "uptime_seconds": state.uptime_seconds(),
        // What the panel's own process is using, when that can be read: the
        // processes card sums the whole fleet, and the panel is in it (0073).
        "own": {
            "name": "anyproxy-panel",
            "memory_mb": crate::own::memory_mb(),
            "cpu_percent": crate::own::cpu_percent(),
        },
    })))
}

#[derive(Deserialize)]
struct SetUp {
    login: String,
    password: String,
    /// Whether the account carries a second factor. Default yes: the panel
    /// holds every secret in the system, and saying no should be a choice
    /// rather than an omission (0060).
    #[serde(default = "yes")]
    second_factor: bool,
}

fn yes() -> bool {
    true
}

/// Creates the administrator the panel is first opened by.
async fn set_up(
    State(state): State<AppState>,
    Json(body): Json<SetUp>,
) -> Result<Response, ApiError> {
    if body.password.len() < MINIMUM_PASSWORD {
        return Err(ApiError::Unprocessable("password_too_short"));
    }
    match crate::set_up(&state, &body.login, &body.password, body.second_factor)
        .await
        .map_err(|_| ApiError::Unprocessable("value_refused"))?
    {
        crate::FirstAdmin::Created(secret) => Ok((
            StatusCode::CREATED,
            [("cache-control", "no-store")],
            Json(serde_json::json!({ "login": body.login, "secret": secret })),
        )
            .into_response()),
        crate::FirstAdmin::AlreadySetUp => Err(ApiError::Conflict("already_set_up")),
    }
}

/// Signs an administrator in.
///
/// Every way of failing does the same work and returns the same answer. A
/// missing login still runs a password verification and a code check against
/// stand-in values, because the difference in time would otherwise say which
/// logins exist.
/// The address a request came from, when the listener knows it.
///
/// Never a refusal: a router called directly, as a test calls it, has no
/// address behind the request, and a handler that took one would be a handler
/// no test could reach.
struct Peer(Option<std::net::IpAddr>);

impl<S: Send + Sync> FromRequestParts<S> for Peer {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|peer| peer.0.ip()),
        ))
    }
}

async fn sign_in(
    State(state): State<AppState>,
    peer: Peer,
    Json(body): Json<SignIn>,
) -> Result<Response, ApiError> {
    if let Some(wait) = state.attempts().record(&body.login) {
        return Err(ApiError::TooManyRequests(wait));
    }

    let parsed = AdminLogin::try_from(body.login.as_str()).ok();
    let found = match &parsed {
        Some(login) => ap_store::AdminRepo::by_login(state.pool(), login).await?,
        None => None,
    };

    let outcome = match &found {
        Some(admin) => {
            let password_ok = verify_password(&body.password, admin.password_hash());
            let code_ok = match admin.totp_secret() {
                Some(sealed) => match sealed.open(state.key()) {
                    Ok(secret) => verify_totp(&secret, &body.totp),
                    Err(_) => false,
                },
                // Nothing to check against, and the same work done anyway:
                // were an answer quicker for an account without a second
                // factor, a search would find those accounts and spend the
                // rest of its time on them alone (Б14).
                None => {
                    verify_absent_totp(&body.totp);
                    true
                }
            };
            let active = admin.state() == ap_core::AdminState::Active;
            password_ok && code_ok && active
        }
        None => {
            verify_absent_password(&body.password);
            verify_absent_totp(&body.totp);
            false
        }
    };

    let (Some(admin), true) = (found, outcome) else {
        return Err(ApiError::InvalidCredentials);
    };

    state.attempts().forget(&body.login);

    let settings = crate::settings::Settings::read(state.pool()).await?;
    // Told to take operators only through the tunnel, the panel takes them
    // only from the loopback, and says no more than it says to a wrong
    // password (0069). A request with no address behind it is one the router
    // was called with directly, which happens only in a test.
    if settings.on("loopback_only") && peer.0.is_some_and(|from| !from.is_loopback()) {
        return Err(ApiError::InvalidCredentials);
    }
    let token = new_token();
    let now = OffsetDateTime::now_utc();
    ap_store::SessionRepo::open(
        state.pool(),
        admin.id(),
        &token_digest(&token),
        now,
        now + time::Duration::hours(settings.number("session_hours")),
    )
    .await?;

    let actor = Actor::new(admin);
    state
        .guarded(&actor)
        .record("session.opened", Some(actor.login()), serde_json::json!({}))
        .await?;

    Ok((
        StatusCode::CREATED,
        [("cache-control", "no-store")],
        Json(serde_json::json!({ "token": token, "role": actor.role().as_stored() })),
    )
        .into_response())
}

async fn whoami(actor: Actor) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "login": actor.login(),
        "role": actor.role().as_stored(),
    }))
}

async fn sign_out(State(state): State<AppState>, actor: Actor) -> Result<StatusCode, ApiError> {
    state
        .guarded(&actor)
        .record("session.closed", Some(actor.login()), serde_json::json!({}))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── health ───────────────────────────────────────────────────────────────

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn ready(State(state): State<AppState>) -> Result<StatusCode, ApiError> {
    ap_store::AdminRepo::count(state.pool()).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── clients ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Page {
    limit: Option<i64>,
    /// One label instead of a page of them.
    ///
    /// An operator names a client by its label, not by an identifier, and a
    /// page has a ceiling: without this, naming the wrong one would depend on
    /// how many clients exist.
    label: Option<String>,
}

fn client_json(client: &Client) -> Result<serde_json::Value, ApiError> {
    Ok(serde_json::json!({
        "id": client.id(),
        "label": client.label().as_str(),
        "state": client.state().as_stored(),
        "quota_bytes": client.quota_bytes(),
        "expires_at": client.expires_at().map(format_rfc3339).transpose()?,
        "created_at": format_rfc3339(client.created_at())?,
        // When a Telegram account was tied to this client, and nothing
        // about the account (0082).
        "telegram_linked_at": client.telegram_linked_at().map(format_rfc3339).transpose()?,
    }))
}

async fn list_clients(
    State(state): State<AppState>,
    actor: Actor,
    Query(page): Query<Page>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let guarded = state.guarded(&actor);
    let clients = match page.label.as_deref() {
        Some(label) => vec![guarded.client_by_label(&Label::try_from(label)?).await?],
        None => guarded.clients(page.limit).await?,
    };
    let body: Result<Vec<_>, ApiError> = clients.iter().map(client_json).collect();
    Ok(Json(serde_json::json!(body?)))
}

#[derive(Deserialize)]
struct NewClient {
    label: String,
    quota_bytes: Option<i64>,
    expires_at: Option<String>,
}

async fn create_client(
    State(state): State<AppState>,
    actor: Actor,
    Json(body): Json<NewClient>,
) -> Result<Response, ApiError> {
    let label = Label::try_from(body.label.as_str())?;
    let mut client = Client::new(label.clone(), OffsetDateTime::now_utc());
    if let Some(bytes) = body.quota_bytes {
        client = client.with_quota(bytes)?;
    }
    if let Some(text) = &body.expires_at {
        client = client.with_expiry(ap_core::time::parse_rfc3339(text)?);
    }

    let guarded = state.guarded(&actor);
    guarded.create_client(&client).await?;
    guarded
        .record(
            "client.created",
            Some(label.as_str()),
            serde_json::json!({}),
        )
        .await?;

    Ok((StatusCode::CREATED, Json(client_json(&client)?)).into_response())
}

async fn read_client(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let client = state.guarded(&actor).client(id).await?;
    Ok(Json(client_json(&client)?))
}

#[derive(Deserialize)]
struct NewState {
    state: String,
}

async fn set_client_state(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
    Json(body): Json<NewState>,
) -> Result<StatusCode, ApiError> {
    let wanted = ClientState::from_stored(&body.state)?;
    let guarded = state.guarded(&actor);
    guarded.set_client_state(id, wanted).await?;
    guarded
        .record(
            "client.state",
            Some(&id.to_string()),
            serde_json::json!({ "state": body.state }),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn client_traffic(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let totals = state.guarded(&actor).client_traffic(id).await?;
    Ok(Json(serde_json::json!({
        "bytes_in": totals.bytes_in,
        "bytes_out": totals.bytes_out,
        "total": totals.total(),
    })))
}

/// How long a code that ties a Telegram account to a client stays usable.
const BOT_CODE_MINUTES: i64 = 60;

/// Issues a one-time code for a client to present to the bot (0082).
///
/// The code is shown here and nowhere else: only its digest is kept. When
/// the panel knows the bot's name, a link that carries the code to it is
/// given as well, so nothing has to be typed.
async fn issue_bot_code(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
    let code = hex::encode(bytes);
    let now = OffsetDateTime::now_utc();
    let expires_at = now + time::Duration::minutes(BOT_CODE_MINUTES);

    let guarded = state.guarded(&actor);
    let client = guarded
        .issue_bot_code(id, &sha2::Sha256::digest(code.as_bytes()), expires_at, now)
        .await?;
    guarded
        .record(
            "bot.code.issued",
            Some(client.label().as_str()),
            serde_json::json!({}),
        )
        .await?;

    let (_, username) = state.bot_status().snapshot();
    Ok((
        StatusCode::CREATED,
        [("cache-control", "no-store")],
        Json(serde_json::json!({
            "code": code,
            "link": username.map(|name| format!("https://t.me/{name}?start={code}")),
            "expires_at": format_rfc3339(expires_at)?,
        })),
    )
        .into_response())
}

/// Takes the Telegram account off a client (0082).
async fn unlink_telegram(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let guarded = state.guarded(&actor);
    let (client, had) = guarded.unlink_telegram(id).await?;
    if had {
        guarded
            .record(
                "bot.unlinked",
                Some(client.label().as_str()),
                serde_json::json!({}),
            )
            .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

// ── accesses ─────────────────────────────────────────────────────────────

fn access_json(access: &AnyAccess) -> Result<serde_json::Value, ApiError> {
    let common = access.common();
    let method = match access {
        AnyAccess::Stealth(access) => access.method().as_stored(),
        AnyAccess::Open(access) => access.method().as_stored(),
    };
    Ok(serde_json::json!({
        "id": common.id(),
        "client_id": common.client_id(),
        "name": common.name().map(LinkName::as_str),
        "node_id": common.node_id(),
        "surface": access.surface_tag(),
        "method": method,
        "tag_id": common.tag_id(),
        "state": common.state().as_stored(),
        "quota_bytes": common.quota_bytes(),
        "expires_at": common.expires_at().map(format_rfc3339).transpose()?,
        "max_devices": common.max_devices(),
        "created_at": format_rfc3339(common.created_at())?,
    }))
}

async fn list_all_accesses(
    State(state): State<AppState>,
    actor: Actor,
    Query(page): Query<Page>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let accesses = state.guarded(&actor).all_accesses(page.limit).await?;
    // What each of them carried lately and when it was last busy: the screen
    // was drawn with a column for each, and one query answers for all (0066).
    let carried = state.guarded(&actor).carried(30).await?;
    let mut body = Vec::with_capacity(accesses.len());
    for access in &accesses {
        let mut one = access_json(access)?;
        if let Some((bytes, last_day)) = carried.get(&access.common().id())
            && let Some(map) = one.as_object_mut()
        {
            map.insert("carried_bytes".to_owned(), serde_json::json!(bytes));
            map.insert("last_active_on".to_owned(), serde_json::json!(last_day));
        }
        body.push(one);
    }
    Ok(Json(serde_json::json!(body)))
}

async fn list_accesses(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let accesses = state.guarded(&actor).accesses(id).await?;
    let body: Result<Vec<_>, ApiError> = accesses.iter().map(access_json).collect();
    Ok(Json(serde_json::json!(body?)))
}

#[derive(Deserialize)]
struct NewAccess {
    /// The client this link is for, on a link that is somebody's.
    client_id: Option<Uuid>,
    /// The name for a link the operator hands out themselves.
    ///
    /// Exactly one of this and `client_id`: a link belongs to a client or to
    /// nobody, and one that belongs to nobody is known by what it is called.
    name: Option<String>,
    node_id: Uuid,
    /// Which method this access arrives by, when the caller says.
    ///
    /// Optional because the node decides it: one method to a host, so the
    /// node's kind names the only method an access on it could use. Given, it
    /// must agree; omitted, it is taken from the node.
    method: Option<String>,
    tag_id: Option<Uuid>,
    quota_bytes: Option<i64>,
    expires_at: Option<String>,
    max_devices: Option<i32>,
}

/// Links the operator hands out themselves.
///
/// Kept apart from a client's accesses because there is no client to ask for:
/// these belong to nobody and are told apart by the name they were given.
async fn list_public_accesses(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<serde_json::Value>, ApiError> {
    let accesses = state.guarded(&actor).public_accesses().await?;
    let body: Result<Vec<_>, ApiError> = accesses.iter().map(access_json).collect();
    Ok(Json(serde_json::json!(body?)))
}

async fn create_access(
    State(state): State<AppState>,
    actor: Actor,
    Json(body): Json<NewAccess>,
) -> Result<Response, ApiError> {
    let guarded = state.guarded(&actor);
    let node = guarded.node(body.node_id).await?;

    let holder = match (body.client_id, body.name.as_deref()) {
        (Some(client_id), None) => Holder::Client(client_id),
        (None, Some(name)) => Holder::Public(LinkName::try_from(name)?),
        _ => return Err(ApiError::Unprocessable("a_link_has_one_holder")),
    };

    let mut common = AccessCommon::new(holder, body.node_id, OffsetDateTime::now_utc());
    if let Some(tag) = body.tag_id {
        common = common.with_tag(tag);
    }
    if let Some(bytes) = body.quota_bytes {
        common = common.with_quota(bytes)?;
    }
    if let Some(text) = &body.expires_at {
        common = common.with_expiry(ap_core::time::parse_rfc3339(text)?);
    }
    if let Some(devices) = body.max_devices {
        common = common.with_max_devices(devices)?;
    }

    // A node serves the one method its kind names and nothing else, so the
    // node decides. A caller that named a method is held to it — an access for
    // another method could never be served, and refusing is better than
    // storing one and wondering later — but naming it is not required.
    let access = match node.kind().tag().served() {
        Served::Masked(only) => {
            if let Some(asked) = &body.method {
                let asked = StealthMethod::from_stored(asked)
                    .map_err(|_| ApiError::Unprocessable("method_not_served"))?;
                if asked != only {
                    return Err(ApiError::Unprocessable("method_not_served"));
                }
            }
            AnyAccess::Stealth(Access::<Stealth>::new(common, only))
        }
        Served::Open(only) => {
            if let Some(asked) = &body.method {
                let asked = OpenMethod::from_stored(asked)
                    .map_err(|_| ApiError::Unprocessable("method_not_served"))?;
                if asked != only {
                    return Err(ApiError::Unprocessable("method_not_served"));
                }
            }
            AnyAccess::Open(Access::<Open>::new(common, only))
        }
    };

    let credential = match &access {
        AnyAccess::Open(open) if !matches!(open.method(), OpenMethod::Mtproto) => {
            // Named by the access, not by the client that holds it. A client
            // with two accesses would otherwise have one name for both, and a
            // node keyed by name would serve whichever it stored last while
            // charging the traffic to whichever it happened to keep.
            Credential::generate_login(access.common().id().simple().to_string())?
        }
        _ => Credential::generate_secret(),
    };

    guarded.create_access(&access, &credential).await?;
    // Whose the link is, by name where it has one: making a link public is
    // the act that puts it on the site, and the journal names things (0074,
    // 0092).
    let (holder, name) = match access.common().holder() {
        Holder::Client(_) => ("client", None),
        Holder::Public(name) => ("public", Some(name.as_str())),
    };
    guarded
        .record(
            "access.created",
            Some(&access.common().id().to_string()),
            serde_json::json!({ "method": body.method, "holder": holder, "name": name }),
        )
        .await?;

    Ok((StatusCode::CREATED, Json(access_json(&access)?)).into_response())
}

async fn read_access(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let access = state.guarded(&actor).access(id).await?;
    Ok(Json(access_json(&access)?))
}

/// How an access is named in the journal: who holds it, and on what.
///
/// Falls back to the identifier when either half cannot be read, so a line is
/// written whatever happens: a journal that skips an entry is worse than one
/// that names it awkwardly.
async fn said_access(guarded: &crate::Guarded<'_>, id: Uuid) -> Result<String, ApiError> {
    let Ok(access) = guarded.access(id).await else {
        return Ok(id.to_string());
    };
    let common = access.common();
    let node = guarded
        .node(common.node_id())
        .await
        .map(|node| node.label().as_str().to_owned())
        .unwrap_or_else(|_| common.node_id().to_string());
    let who = match common.name() {
        Some(name) => name.as_str().to_owned(),
        None => match common.client_id() {
            Some(client_id) => guarded
                .client(client_id)
                .await
                .map(|client| client.label().as_str().to_owned())
                .unwrap_or_else(|_| client_id.to_string()),
            None => id.to_string(),
        },
    };
    Ok(format!("{who} · {node}"))
}

async fn set_access_state(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
    Json(body): Json<NewState>,
) -> Result<StatusCode, ApiError> {
    let wanted = AccessState::from_stored(&body.state)?;
    let guarded = state.guarded(&actor);
    // An access has no name of its own. It is said by who holds it and which
    // node it is on, which is how the screens name it too (0074).
    let said = said_access(&guarded, id).await?;
    let changed = guarded.set_access_state(id, wanted).await?;
    guarded
        .record(
            "access.state",
            Some(&said),
            serde_json::json!({ "state": body.state, "changed": changed, "access": id }),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct LinkRequest {
    host: String,
    acknowledged: bool,
}

/// Renders the connection link.
///
/// The only response in this API that carries a secret. The audit entry is
/// written before the link is produced: if the log cannot be written, the
/// secret does not leave.
async fn render_link(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
    Json(body): Json<LinkRequest>,
) -> Result<Response, ApiError> {
    if !body.acknowledged {
        return Err(ApiError::Unprocessable("acknowledgement_required"));
    }
    if body.host.is_empty() {
        return Err(ApiError::Unprocessable("host_required"));
    }

    let guarded = state.guarded(&actor);
    let access = guarded.access(id).await?;

    guarded
        .record(
            "access.link.rendered",
            Some(&id.to_string()),
            serde_json::json!({ "host": body.host }),
        )
        .await?;

    let credential = guarded.credential(id).await?;
    let node = guarded.node(access.common().node_id()).await?;

    // Built where the bot builds it too, so both hand out the same thing
    // (0088).
    let payload = match crate::handout::handout(&access, &credential, node.kind(), &body.host)? {
        crate::handout::Handout::Link { link, method } => serde_json::json!({
            "link": link,
            "method": method,
        }),
        crate::handout::Handout::Account {
            host,
            port,
            user,
            password,
            method,
        } => serde_json::json!({
            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "method": method,
        }),
    };

    Ok((
        StatusCode::OK,
        [("cache-control", "no-store")],
        Json(payload),
    )
        .into_response())
}

// ── tags ─────────────────────────────────────────────────────────────────

async fn list_tags(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tags = state.guarded(&actor).tags().await?;
    Ok(Json(serde_json::json!(
        tags.iter()
            .map(|tag| serde_json::json!({ "id": tag.id(), "name": tag.name().as_str() }))
            .collect::<Vec<_>>()
    )))
}

#[derive(Deserialize)]
struct NewTag {
    name: String,
}

async fn create_tag(
    State(state): State<AppState>,
    actor: Actor,
    Json(body): Json<NewTag>,
) -> Result<Response, ApiError> {
    let name = TagName::try_from(body.name.as_str())?;
    let tag = Tag::new(name.clone());
    let guarded = state.guarded(&actor);
    guarded.create_tag(&tag).await?;
    guarded
        .record("tag.created", Some(name.as_str()), serde_json::json!({}))
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": tag.id(), "name": name.as_str() })),
    )
        .into_response())
}

// ── nodes ────────────────────────────────────────────────────────────────

fn node_json(node: &Node) -> Result<serde_json::Value, ApiError> {
    node_json_with(node, 0)
}

/// The same, knowing how long a node may stay quiet before that is a fault.
///
/// A node reports itself well and then stops speaking; nothing it said was
/// wrong, so nothing looked wrong. How long counts as too long is the
/// operator's to say (0069).
fn node_json_with(node: &Node, silence_minutes: i64) -> Result<serde_json::Value, ApiError> {
    // Everything the panel knows about the node goes out. The three words of
    // health and the machine's word are what an operator looks at first; a
    // listing that showed only the state was a listing that hid every node
    // in trouble behind the word "active".
    let health = node
        .health()
        .map(|health| -> Result<serde_json::Value, ApiError> {
            Ok(serde_json::json!({
                "engine": health.engine,
                "site": health.site,
                "reach": health.reach,
                "cert_not_after": health.cert_not_after.map(format_rfc3339).transpose()?,
            }))
        })
        .transpose()?;
    let machine = node.machine().map(|machine| {
        serde_json::json!({
            "pressure": machine.pressure.as_stored(),
            "cpus": machine.cpus,
            "memory_used_mb": machine.memory_used_mb,
            "memory_limit_mb": machine.memory_limit_mb,
            "memory_stall": machine.memory_stall,
            "cpu_stall": machine.cpu_stall,
            "open_files": machine.open_files,
            "file_limit": machine.file_limit,
            "cpu_percent": machine.cpu_percent,
            "uptime_seconds": machine.uptime_seconds,
            "connections": machine.connections,
            "rx_bps": machine.rx_bps,
            "tx_bps": machine.tx_bps,
        })
    });
    // Quiet for longer than allowed, or never heard from at all once it was
    // supposed to have been.
    let silent = silence_minutes > 0
        && match node.last_seen_at() {
            Some(seen) => {
                OffsetDateTime::now_utc() - seen > time::Duration::minutes(silence_minutes)
            }
            None => node.state() != ap_core::NodeState::Pending,
        };
    Ok(serde_json::json!({
        "id": node.id(),
        "label": node.label().as_str(),
        "kind": node.kind().tag().chosen().0,
        "masked": node.kind().tag().chosen().1,
        "ad_tag": node.ad_tag().map(AdTag::as_str),
        "domain": node.kind().domain().map(Domain::as_str),
        "address": node.address().map(|address| address.to_string()),
        "state": node.state().as_stored(),
        "agent_version": node.agent_version(),
        "last_seen_at": node.last_seen_at().map(format_rfc3339).transpose()?,
        "health": health,
        "machine": machine,
        "trouble_since": node.trouble_since().map(format_rfc3339).transpose()?,
        "wants_attention": node.wants_attention() || silent,
        "silent": silent,
        "created_at": format_rfc3339(node.created_at())?,
    }))
}

async fn list_nodes(
    State(state): State<AppState>,
    actor: Actor,
    Query(page): Query<Page>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let guarded = state.guarded(&actor);
    let nodes = match page.label.as_deref() {
        Some(label) => vec![guarded.node_by_label(&Label::try_from(label)?).await?],
        None => guarded.nodes().await?,
    };
    // What runs on them comes in one query rather than one per node.
    let ids: Vec<Uuid> = nodes.iter().map(Node::id).collect();
    let running = guarded.processes(&ids).await.unwrap_or_default();
    // How long a node may stay quiet before that is a fault (0069).
    let quiet = crate::settings::Settings::read(state.pool())
        .await?
        .number("silence_minutes");
    let body: Result<Vec<_>, ApiError> = nodes
        .iter()
        .map(|node| {
            let mut shown = node_json_with(node, quiet)?;
            let theirs: Vec<serde_json::Value> = running
                .iter()
                .filter(|(id, _)| *id == node.id())
                .map(|(_, process)| {
                    serde_json::json!({
                        "name": process.name,
                        "cpu_percent": process.cpu_percent,
                        "memory_mb": process.memory_mb,
                        "restarts": process.restarts,
                    })
                })
                .collect();
            shown["processes"] = serde_json::Value::Array(theirs);
            Ok(shown)
        })
        .collect();
    Ok(Json(serde_json::json!(body?)))
}

#[derive(Deserialize)]
struct NewNode {
    label: String,
    /// The transport: mtproto, web, socks5 or http.
    kind: String,
    /// Whether MTProto hides behind a forged handshake. Offered for no other
    /// transport, and refused rather than ignored where it is not.
    #[serde(default)]
    masked: bool,
    /// The name a masked node answers to. A node serving in the open has none.
    domain: Option<String>,
}

async fn create_node(
    State(state): State<AppState>,
    actor: Actor,
    Json(body): Json<NewNode>,
) -> Result<Response, ApiError> {
    let label = Label::try_from(body.label.as_str())?;
    let tag = NodeKindTag::from_chosen(&body.kind, body.masked)?;
    let domain = body.domain.as_deref().map(Domain::try_from).transpose()?;
    let kind = NodeKind::from_parts(tag, domain)?;
    let mut node = Node::new(label.clone(), kind, OffsetDateTime::now_utc());
    // A node made without a tag takes the one set as the default (0069).
    let settings = crate::settings::Settings::read(state.pool()).await?;
    if let Ok(tag) = ap_core::AdTag::try_from(settings.text("default_ad_tag")) {
        node = node.with_ad_tag(Some(tag));
    }

    let guarded = state.guarded(&actor);
    guarded.create_node(&node).await?;
    guarded
        .record("node.created", Some(label.as_str()), serde_json::json!({}))
        .await?;

    Ok((StatusCode::CREATED, Json(node_json(&node)?)).into_response())
}

/// Issues a one-time enrolment code.
///
/// The value is shown here and nowhere else: only its digest is kept, so it
/// cannot be read back, only replaced.
async fn issue_enrollment(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let guarded = state.guarded(&actor);
    let node = guarded.node(id).await?;
    if !actor.role().manages_nodes() {
        return Err(ApiError::NotFound);
    }

    let issued = crate::enrollment::issue(&state, id).await?;
    guarded
        .record(
            "node.enrollment.issued",
            Some(node.label().as_str()),
            serde_json::json!({}),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        [("cache-control", "no-store")],
        Json(serde_json::json!({
            "code": issued.code,
            "panel_fingerprint": issued.fingerprint,
            "expires_at": issued.expires_at,
        })),
    )
        .into_response())
}

async fn burn_node(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let guarded = state.guarded(&actor);
    // Read before it is burned: a burned node is still there to be named, and
    // reading it first keeps the journal line readable either way (0074).
    let node = guarded.node(id).await?;
    guarded.burn_node(id).await?;
    guarded
        .record(
            "node.burned",
            Some(node.label().as_str()),
            serde_json::json!({}),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Deserialize)]
struct Sponsorship {
    /// The tag from @MTProxybot, or null to carry none.
    ad_tag: Option<String>,
}

/// Sets or clears the sponsorship a node carries.
///
/// A node with a tag routes through Telegram's middle proxies, which is the
/// only way the sponsored channel is counted, and pays an extra hop for it. A
/// node without one goes to the data centres directly.
async fn sponsor_node(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
    Json(body): Json<Sponsorship>,
) -> Result<StatusCode, ApiError> {
    let ad_tag = body.ad_tag.as_deref().map(AdTag::try_from).transpose()?;

    let guarded = state.guarded(&actor);
    guarded.sponsor_node(id, ad_tag).await?;
    guarded
        .record(
            "node.sponsorship.set",
            Some(&id.to_string()),
            serde_json::json!({ "sponsored": body.ad_tag.is_some() }),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Deserialize)]
struct NewNames {
    domain: Option<String>,
}

/// Changes the names a node answers to.
///
/// Every link already issued for this node names the old one, so this is a
/// change an operator makes knowing that clients have to be given new links.
/// It is written to the audit log for that reason.
async fn rename_node(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
    Json(body): Json<NewNames>,
) -> Result<StatusCode, ApiError> {
    let domain = body.domain.as_deref().map(Domain::try_from).transpose()?;

    let guarded = state.guarded(&actor);
    guarded.rename_node(id, domain).await?;
    guarded
        .record(
            "node.renamed",
            Some(&id.to_string()),
            serde_json::json!({ "domain": body.domain }),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Deserialize)]
struct NewAddress {
    /// The address clients reach the node at, or null to carry none.
    address: Option<String>,
}

/// Sets or clears the address clients reach a node at (0091).
///
/// Given by the operator rather than read off the agent channel: the panel
/// may hear a node through a tunnel, and then what it sees is the tunnel.
/// The public feed puts this into every link for the node, so it is written
/// to the audit log by the node's name.
async fn set_node_address(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
    Json(body): Json<NewAddress>,
) -> Result<StatusCode, ApiError> {
    let address = body
        .address
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(|text| {
            text.parse::<std::net::IpAddr>()
                .map_err(|_| ApiError::Unprocessable("address_form"))
        })
        .transpose()?;

    let guarded = state.guarded(&actor);
    let node = guarded.node(id).await?;
    guarded.set_node_address(id, address).await?;
    guarded
        .record(
            "node.address",
            Some(node.label().as_str()),
            serde_json::json!({ "address": address.map(|address| address.to_string()) }),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Asks a node to look at itself at the first opportunity (0070).
///
/// Answers as soon as the asking is written down rather than when the node
/// gets to it: the node may be a minute away, and an operator waiting on a
/// button learns nothing from the wait.
async fn ask_check(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let guarded = state.guarded(&actor);
    let node = guarded.node(id).await?;
    ap_store::PresenceRepo::ask_check(state.pool(), node.id(), OffsetDateTime::now_utc()).await?;
    guarded
        .record(
            "node.check_asked",
            Some(node.label().as_str()),
            serde_json::json!({}),
        )
        .await?;
    Ok(StatusCode::ACCEPTED)
}

// ── settings ─────────────────────────────────────────────────────────────

/// What the panel is set to, and what each setting may be set to (0069).
///
/// The choices come with the values: the screen draws a list of them, and
/// which lists there are is the panel's business, not the screen's.
async fn read_settings(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !actor.role().reads_audit() {
        return Err(ApiError::NotFound);
    }
    let stored = ap_store::SettingRepo::all(state.pool()).await?;
    let changed: std::collections::HashMap<&str, OffsetDateTime> = stored
        .iter()
        .map(|one| (one.name.as_str(), one.changed_at))
        .collect();
    // A sealed setting says when it was set and nothing of what it says
    // (0084).
    let sealed = ap_store::SealedSettingRepo::all(state.pool()).await?;
    let sealed_at: std::collections::HashMap<&str, OffsetDateTime> = sealed
        .iter()
        .map(|one| (one.name.as_str(), one.changed_at))
        .collect();
    let settings = crate::settings::Settings::read(state.pool()).await?;
    let mut said = Vec::with_capacity(crate::settings::KNOWN.len());
    for known in crate::settings::KNOWN {
        let touched = if known.secret {
            sealed_at.get(known.name)
        } else {
            changed.get(known.name)
        };
        said.push(serde_json::json!({
            "name": known.name,
            "value": if known.secret { "" } else { settings.text(known.name) },
            "choices": known.choices,
            "secret": known.secret,
            "set": if known.secret { touched.is_some() } else { !settings.text(known.name).is_empty() },
            "changed_at": touched
                .map(|at| format_rfc3339(*at))
                .transpose()?,
        }));
    }
    // What the bot is doing, for the head of its group on the screen (0085).
    let (standing, username) = state.bot_status().snapshot();
    Ok(Json(serde_json::json!({
        "settings": said,
        "bot": { "state": standing.as_stored(), "username": username },
    })))
}

/// Changes settings, one call for however many the operator changed.
///
/// All or none: the screen shows a save bar and saves what it has, and half
/// of it landing would leave the panel in a state nobody chose.
#[derive(Deserialize)]
struct NewSettings {
    values: std::collections::HashMap<String, String>,
}

async fn write_settings(
    State(state): State<AppState>,
    actor: Actor,
    Json(body): Json<NewSettings>,
) -> Result<StatusCode, ApiError> {
    if !actor.role().reads_audit() {
        return Err(ApiError::NotFound);
    }
    for (name, value) in &body.values {
        if !crate::settings::acceptable(name, value) {
            return Err(ApiError::Unprocessable("setting_value"));
        }
    }
    let now = OffsetDateTime::now_utc();
    for (name, value) in &body.values {
        if crate::settings::is_secret(name) {
            // Sealed under the key, or taken away when the value is empty
            // (0084). Never in the table the others are in.
            if value.is_empty() {
                ap_store::SealedSettingRepo::clear(state.pool(), name).await?;
            } else {
                ap_store::SealedSettingRepo::put(
                    state.pool(),
                    name,
                    value,
                    state.key(),
                    Some(actor.id()),
                    now,
                )
                .await?;
            }
            continue;
        }
        ap_store::SettingRepo::put(state.pool(), name, value, Some(actor.id()), now).await?;
    }
    // The name is recorded and the value is not: a value can be an address or
    // a sponsorship tag, and the journal has no use for either.
    let names: Vec<&str> = body.values.keys().map(String::as_str).collect();
    state
        .guarded(&actor)
        .record(
            "setting.changed",
            Some(&names.join(", ")),
            serde_json::json!({ "count": names.len() }),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── audit ────────────────────────────────────────────────────────────────

/// What the journal screen asks for: a page, of one kind, over a window.
#[derive(Deserialize)]
struct Journal {
    limit: Option<i64>,
    #[serde(default)]
    offset: i64,
    /// Beginnings of action names, separated by commas, such as
    /// `access.,client.`. An entry matches if it starts with any of them.
    prefix: Option<String>,
    /// How far back to look, in days.
    days: Option<i64>,
}

async fn read_audit(
    State(state): State<AppState>,
    actor: Actor,
    Query(page): Query<Journal>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let prefixes: Option<Vec<String>> = page.prefix.as_deref().map(|given| {
        given
            .split(',')
            .map(str::trim)
            .filter(|one| !one.is_empty())
            .map(str::to_owned)
            .collect()
    });
    let (entries, total) = state
        .guarded(&actor)
        .audit_page(page.limit, page.offset, prefixes.as_deref(), page.days)
        .await?;
    let rows: Result<Vec<_>, ApiError> = entries
        .iter()
        .map(|entry| {
            Ok(serde_json::json!({
                "id": entry.id,
                "actor_id": entry.actor_id,
                "action": entry.action,
                "target": entry.target,
                "at": format_rfc3339(entry.at)?,
                "details": entry.details,
            }))
        })
        .collect();
    Ok(Json(
        serde_json::json!({ "total": total, "entries": rows? }),
    ))
}

/// How many entries of each action there have been lately (0067).
async fn audit_summary(
    State(state): State<AppState>,
    actor: Actor,
    Query(page): Query<Journal>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let counts = state
        .guarded(&actor)
        .audit_counts(page.days.unwrap_or(1))
        .await?;
    let by_action: serde_json::Map<String, serde_json::Value> = counts
        .iter()
        .map(|(action, many)| (action.clone(), serde_json::json!(many)))
        .collect();
    let total: i64 = counts.iter().map(|(_, many)| many).sum();
    Ok(Json(
        serde_json::json!({ "total": total, "by_action": by_action }),
    ))
}

// ── traffic ──────────────────────────────────────────────────────────────

/// How far back the series reaches when the caller does not say.
const DEFAULT_TRAFFIC_DAYS: i64 = 30;

#[derive(Deserialize)]
struct TrafficRange {
    days: Option<i64>,
    /// Asked for instead of days when the card is showing one day (0072).
    hours: Option<i64>,
}

/// Traffic by day, summed over everything the actor may see.
async fn traffic(
    State(state): State<AppState>,
    actor: Actor,
    Query(range): Query<TrafficRange>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // A day is asked for by the hour: a day of daily figures is one figure,
    // and the card was drawn with a curve (0072).
    if let Some(hours) = range.hours {
        let series = state.guarded(&actor).traffic_hourly(hours).await?;
        let body: Result<Vec<_>, ApiError> = series
            .iter()
            .map(|(at, bytes_in, bytes_out)| {
                Ok(serde_json::json!({
                    "hour": format_rfc3339(*at)?,
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                }))
            })
            .collect();
        return Ok(Json(serde_json::json!(body?)));
    }
    let series = state
        .guarded(&actor)
        .traffic_daily(range.days.unwrap_or(DEFAULT_TRAFFIC_DAYS))
        .await?;
    let body: Result<Vec<_>, ApiError> = series
        .iter()
        .map(|point| {
            Ok(serde_json::json!({
                "day": format_date(point.day)?,
                "bytes_in": point.bytes_in,
                "bytes_out": point.bytes_out,
            }))
        })
        .collect();
    Ok(Json(serde_json::json!(body?)))
}

// ── the interface ────────────────────────────────────────────────────────

const INTERFACE_PAGE: &str = include_str!("../../../ui/index.html");
const INTERFACE_STYLE: &str = include_str!("../../../ui/app.css");
const INTERFACE_SCRIPT: &str = include_str!("../../../ui/app.js");

/// The web interface, built into the binary (0058).
///
/// Served without a session: the page holds no data, only the means to ask
/// for it, and every request it makes carries the token the way the CLI
/// does. The policy header keeps it from loading anything from anywhere but
/// this panel, which is also the only place it could load from.
async fn interface() -> Response {
    (
        [
            ("content-type", "text/html; charset=utf-8"),
            ("cache-control", "no-cache"),
            (
                "content-security-policy",
                // Inline styles are allowed because the screens carry their
                // own: a bar's width and a card's delay are per-row numbers
                // written on the element. Scripts are not: those stay at
                // 'self', which is what the directive is for.
                "default-src 'self'; style-src 'self' 'unsafe-inline'; \
                 font-src 'self'; frame-ancestors 'none'",
            ),
            ("x-content-type-options", "nosniff"),
        ],
        INTERFACE_PAGE,
    )
        .into_response()
}

/// One of the faces the interface is drawn with (0068).
///
/// Named one by one rather than read from a directory: the panel serves what
/// was built into it, and a path from the request never reaches a file system.
async fn interface_font(Path(name): Path<String>) -> Response {
    let face: &'static [u8] = match name.as_str() {
        "plex-mono-400-cyrillic.woff2" => {
            include_bytes!("../../../ui/fonts/plex-mono-400-cyrillic.woff2").as_slice()
        }
        "plex-mono-400-latin.woff2" => {
            include_bytes!("../../../ui/fonts/plex-mono-400-latin.woff2").as_slice()
        }
        "plex-mono-500-cyrillic.woff2" => {
            include_bytes!("../../../ui/fonts/plex-mono-500-cyrillic.woff2").as_slice()
        }
        "plex-mono-500-latin.woff2" => {
            include_bytes!("../../../ui/fonts/plex-mono-500-latin.woff2").as_slice()
        }
        "plex-mono-600-cyrillic.woff2" => {
            include_bytes!("../../../ui/fonts/plex-mono-600-cyrillic.woff2").as_slice()
        }
        "plex-mono-600-latin.woff2" => {
            include_bytes!("../../../ui/fonts/plex-mono-600-latin.woff2").as_slice()
        }
        "plex-sans-400-600-cyrillic.woff2" => {
            include_bytes!("../../../ui/fonts/plex-sans-400-600-cyrillic.woff2").as_slice()
        }
        "plex-sans-400-600-latin.woff2" => {
            include_bytes!("../../../ui/fonts/plex-sans-400-600-latin.woff2").as_slice()
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            ("content-type", "font/woff2"),
            // The faces change only when the panel does, and the panel is
            // asked for afresh every time.
            ("cache-control", "public, max-age=604800, immutable"),
        ],
        face,
    )
        .into_response()
}

async fn interface_style() -> Response {
    (
        [
            ("content-type", "text/css; charset=utf-8"),
            ("cache-control", "no-cache"),
        ],
        INTERFACE_STYLE,
    )
        .into_response()
}

async fn interface_script() -> Response {
    (
        [
            ("content-type", "text/javascript; charset=utf-8"),
            ("cache-control", "no-cache"),
        ],
        INTERFACE_SCRIPT,
    )
        .into_response()
}

#[derive(Deserialize)]
struct LanguageQuery {
    lang: Option<String>,
}

/// The interface's text in one language, as the catalogue has it.
///
/// Not behind a session: the words are the same for everyone and there is
/// nothing in them to protect. `lang` wins over `Accept-Language`, so the
/// switch in the interface holds regardless of what the browser prefers.
async fn interface_text(
    Query(query): Query<LanguageQuery>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let preferred = headers
        .get("accept-language")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(|value| value.split(';').next().unwrap_or(value).trim().to_owned());
    let locale = Locale::from_code(&query.lang.or(preferred).unwrap_or_default());
    // The interface's own words, and the sentences for what the panel
    // refuses: the code travels, the sentence is made where it is read.
    let messages: serde_json::Map<String, serde_json::Value> = raw_messages(locale, "ui-")
        .into_iter()
        .chain(raw_messages(locale, "api-"))
        .map(|(key, pattern)| (key, serde_json::Value::String(pattern)))
        .collect();
    Json(serde_json::json!({ "lang": locale.code(), "messages": messages }))
}
