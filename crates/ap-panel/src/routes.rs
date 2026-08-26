use ap_core::{
    Access, AccessCommon, AccessState, AdminLogin, AnyAccess, Client, ClientState, Credential,
    Domain, Label, Node, NodeKind, NodeKindTag, Open, OpenMethod, Stealth, StealthMethod, Tag,
    TagName, time::format_rfc3339,
};
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::{
    new_token, token_digest, verify_absent_password, verify_absent_totp, verify_password,
    verify_totp,
};
use crate::{Actor, ApiError, AppState};

/// How long a session lives.
const SESSION_HOURS: i64 = 12;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/healthz", get(healthz))
        .route("/v1/readyz", get(readyz))
        .route("/v1/session", post(sign_in).get(whoami))
        .route("/v1/session", delete(sign_out))
        .route("/v1/clients", get(list_clients).post(create_client))
        .route("/v1/clients/{id}", get(read_client))
        .route("/v1/clients/{id}/state", post(set_client_state))
        .route("/v1/clients/{id}/traffic", get(client_traffic))
        .route("/v1/clients/{id}/accesses", get(list_accesses))
        .route("/v1/accesses", post(create_access))
        .route("/v1/accesses/{id}", get(read_access))
        .route("/v1/accesses/{id}/state", post(set_access_state))
        .route("/v1/accesses/{id}/link", post(render_link))
        .route("/v1/tags", get(list_tags).post(create_tag))
        .route("/v1/nodes", get(list_nodes).post(create_node))
        .route("/v1/nodes/{id}/burn", post(burn_node))
        .route("/v1/nodes/{id}/enrollment", post(issue_enrollment))
        .route("/v1/audit", get(read_audit))
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
    totp: String,
}

/// Signs an administrator in.
///
/// Every way of failing does the same work and returns the same answer. A
/// missing login still runs a password verification and a code check against
/// stand-in values, because the difference in time would otherwise say which
/// logins exist.
async fn sign_in(
    State(state): State<AppState>,
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
            let secret = admin.totp_secret().open(state.key()).ok();
            let code_ok = match &secret {
                Some(secret) => verify_totp(secret, &body.totp),
                None => false,
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

    let token = new_token();
    let now = OffsetDateTime::now_utc();
    ap_store::SessionRepo::open(
        state.pool(),
        admin.id(),
        &token_digest(&token),
        now,
        now + time::Duration::hours(SESSION_HOURS),
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

async fn healthz() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn readyz(State(state): State<AppState>) -> Result<StatusCode, ApiError> {
    ap_store::AdminRepo::count(state.pool()).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── clients ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Page {
    limit: Option<i64>,
}

fn client_json(client: &Client) -> Result<serde_json::Value, ApiError> {
    Ok(serde_json::json!({
        "id": client.id(),
        "label": client.label().as_str(),
        "state": client.state().as_stored(),
        "quota_bytes": client.quota_bytes(),
        "expires_at": client.expires_at().map(format_rfc3339).transpose()?,
        "created_at": format_rfc3339(client.created_at())?,
    }))
}

async fn list_clients(
    State(state): State<AppState>,
    actor: Actor,
    Query(page): Query<Page>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let clients = state.guarded(&actor).clients(page.limit).await?;
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
    client_id: Uuid,
    node_id: Uuid,
    method: String,
    tag_id: Option<Uuid>,
    quota_bytes: Option<i64>,
    expires_at: Option<String>,
    max_devices: Option<i32>,
}

async fn create_access(
    State(state): State<AppState>,
    actor: Actor,
    Json(body): Json<NewAccess>,
) -> Result<Response, ApiError> {
    let guarded = state.guarded(&actor);
    let node = guarded.node(body.node_id).await?;

    let mut common = AccessCommon::new(body.client_id, body.node_id, OffsetDateTime::now_utc());
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

    let access = match node.kind().tag() {
        NodeKindTag::Stealth => AnyAccess::Stealth(Access::<Stealth>::new(
            common,
            StealthMethod::from_stored(&body.method)
                .map_err(|_| ApiError::Unprocessable("method_not_served"))?,
        )),
        NodeKindTag::Open => AnyAccess::Open(Access::<Open>::new(
            common,
            OpenMethod::from_stored(&body.method)
                .map_err(|_| ApiError::Unprocessable("method_not_served"))?,
        )),
    };

    let credential = match &access {
        AnyAccess::Open(open) if !matches!(open.method(), OpenMethod::Mtproto) => {
            Credential::generate_login(access.common().client_id().simple().to_string())?
        }
        _ => Credential::generate_secret(),
    };

    guarded.create_access(&access, &credential).await?;
    guarded
        .record(
            "access.created",
            Some(&access.common().id().to_string()),
            serde_json::json!({ "method": body.method }),
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

async fn set_access_state(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
    Json(body): Json<NewState>,
) -> Result<StatusCode, ApiError> {
    let wanted = AccessState::from_stored(&body.state)?;
    let guarded = state.guarded(&actor);
    let changed = guarded.set_access_state(id, wanted).await?;
    guarded
        .record(
            "access.state",
            Some(&id.to_string()),
            serde_json::json!({ "state": body.state, "changed": changed }),
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

    let payload = match (&access, &credential) {
        (AnyAccess::Stealth(access), Credential::Secret(secret)) => {
            let domain = node
                .kind()
                .domain()
                .ok_or(ApiError::Internal("node_without_domain"))?;
            serde_json::json!({
                "link": ap_core::stealth_link(*access.method(), &body.host, domain, secret)?,
                "method": access.method().as_stored(),
            })
        }
        (AnyAccess::Open(access), Credential::Secret(secret)) => serde_json::json!({
            "link": ap_core::mtproto_link(&body.host, 8443, secret)?,
            "method": access.method().as_stored(),
        }),
        (AnyAccess::Open(access), Credential::Login { user, pass }) => serde_json::json!({
            "host": body.host,
            "port": 1080,
            "user": user,
            "password": pass,
            "method": access.method().as_stored(),
        }),
        _ => return Err(ApiError::Internal("credential_mismatch")),
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
    Ok(serde_json::json!({
        "id": node.id(),
        "label": node.label().as_str(),
        "kind": node.kind().tag().as_stored(),
        "domain": node.kind().domain().map(Domain::as_str),
        "state": node.state().as_stored(),
        "created_at": format_rfc3339(node.created_at())?,
    }))
}

async fn list_nodes(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<serde_json::Value>, ApiError> {
    let nodes = state.guarded(&actor).nodes().await?;
    let body: Result<Vec<_>, ApiError> = nodes.iter().map(node_json).collect();
    Ok(Json(serde_json::json!(body?)))
}

#[derive(Deserialize)]
struct NewNode {
    label: String,
    kind: String,
    domain: Option<String>,
}

async fn create_node(
    State(state): State<AppState>,
    actor: Actor,
    Json(body): Json<NewNode>,
) -> Result<Response, ApiError> {
    let label = Label::try_from(body.label.as_str())?;
    let tag = NodeKindTag::from_stored(&body.kind)?;
    let domain = body.domain.as_deref().map(Domain::try_from).transpose()?;
    let kind = NodeKind::from_parts(tag, domain)?;
    let node = Node::new(label.clone(), kind, OffsetDateTime::now_utc());

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
    guarded.node(id).await?;
    if !actor.role().manages_nodes() {
        return Err(ApiError::NotFound);
    }

    let issued = crate::enrollment::issue(&state, id).await?;
    guarded
        .record(
            "node.enrollment.issued",
            Some(&id.to_string()),
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
    guarded.burn_node(id).await?;
    guarded
        .record("node.burned", Some(&id.to_string()), serde_json::json!({}))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── audit ────────────────────────────────────────────────────────────────

async fn read_audit(
    State(state): State<AppState>,
    actor: Actor,
    Query(page): Query<Page>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let entries = state.guarded(&actor).audit(page.limit).await?;
    Ok(Json(serde_json::json!(
        entries
            .iter()
            .map(|entry| serde_json::json!({
                "id": entry.id,
                "actor_id": entry.actor_id,
                "action": entry.action,
                "target": entry.target,
                "details": entry.details,
            }))
            .collect::<Vec<_>>()
    )))
}
