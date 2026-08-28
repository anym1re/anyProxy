//! The same router with the handler asking who is calling.

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/audit", get(read_audit))
        .with_state(state)
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn read_audit(
    State(state): State<AppState>,
    actor: Actor,
    Query(page): Query<Page>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let entries = state.guarded(&actor).audit(page.limit).await?;
    Ok(Json(serde_json::json!(entries.len())))
}
