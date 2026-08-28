//! A router whose audit route reaches a handler that never asks who is calling.

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
    Query(page): Query<Page>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let entries = state.audit(page.limit).await?;
    Ok(Json(serde_json::json!(entries.len())))
}
