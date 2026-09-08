//! A router that mounts the site feed beside the sign-in.

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/session", post(sign_in))
        .route("/v1/public-links", get(public_links))
        .with_state(state)
}
