use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// What the caller is told, and nothing more.
///
/// The variants deliberately collapse cases the caller must not be able to
/// tell apart: a missing entity and one they may not see are the same
/// `NotFound`, and every way of failing to sign in is one `InvalidCredentials`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// The body or a parameter was not accepted.
    BadRequest(&'static str),
    /// No live session.
    Unauthenticated,
    /// Wrong login, wrong password or wrong code. Which one is never said.
    InvalidCredentials,
    /// The role does not allow it.
    Forbidden,
    /// It does not exist, or the role must not know that it does.
    NotFound,
    /// It contradicts the current state.
    Conflict(&'static str),
    /// The shape was right, the value was refused.
    Unprocessable(&'static str),
    /// Too often. Carries how long to wait.
    TooManyRequests(u64),
    /// The panel could not finish the work.
    Internal(&'static str),
}

impl ApiError {
    /// The stable string a program matches on.
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(code)
            | Self::Conflict(code)
            | Self::Unprocessable(code)
            | Self::Internal(code) => code,
            Self::Unauthenticated => "unauthenticated",
            Self::InvalidCredentials => "invalid_credentials",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::TooManyRequests(_) => "too_many_requests",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthenticated | Self::InvalidCredentials => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<ap_store::StoreError> for ApiError {
    fn from(error: ap_store::StoreError) -> Self {
        if error.is_constraint_violation() {
            Self::Conflict("constraint_violation")
        } else {
            Self::Internal("storage")
        }
    }
}

impl From<ap_core::Error> for ApiError {
    fn from(_: ap_core::Error) -> Self {
        Self::Unprocessable("value_refused")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": { "code": self.code(), "message": self.code() }
        }));
        let mut response = (self.status(), body).into_response();
        if let Self::TooManyRequests(seconds) = self
            && let Ok(value) = seconds.to_string().parse()
        {
            response.headers_mut().insert("retry-after", value);
        }
        response
    }
}
