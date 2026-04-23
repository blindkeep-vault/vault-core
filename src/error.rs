use thiserror::Error;

/// Shared API error type. Each server crate implements its own `IntoResponse`.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("gone")]
    Gone,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("payment required")]
    PaymentRequired,
    #[error("too many requests")]
    TooManyRequests,
    #[error("conflict: {0}")]
    Conflict(String),
    /// The request is well-formed and the caller is authorized, but the
    /// operation is refused by a handling policy (e.g. attempting to create an
    /// anonymous drop of a `Restricted`-classified item). Distinct from
    /// `Forbidden` so callers can surface policy violations separately from
    /// access-control denials.
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<crate::storage::StorageError> for ApiError {
    fn from(err: crate::storage::StorageError) -> Self {
        match err {
            crate::storage::StorageError::NotFound(_) => ApiError::NotFound,
            crate::storage::StorageError::BackendError(msg) => ApiError::Internal(msg),
        }
    }
}

impl From<argon2::password_hash::Error> for ApiError {
    fn from(err: argon2::password_hash::Error) -> Self {
        ApiError::Internal(err.to_string())
    }
}

#[cfg(feature = "server")]
impl From<jsonwebtoken::errors::Error> for ApiError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        ApiError::Internal(err.to_string())
    }
}

/// HTTP status code for this error (u16 to avoid depending on an HTTP crate).
impl ApiError {
    pub fn status_code(&self) -> u16 {
        match self {
            ApiError::NotFound => 404,
            ApiError::Unauthorized => 401,
            ApiError::Forbidden => 403,
            ApiError::Gone => 410,
            ApiError::BadRequest(_) => 400,
            ApiError::PaymentRequired => 402,
            ApiError::TooManyRequests => 429,
            ApiError::Conflict(_) => 409,
            ApiError::PolicyDenied(_) => 422,
            ApiError::Internal(_) => 500,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages() {
        assert_eq!(ApiError::NotFound.to_string(), "not found");
        assert_eq!(
            ApiError::BadRequest("missing field".into()).to_string(),
            "bad request: missing field"
        );
        assert_eq!(
            ApiError::Conflict("already exists".into()).to_string(),
            "conflict: already exists"
        );
        assert_eq!(
            ApiError::PolicyDenied("restricted items cannot be dropped".into()).to_string(),
            "policy denied: restricted items cannot be dropped"
        );
    }

    #[test]
    fn status_codes() {
        assert_eq!(ApiError::NotFound.status_code(), 404);
        assert_eq!(ApiError::Unauthorized.status_code(), 401);
        assert_eq!(ApiError::Forbidden.status_code(), 403);
        assert_eq!(ApiError::Gone.status_code(), 410);
        assert_eq!(ApiError::BadRequest("x".into()).status_code(), 400);
        assert_eq!(ApiError::PaymentRequired.status_code(), 402);
        assert_eq!(ApiError::TooManyRequests.status_code(), 429);
        assert_eq!(ApiError::Conflict("x".into()).status_code(), 409);
        assert_eq!(ApiError::PolicyDenied("x".into()).status_code(), 422);
        assert_eq!(ApiError::Internal("x".into()).status_code(), 500);
    }

    #[test]
    fn from_storage_not_found() {
        let err: ApiError = crate::storage::StorageError::NotFound("key".into()).into();
        assert!(matches!(err, ApiError::NotFound));
    }

    #[test]
    fn from_storage_backend_error() {
        let err: ApiError = crate::storage::StorageError::BackendError("boom".into()).into();
        assert!(matches!(err, ApiError::Internal(_)));
    }
}
