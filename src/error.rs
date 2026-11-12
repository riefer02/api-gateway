use std::borrow::Cow;

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

/// Errors that may cross the HTTP boundary.
///
/// The `Display` output is for logs only; `public_message` is what clients see.
/// Internal text never reaches a response body.
#[derive(Debug, Error)]
pub enum AppError {
    #[allow(dead_code)] // TODO(W5): emitted once route matching can reject malformed paths.
    #[error("bad request: {message}")]
    BadRequest { message: Cow<'static, str> },
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found: {message}")]
    NotFound { message: Cow<'static, str> },
    #[error("conflict: {message}")]
    Conflict { message: Cow<'static, str> },
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("request deadline exceeded")]
    RequestTimeout,
    #[error("method not allowed")]
    MethodNotAllowed { allowed: Vec<axum::http::Method> },
    #[error("rate limited for {retry_after_secs}s")]
    RateLimited {
        retry_after_secs: u64,
        limit: u32,
        reset_after_secs: u64,
    },
    #[error("upstream circuit is open for {retry_after_secs}s")]
    CircuitOpen { retry_after_secs: u64 },
    #[error("upstream timed out")]
    UpstreamTimeout,
    #[error("bad gateway")]
    BadGateway,
    #[error("service unavailable")]
    ServiceUnavailable,
    #[error("internal error: {source}")]
    Internal {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl AppError {
    #[allow(dead_code)] // TODO(W5): used once route matching validates paths.
    pub fn bad_request(message: impl Into<Cow<'static, str>>) -> Self {
        Self::BadRequest {
            message: message.into(),
        }
    }

    pub fn internal(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::Internal {
            source: source.into(),
        }
    }

    pub(crate) fn not_found() -> Self {
        Self::NotFound {
            message: "no route matches this request".into(),
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::MethodNotAllowed { .. } => StatusCode::METHOD_NOT_ALLOWED,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::CircuitOpen { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::BadGateway => StatusCode::BAD_GATEWAY,
            Self::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest { .. } => "bad_request",
            Self::Unauthorized => "invalid_credentials",
            Self::Forbidden => "forbidden",
            Self::NotFound { .. } => "not_found",
            Self::Conflict { .. } => "conflict",
            Self::PayloadTooLarge => "payload_too_large",
            Self::RequestTimeout => "request_timeout",
            Self::MethodNotAllowed { .. } => "method_not_allowed",
            Self::RateLimited { .. } => "rate_limited",
            Self::CircuitOpen { .. } => "circuit_open",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::BadGateway => "bad_gateway",
            Self::ServiceUnavailable => "service_unavailable",
            Self::Internal { .. } => "internal_error",
        }
    }

    fn public_message(&self) -> Cow<'static, str> {
        match self {
            Self::BadRequest { message } => message.clone(),
            Self::Unauthorized => "invalid or missing bearer credentials".into(),
            Self::Forbidden => "the credential is not permitted to perform this request".into(),
            Self::NotFound { message } => message.clone(),
            Self::Conflict { message } => message.clone(),
            Self::PayloadTooLarge => "request body exceeds the configured limit".into(),
            Self::RequestTimeout => "the request exceeded the server deadline".into(),
            Self::MethodNotAllowed { .. } => "this route does not accept that method".into(),
            Self::RateLimited { .. } => "too many requests".into(),
            Self::CircuitOpen { .. } => "the upstream is temporarily unavailable".into(),
            Self::UpstreamTimeout => "the upstream did not respond in time".into(),
            Self::BadGateway => "the upstream returned an invalid response".into(),
            Self::ServiceUnavailable => "the service is temporarily unavailable".into(),
            Self::Internal { .. } => "an internal error occurred".into(),
        }
    }
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: Cow<'static, str>,
    request_id: Option<String>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();

        if status.is_server_error() {
            tracing::error!(error = %self, "request failed");
        } else {
            tracing::debug!(error = %self, "request rejected");
        }

        let body = ErrorEnvelope {
            error: ErrorBody {
                code: self.code(),
                message: self.public_message(),
                request_id: crate::request_context::current(),
            },
        };

        let retry_after = match self {
            Self::RateLimited {
                retry_after_secs, ..
            } => Some(retry_after_secs),
            Self::CircuitOpen { retry_after_secs } => Some(retry_after_secs),
            _ => None,
        };

        let rate_limit = match self {
            Self::RateLimited {
                limit,
                reset_after_secs,
                ..
            } => Some((limit, reset_after_secs)),
            _ => None,
        };

        let mut response = (status, Json(body)).into_response();

        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }

        if let Some(seconds) = retry_after
            && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
        {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, value);
        }

        if let Some((limit, reset_after_secs)) = rate_limit {
            let headers = response.headers_mut();

            if let Ok(value) = HeaderValue::from_str(&limit.to_string()) {
                headers.insert("ratelimit-limit", value);
            }
            if let Ok(value) = HeaderValue::from_str(&reset_after_secs.to_string()) {
                headers.insert("ratelimit-reset", value);
            }
        }

        if let Self::MethodNotAllowed { allowed } = &self {
            let allow = allowed
                .iter()
                .map(|method| method.as_str())
                .collect::<Vec<_>>()
                .join(", ");

            if let Ok(value) = HeaderValue::from_str(&allow) {
                response
                    .headers_mut()
                    .insert(header::ALLOW, value);
            }
        }

        response
    }
}
