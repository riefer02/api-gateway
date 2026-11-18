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
    #[error("bad request: {message}")]
    BadRequest { message: Cow<'static, str> },
    #[error("unauthorized")]
    Unauthorized,
    #[error("oauth unauthorized")]
    OAuthUnauthorized {
        /// `invalid_token`, or `None` when no credential was presented.
        error: Option<&'static str>,
        scope: Option<String>,
        resource_metadata: String,
    },
    #[error("forbidden")]
    Forbidden,
    #[error("oauth insufficient scope")]
    OAuthForbidden {
        scope: String,
        resource_metadata: String,
    },
    #[error("not found: {message}")]
    NotFound { message: Cow<'static, str> },
    #[error("conflict: {message}")]
    Conflict { message: Cow<'static, str> },
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("response too large")]
    ResponseTooLarge,
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
    #[error("upstream authentication failed")]
    UpstreamAuthFailed,
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
            Self::Unauthorized | Self::OAuthUnauthorized { .. } => StatusCode::UNAUTHORIZED,
            Self::Forbidden | Self::OAuthForbidden { .. } => StatusCode::FORBIDDEN,
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::ResponseTooLarge => StatusCode::BAD_GATEWAY,
            Self::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::MethodNotAllowed { .. } => StatusCode::METHOD_NOT_ALLOWED,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::CircuitOpen { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::UpstreamAuthFailed => StatusCode::BAD_GATEWAY,
            Self::BadGateway => StatusCode::BAD_GATEWAY,
            Self::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest { .. } => "bad_request",
            Self::Unauthorized | Self::OAuthUnauthorized { .. } => "invalid_credentials",
            Self::Forbidden | Self::OAuthForbidden { .. } => "forbidden",
            Self::NotFound { .. } => "not_found",
            Self::Conflict { .. } => "conflict",
            Self::PayloadTooLarge => "payload_too_large",
            Self::ResponseTooLarge => "response_too_large",
            Self::RequestTimeout => "request_timeout",
            Self::MethodNotAllowed { .. } => "method_not_allowed",
            Self::RateLimited { .. } => "rate_limited",
            Self::CircuitOpen { .. } => "circuit_open",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::UpstreamAuthFailed => "upstream_auth_failed",
            Self::BadGateway => "bad_gateway",
            Self::ServiceUnavailable => "service_unavailable",
            Self::Internal { .. } => "internal_error",
        }
    }

    fn public_message(&self) -> Cow<'static, str> {
        match self {
            Self::BadRequest { message } => message.clone(),
            Self::Unauthorized | Self::OAuthUnauthorized { .. } => {
                "invalid or missing bearer credentials".into()
            }
            Self::Forbidden | Self::OAuthForbidden { .. } => {
                "the credential is not permitted to perform this request".into()
            }
            Self::NotFound { message } => message.clone(),
            Self::Conflict { message } => message.clone(),
            Self::PayloadTooLarge => "request body exceeds the configured limit".into(),
            Self::ResponseTooLarge => "the upstream response exceeds the configured limit".into(),
            Self::RequestTimeout => "the request exceeded the server deadline".into(),
            Self::MethodNotAllowed { .. } => "this route does not accept that method".into(),
            Self::RateLimited { .. } => "too many requests".into(),
            Self::CircuitOpen { .. } => "the upstream is temporarily unavailable".into(),
            Self::UpstreamTimeout => "the upstream did not respond in time".into(),
            Self::UpstreamAuthFailed => "the upstream credential exchange failed".into(),
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

        match &self {
            Self::Unauthorized => {
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            }
            Self::OAuthUnauthorized {
                error,
                scope,
                resource_metadata,
            } => {
                let mut challenge = String::from("Bearer ");

                if let Some(error) = error {
                    challenge.push_str(&format!("error=\"{error}\", "));
                }
                if let Some(scope) = scope
                    && !scope.is_empty()
                {
                    challenge.push_str(&format!("scope=\"{}\", ", escape_challenge(scope)));
                }
                challenge.push_str(&format!(
                    "resource_metadata=\"{}\"",
                    escape_challenge(resource_metadata)
                ));

                if let Ok(value) = HeaderValue::from_str(&challenge) {
                    response
                        .headers_mut()
                        .insert(header::WWW_AUTHENTICATE, value);
                }
            }
            Self::OAuthForbidden {
                scope,
                resource_metadata,
            } => {
                let challenge = format!(
                    "Bearer error=\"insufficient_scope\", scope=\"{}\", resource_metadata=\"{}\"",
                    escape_challenge(scope),
                    escape_challenge(resource_metadata)
                );

                if let Ok(value) = HeaderValue::from_str(&challenge) {
                    response
                        .headers_mut()
                        .insert(header::WWW_AUTHENTICATE, value);
                }
            }
            _ => {}
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

/// OAuth challenges are header values, not JSON: strip anything that could
/// break the quoted-string grammar or inject a second header.
fn escape_challenge(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control() && *character != '"' && *character != '\\')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn render(error: AppError) -> Response {
        error.into_response()
    }

    #[tokio::test]
    async fn every_variant_maps_to_a_status_and_a_stable_code() {
        let cases = [
            (
                AppError::bad_request("bad"),
                StatusCode::BAD_REQUEST,
                "bad_request",
            ),
            (
                AppError::Unauthorized,
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
            ),
            (AppError::Forbidden, StatusCode::FORBIDDEN, "forbidden"),
            (AppError::not_found(), StatusCode::NOT_FOUND, "not_found"),
            (
                AppError::PayloadTooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
            ),
            (
                AppError::RequestTimeout,
                StatusCode::REQUEST_TIMEOUT,
                "request_timeout",
            ),
            (
                AppError::MethodNotAllowed {
                    allowed: vec![axum::http::Method::GET],
                },
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
            ),
            (
                AppError::RateLimited {
                    retry_after_secs: 5,
                    limit: 10,
                    reset_after_secs: 5,
                },
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
            ),
            (
                AppError::CircuitOpen {
                    retry_after_secs: 30,
                },
                StatusCode::SERVICE_UNAVAILABLE,
                "circuit_open",
            ),
            (
                AppError::UpstreamTimeout,
                StatusCode::GATEWAY_TIMEOUT,
                "upstream_timeout",
            ),
            (AppError::BadGateway, StatusCode::BAD_GATEWAY, "bad_gateway"),
            (
                AppError::ServiceUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
            ),
            (
                AppError::internal("boom"),
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
        ];

        for (error, status, code) in cases {
            let response = render(error).await;
            assert_eq!(response.status(), status, "status for {code}");

            let body = to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON envelope");

            assert_eq!(json["error"]["code"], code);
            assert!(
                json["error"]["message"]
                    .as_str()
                    .is_some_and(|message| !message.is_empty()),
                "message for {code} is empty"
            );
            assert!(
                json["error"]
                    .get("request_id")
                    .is_some()
            );
        }
    }

    /// The caller-supplied text is what a client sees, so it must survive.
    #[tokio::test]
    async fn bad_request_keeps_the_caller_facing_message() {
        let response = render(AppError::bad_request("field `name` is required")).await;

        let body = to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON envelope");

        assert_eq!(json["error"]["message"], "field `name` is required");
    }

    #[tokio::test]
    async fn circuit_open_carries_retry_after() {
        let response = render(AppError::CircuitOpen {
            retry_after_secs: 12,
        })
        .await;

        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .unwrap(),
            "12"
        );
    }

    #[tokio::test]
    async fn unauthorized_offers_a_challenge() {
        let response = render(AppError::Unauthorized).await;

        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .unwrap(),
            "Bearer"
        );
    }

    #[tokio::test]
    async fn rate_limited_carries_retry_metadata() {
        let response = render(AppError::RateLimited {
            retry_after_secs: 7,
            limit: 60,
            reset_after_secs: 7,
        })
        .await;

        let headers = response.headers();
        assert_eq!(
            headers
                .get(header::RETRY_AFTER)
                .unwrap(),
            "7"
        );
        assert_eq!(headers.get("ratelimit-limit").unwrap(), "60");
        assert_eq!(headers.get("ratelimit-reset").unwrap(), "7");
    }

    #[tokio::test]
    async fn method_not_allowed_lists_the_methods() {
        let response = render(AppError::MethodNotAllowed {
            allowed: vec![axum::http::Method::GET, axum::http::Method::HEAD],
        })
        .await;

        assert_eq!(
            response
                .headers()
                .get(header::ALLOW)
                .unwrap(),
            "GET, HEAD"
        );
    }

    /// The whole point of the internal variant: the cause is for logs, never
    /// for the client.
    #[tokio::test]
    async fn internal_errors_do_not_leak_their_cause() {
        let response = render(AppError::internal("secret database detail")).await;

        let body = to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert!(!body.contains("secret database detail"));
        assert!(body.contains("\"code\":\"internal_error\""));
    }

    #[tokio::test]
    async fn oauth_unauthorized_points_at_the_metadata() {
        let response = render(AppError::OAuthUnauthorized {
            error: Some("invalid_token"),
            scope: None,
            resource_metadata: "https://gw.example.com/.well-known/oauth-protected-resource/mcp"
                .to_owned(),
        })
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .unwrap(),
            "Bearer error=\"invalid_token\", resource_metadata=\"https://gw.example.com/.well-known/oauth-protected-resource/mcp\""
        );
    }

    #[tokio::test]
    async fn oauth_forbidden_is_a_step_up_challenge() {
        let response = render(AppError::OAuthForbidden {
            scope: "mcp:tools read".to_owned(),
            resource_metadata: "https://gw.example.com/.well-known/oauth-protected-resource"
                .to_owned(),
        })
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .unwrap(),
            "Bearer error=\"insufficient_scope\", scope=\"mcp:tools read\", resource_metadata=\"https://gw.example.com/.well-known/oauth-protected-resource\""
        );
    }

    #[tokio::test]
    async fn oauth_challenge_values_cannot_inject_headers() {
        let response = render(AppError::OAuthForbidden {
            scope: "read\"\r\nX-Evil: 1".to_owned(),
            resource_metadata: "https://gw.example.com/mcp".to_owned(),
        })
        .await;

        let challenge = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();

        assert!(!challenge.contains('\r'));
        assert!(!challenge.contains('\n'));
        assert_eq!(
            response
                .headers()
                .get_all(header::WWW_AUTHENTICATE)
                .iter()
                .count(),
            1
        );
    }
}
