# API Gateway Roadmap

Completed gateway primitives have been removed from this active list: basic API-key middleware, request IDs and tracing, request-body size limiting, and the SWAPI upstream timeout.

## Authorization and credentials

1. Add authorization coverage for missing/wrong keys, missing scopes, expired/revoked keys, suspended clients/tenants, and credential-store failures.
2. Generate high-entropy API keys securely, show the secret only once, and support expiry, rotation, and revocation.
3. Replace the in-memory credential store with shared persistent storage so keys and revocations work across restarts and gateway replicas.
4. Audit key creation, rotation, revocation, and authentication failures without recording secret material.

## Request and abuse protection

5. Add rate limits for unauthenticated traffic by client IP and authenticated traffic by client or tenant; define trusted-proxy rules before using forwarded IP headers.
6. Add an overall inbound request deadline in addition to the existing upstream timeout.
7. Limit total in-flight requests and concurrent requests to each upstream.
8. Define a consistent policy for malformed credentials, authentication failures, authorization failures, and rate-limit responses.

## Upstream safety and resilience

9. Validate configured upstream URLs against an allowlist of schemes, hosts, and ports to prevent unintended destinations and SSRF.
10. Add upstream health checks and circuit breakers.
11. Retry only safe/idempotent requests, with bounded exponential backoff and jitter.
12. Define which request headers and response headers may pass through; strip hop-by-hop and sensitive headers.

## Operations and deployment

13. Require HTTPS at the gateway edge and document the trusted TLS-termination setup.
14. Make credential redaction an explicit logging/tracing rule and verify no authorization header or secret reaches logs, traces, or error responses.
15. Add metrics for request volume, latency, auth decisions, throttling, and upstream health.
16. Separate liveness and readiness checks; add graceful shutdown and telemetry flush.
17. Validate production configuration at startup, including upstream allowlists, timeouts, limits, and credential-store availability.
