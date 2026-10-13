1. Add client authentication.
2. Route requests only to configured upstream destinations.
3. Rate-limit by IP address.
4. Rate-limit by authenticated client to enforce fair quotas.
5. Enforce request body size limits with body-limit middleware.
6. Set request and upstream timeouts.
7. Limit overall request concurrency.
8. Bound concurrent requests per upstream.
9. Add upstream health checks and circuit breakers.
10. Retry only safe requests, using exponential backoff with jitter.
11. Preserve request IDs and traces.
12. Record useful security audit events.
13. Redact credentials and sensitive headers from logs.
