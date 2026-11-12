# Security policy

## Reporting a vulnerability

Please don't open a public issue for a security problem. Use GitHub's private
vulnerability reporting on this repository (Security → Report a vulnerability), or email
the maintainer listed on the GitHub profile.

Include:

- what the issue is and the impact you believe it has
- the smallest reproduction you can build (request, config, or steps)
- the version or commit you tested

You will get an acknowledgement, an assessment, and a fix or mitigation plan. Please give
us a reasonable window before publishing.

## Supported versions

`main` is the only supported branch. Releases are tagged; security fixes land on `main`
and in a patch release.

## Scope

The gateway process, its configuration surface, the control plane, and the deployment
manifests in this repository.

Out of scope: vulnerabilities in upstream services, the host OS or container runtime, and
deployments that disable the documented safeguards (for example running with
`AUTH_CACHE_TTL_SECS=0` plus a permissive database, or terminating TLS at an untrusted
edge).

## What is already true

- API keys are stored as peppered HMAC verifiers, never plaintext, and compared in
  constant time.
- Admin tokens are named identities with scopes; `/metrics` can require its own token.
- Upstream destinations are allowlisted, redirects are never followed, and hop-by-hop,
  forwarded, and credential headers are stripped in both directions.
- Paths are rejected before matching when they could normalize differently in the URL
  parser than in the router.
- Every control-plane mutation is audited with the actor and request id.
