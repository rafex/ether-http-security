# ether-http-security

Portable HTTP security policies for Ether.

## Scope

- CORS policy generation
- Security header defaults
- Trusted proxy hints
- IP allow/deny policy
- Rate limit configuration

This module is transport-agnostic. Adapters such as Jetty can consume these
policies and map them to server-specific handlers or filters.

## Current Jetty mapping

- `CorsPolicy` -> CORS response and preflight handling
- `SecurityHeadersPolicy` -> response headers
- `TrustedProxyPolicy` -> request IP resolution and forwarded-header customization
- `IpPolicy` -> allow/deny gate before route handling
- `RateLimitPolicy` -> local in-memory fixed-window limiter plus optional concurrency guard

## Important note on rate limiting

The current Jetty adapter uses an in-memory limiter per JVM instance. It is:

- local to one process
- reset on restart
- not distributed across replicas

This is intentional for v8. A later evolution can move the same policy model to a shared backend such as Redis.
