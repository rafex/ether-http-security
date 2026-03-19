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
