---
date: 2026-11-16
---

# Trust loopback HTTP without a switch

## Status

Accepted.

## Context

Tests reach fake registries and download servers over plain HTTP on loopback, so `allow_http_loopback` entered `gleam.toml` and `candidate/v1`, and `allowHttpLoopback` entered the Action.

## Decision

A registry, GitHub API, or download URL uses HTTPS, or HTTP to a numeric loopback address in `127.0.0.0/8` or `::1`, with no key that changes the rule.
[Secure Contexts](https://www.w3.org/TR/secure-contexts/#is-origin-trustworthy) counts both ranges as potentially trustworthy, and loopback traffic never leaves the host.

## Alternatives

Keeping the switch leaves a public, sealed field that weakens transport for anyone.
Trusting a test certificate authority from an environment variable gives production certificate validation a redirect.

## Consequences

An old configuration or Candidate that names the key fails as an unknown field.
`localhost` still needs HTTPS, because resolving it can leave the host.

## Confirmation

Tests refuse `http://` to a host name or public address and accept `127.0.0.1` and `[::1]`, for the registry and the Action.
Reconsider if a less trusted local process could impersonate a loopback service.
