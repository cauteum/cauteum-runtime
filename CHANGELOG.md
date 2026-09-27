# Changelog

## [Unreleased]

## [v0.0.2-alpha.1] - 2026-09-28

### Security

- Secrets KEK v2: scrypt+salt for passwords, raw 32-byte keys without KDF; durable migrate/rename.
- Stage agent/runtime credential files as mode `0600`.
- OIDC validates token `typ` and uses bounded HTTP client timeouts.
- Harden `best_effort` always logs Landlock/drop failures.

### Fixed

- JWT payload split uses `strings.Cut` instead of a custom scanner.
