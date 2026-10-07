# Changelog

## [Unreleased]

## [v0.1.0-alpha.2] - 2026-10-07

### Added

- Add a Go workload supervisor for signal forwarding, child reaping, and authenticated lifecycle control over a Unix socket.
- Add OpenShell relay targets and policy-status reporting for gateway-backed sandboxes.
- Validate OCI process identity and apply filesystem hardening with explicit best-effort diagnostics.

### Compatibility

- Unix guests provide process-group signal forwarding, adopted-child reaping, and sidecar lifecycle reporting. Windows builds retain a command-launch fallback without those Unix lifecycle features.

### Changed

- Replace shell-based agent entrypoints with the Go supervisor and staged harness files.
- Update core, driver, proxy, and slogx to their published v0.1.0-alpha.2 modules; update Landlock to v0.10.1 and `golang.org/x/crypto` to v0.57.0.
- Distribute the module under Apache-2.0.

### Security

- Bound OIDC/token refresh requests and preserve fail-closed behavior for credential staging and policy lifecycle failures.

## [v0.0.2-alpha.1] - 2026-09-28

### Security

- Secrets KEK v2: scrypt+salt for passwords, raw 32-byte keys without KDF; durable migrate/rename.
- Stage agent/runtime credential files as mode `0600`.
- OIDC validates token `typ` and uses bounded HTTP client timeouts.
- Harden `best_effort` always logs Landlock/drop failures.

### Fixed

- JWT payload split uses `strings.Cut` instead of a custom scanner.
