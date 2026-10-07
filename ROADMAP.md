# Roadmap — whaleshell-runtime

Status: **v0.1.0-alpha.1** (alpha) · Depends on whaleshell-core / whaleshell-driver / whaleshell-proxy `v0.1.0-alpha.1`

## This module

| ID | Item | Notes |
|----|------|-------|
| T1 | **Image catalog** | Keep GHCR `sandboxes/{base,gui,gpu}` in sync with tags |
| T2 | **Secrets store** | Map/Env → Vault adapters (hub R3) |
| T3 | **Identity federation** | Align gateway OIDC/mTLS and workload identity with OpenShell config and authorization semantics (hub R3) |
| T4 | **Harden depth** | Landlock/seccomp profile documentation |

## Release

Tagged after core + driver + proxy in the cascade.
