# Roadmap — cauteum-runtime

Status: **v0.1.4** (stable numbered release) · Depends on core / driver `v0.1.4`; slogx `v0.1.2`

## This module

| ID | Item | Notes |
|----|------|-------|
| T1 | **Image catalog** | Keep GHCR `sandboxes/{base,gui,gpu}` in sync with tags |
| T2 | **Secrets store** | Map/Env → Vault adapters |
| T3 | **Identity federation** | Align gateway OIDC/mTLS and workload identity with OpenShell config and authorization semantics |
| T4 | **Harden depth** | Landlock/seccomp profile documentation |

## Release

Tagged after core + driver + proxy in the cascade.
