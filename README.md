<h1 align="center">cauteum-runtime</h1>

<p align="center">
  <strong>Sandbox glue & images</strong><br>
  Lifecycle helpers, harden, secrets store, cauteum-init, and GHCR sandbox images.
</p>
<p align="center">
  <a href="https://github.com/cauteum-haven/cauteum-runtime/actions/workflows/ci.yml"><img src="https://github.com/cauteum-haven/cauteum-runtime/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pkg.go.dev/github.com/cauteum-haven/cauteum-runtime"><img src="https://pkg.go.dev/badge/github.com/cauteum-haven/cauteum-runtime.svg" alt="Go Reference"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/cauteum-haven/cauteum-runtime"><img src="https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go" alt="Go Version"></a>

  <a href="https://github.com/cauteum-haven/cauteum-runtime/actions/workflows/images-sandbox.yml"><img src="https://github.com/cauteum-haven/cauteum-runtime/actions/workflows/images-sandbox.yml/badge.svg" alt="images-sandbox"></a>
</p>
<p align="center">
  <sub>Part of the <a href="https://github.com/cauteum-haven">cauteum / cauteum</a> ecosystem</sub>
</p>

---

## Overview

See the [architecture](https://cauteum.github.io/concepts/architecture/) and [security](https://cauteum.github.io/concepts/security/) pages for the sandbox process and its trust boundaries.

**cauteum-runtime** ties sandbox creation together: guest init (`cauteum-init`), Landlock/seccomp harden, secrets store, inference snippets, and the Debian-based sandbox image flavors published to GHCR.

### Key Features

| Category | Capabilities |
|----------|--------------|
| **Images** | `sandboxes/{base,gui,gpu}` on `ghcr.io/cauteum/cauteum` |
| **Init** | `cauteum-init` — Landlock, seccomp, workspace mount |
| **Supervisor** | `cauteum-supervisor` — PID 1 workload lifecycle and sandbox-side loopback dial socket for `ForwardTcp` |
| **Relay** | `relaytarget` — validates and dials loopback TCP targets inside the sandbox network namespace over the private shared Unix socket |
| **Secrets** | Host-side store resolved into guest placeholders |
| **Harden** | Linux sandbox hardening helpers |
| **Inference** | Local host-gateway model URL helpers |

---

## Installation

Build from this checkout in the sibling `go.work` workspace. The published alpha tag still declares an older module path, so a standalone `go get` needs a new coordinated release.

**Images (after CI publish):**

```text
ghcr.io/cauteum/cauteum/sandboxes/base:latest
ghcr.io/cauteum/cauteum/sandboxes/gui:latest
ghcr.io/cauteum/cauteum/sandboxes/gpu:latest
```

**Requirements:** Go 1.27+

Sandbox images declare `USER sandbox` and give that account writable ownership of `/sandbox`, `/workspace`, and `/cauteum/data`. Docker/Podman start the hardened supervisor as root while passing the inspected image's OCI `Config.User` to the workload identity resolver; explicit OpenShell policy fields take precedence. Custom images that omit OCI `USER` must specify both process identity fields in policy or use a backend that provides resolved `OPENSHELL_SANDBOX_UID` / `OPENSHELL_SANDBOX_GID` values.

---

## Quick Start

```bash
# build guest init into the image context (as CI does)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -o images/sandbox/cauteum-init ./cmd/cauteum-init

docker build -t cauteum-sandbox:local --target cli -f images/sandbox/Dockerfile images/sandbox
```

---

## Package Structure

| Path | Purpose |
|------|---------|
| `cmd/cauteum-init` | Guest entrypoint |
| `sandbox/` | Lifecycle helpers |
| `harden/` | Landlock / seccomp |
| `secrets/` | Secret store |
| `images/sandbox/` | Multi-target Dockerfile |
| `inference/` | Local model policy snippets |
| `agentconfig/` | Supervisor policy-advisor and `AGENTS.md` installation |


---

## Related

| Resource | Link |
|----------|------|
| Roadmap | [ROADMAP.md](./ROADMAP.md) |
| Organization | [https://github.com/cauteum](https://github.com/cauteum-haven) |
| Organization overview | [github.com/cauteum](https://github.com/cauteum-haven) |
| pkg.go.dev | [`github.com/cauteum-haven/cauteum-runtime`](https://pkg.go.dev/github.com/cauteum-haven/cauteum-runtime) |

## License

[Apache-2.0](./LICENSE) © cauteum
