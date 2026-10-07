# SPDX-FileCopyrightText: Copyright (c) 2026 lkmavi
# SPDX-License-Identifier: Apache-2.0
#
# Multi-target sandbox images (Debian bookworm).
#   docker build --target cli -t whaleshell-sandbox:local .
#   docker build --target gui -t whaleshell-sandbox:gui .
#   docker build --target gpu -t whaleshell-sandbox:gpu .
#
# cli  — OpenShell-like base: languages, agents, networking, developer tools
# gui  — Debian bookworm: Chromium + Xvfb/openbox/noVNC
# gpu  — Debian bookworm + CUDA *userland* packages; host injects libcuda via CDI

ARG DEBIAN_BASE=debian:bookworm

FROM ${DEBIAN_BASE} AS cli
LABEL org.opencontainers.image.title="whaleshell-sandbox" \
      org.opencontainers.image.description="whaleshell agent sandbox (OpenShell-like toolset)" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/whaleshell/whaleshell-runtime"
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    bash \
    build-essential \
    python3 \
    python3-pip \
    python3-venv \
    vim-tiny \
    nano \
    dnsutils \
    iproute2 \
    iputils-ping \
    net-tools \
    netcat-openbsd \
    traceroute \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Node.js 22 (nodesource) + npm
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g npm@11

# GitHub CLI
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# Agent CLIs (OpenShell Community base parity)
RUN npm install -g \
        opencode-ai \
        @openai/codex \
        @github/copilot \
    && curl -fsSL https://claude.ai/install.sh | bash \
    && if [ -x /root/.local/bin/claude ]; then cp /root/.local/bin/claude /usr/local/bin/claude && chmod 755 /usr/local/bin/claude; fi \
    && npm cache clean --force

# uv for Python toolchain (optional; system python3 remains available)
COPY --from=ghcr.io/astral-sh/uv:0.10.8 /uv /usr/local/bin/uv

COPY whaleshell-init /usr/local/bin/whaleshell-init
RUN chmod 0755 /usr/local/bin/whaleshell-init \
    && mkdir -p /whaleshell/data/home/.local/bin /whaleshell/data/bin /workspace \
    && ln -sf /usr/bin/python3 /usr/local/bin/python || true
RUN groupadd --system sandbox \
    && useradd --system --gid sandbox --home-dir /sandbox --create-home --shell /bin/bash sandbox \
    && chown -R sandbox:sandbox /whaleshell/data /sandbox /workspace

ENV WHALESHELL_POLICY=/whaleshell/policy.yaml \
    HOME=/whaleshell/data/home \
    PATH=/whaleshell/data/home/.local/bin:/whaleshell/data/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /workspace
USER sandbox
ENTRYPOINT ["/usr/local/bin/whaleshell-init"]
CMD ["--", "sleep", "infinity"]

# GPU-oriented sandbox: toolchain for CUDA samples / torch wheels.
# Drivers and libcuda.so come from the host via CDI (whaleshell sandbox create --gpu).
FROM ${DEBIAN_BASE} AS gpu
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    bash \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
COPY whaleshell-init /usr/local/bin/whaleshell-init
RUN chmod 0755 /usr/local/bin/whaleshell-init \
    && groupadd --system sandbox \
    && useradd --system --gid sandbox --home-dir /sandbox --create-home --shell /bin/sh sandbox \
    && mkdir -p /whaleshell/data /workspace \
    && chown -R sandbox:sandbox /whaleshell/data /sandbox /workspace
ENV WHALESHELL_POLICY=/whaleshell/policy.yaml \
    HOME=/whaleshell/data/home \
    PATH=/whaleshell/data/home/.local/bin:/whaleshell/data/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    NVIDIA_VISIBLE_DEVICES=all \
    NVIDIA_DRIVER_CAPABILITIES=compute,utility
USER sandbox
ENTRYPOINT ["/usr/local/bin/whaleshell-init"]
CMD ["--", "sleep", "infinity"]

FROM ${DEBIAN_BASE} AS gui
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    xvfb \
    x11vnc \
    openbox \
    novnc \
    websockify \
    chromium \
    chromium-sandbox \
    fonts-liberation \
    fonts-dejavu-core \
    dbus-x11 \
    xterm \
    curl \
    git \
    bash \
    && rm -rf /var/lib/apt/lists/* \
    && chromium --version

COPY whaleshell-init /usr/local/bin/whaleshell-init
COPY whaleshell-gui-boot /usr/local/bin/whaleshell-gui-boot
COPY whaleshell-display-start /usr/local/bin/whaleshell-display-start
COPY chromium-whaleshell /usr/local/bin/chromium-whaleshell
RUN chmod 0755 /usr/local/bin/whaleshell-init /usr/local/bin/whaleshell-gui-boot \
        /usr/local/bin/whaleshell-display-start /usr/local/bin/chromium-whaleshell \
    && ln -sf /usr/local/bin/chromium-whaleshell /usr/local/bin/google-chrome \
    && ln -sf /usr/local/bin/chromium-whaleshell /usr/local/bin/chrome \
    && groupadd --system sandbox \
    && useradd --system --gid sandbox --home-dir /sandbox --create-home --shell /bin/bash sandbox \
    && mkdir -p /whaleshell/data /workspace \
    && chown -R sandbox:sandbox /whaleshell/data /sandbox /workspace

ENV WHALESHELL_POLICY=/whaleshell/policy.yaml \
    HOME=/whaleshell/data/home \
    PATH=/whaleshell/data/home/.local/bin:/whaleshell/data/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    DISPLAY=:99 \
    DISPLAY_MODE=none \
    WHALESHELL_DISPLAY_GEOM=1280x800x24 \
    CHROME_BIN=/usr/local/bin/chromium-whaleshell \
    BROWSER=/usr/local/bin/chromium-whaleshell

USER sandbox
ENTRYPOINT ["/usr/local/bin/whaleshell-init"]
CMD ["--", "/usr/local/bin/whaleshell-gui-boot"]
