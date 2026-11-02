# syntax=docker/dockerfile:1.7

# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Image for `nico-rest-cert-manager`. Build it from the repository root, since
# that's where the Cargo workspace is:
#
#   docker buildx build --platform linux/amd64 \
#     -f crates/rest-api-cert-manager/Dockerfile \
#     --build-arg VERSION=0.1.0 -t nico-rest-cert-manager:latest .
#
# NOTE: Cross-compilation architecture
# QEMU emulation segfaults while assembling the hand-written assembly in
# `aws-lc-sys`. So the builder stage always runs natively on the build host
# (`$BUILDPLATFORM`) and cross-compiles to the GNU triple for `TARGETARCH`.
#
# The builder is pinned by manifest-list digest, so a rebuild can't pick up
# different toolchain content without a source change. The tag documents the
# version and must match `rust-toolchain.toml`.
ARG BUILDER_BASE=rust:1.97.1-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3
# Every target architecture uses this one overridable runtime base. It's a
# single manifest-list digest, so the per-arch base versions can't differ.
ARG RUNTIME_BASE=gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

FROM --platform=$BUILDPLATFORM ${BUILDER_BASE} AS builder

# There's no default. BuildKit sets `TARGETARCH` from the requested platform.
# The REST CI workflow also passes it explicitly.
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && case "$TARGETARCH" in \
         amd64) \
           if [ "$(uname -m)" != "x86_64" ]; then \
             apt-get install -y --no-install-recommends \
               gcc-x86-64-linux-gnu libc6-dev-amd64-cross; \
           else \
             apt-get install -y --no-install-recommends gcc libc6-dev; \
           fi ;; \
         arm64) \
           if [ "$(uname -m)" != "aarch64" ]; then \
             apt-get install -y --no-install-recommends \
               gcc-aarch64-linux-gnu libc6-dev-arm64-cross; \
           else \
             apt-get install -y --no-install-recommends gcc libc6-dev; \
           fi ;; \
         *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
       esac \
    && rm -rf /var/lib/apt/lists/*

ENV CARGO_HOME=/cargo-home
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
ENV CARGO_TARGET_DIR=/cargo-target
ENV RUST_BACKTRACE=1

WORKDIR /workspace

# Only the workspace files below are copied, so the build directory isn't a
# git repository. When `git rev-parse` fails, `carbide_version::build()`
# ignores `VERSION` and leaves the version blank. An empty repository is
# enough for `carbide_version::build()` to stamp `VERSION`.
RUN git init -q

# Only the Cargo workspace is copied, so unrelated repository changes don't
# invalidate this layer.
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY .cargo/ .cargo/
COPY crates/ crates/

# These are declared after the toolchain and source layers, so a new version
# reuses those layers. `carbide_version::build()` reads them when `build.rs`
# runs. The binary reports `VERSION` from `GET /version` and `--version`.
ARG VERSION=dev
ARG CI_COMMIT_SHORT_SHA
ENV VERSION=${VERSION}
ENV CI_COMMIT_SHORT_SHA=${CI_COMMIT_SHORT_SHA}

# Build the release binary, cross-compiling when builder and target differ.
RUN --mount=type=cache,id=nico-rest-cert-manager-cargo-home-$TARGETARCH,target=/cargo-home,sharing=locked \
    --mount=type=cache,id=nico-rest-cert-manager-cargo-target-$TARGETARCH,target=/cargo-target,sharing=locked \
    case "$TARGETARCH" in \
      amd64) \
        RUST_TARGET=x86_64-unknown-linux-gnu; \
        if [ "$(uname -m)" != "x86_64" ]; then \
          export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
                 CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc; \
        fi ;; \
      arm64) \
        RUST_TARGET=aarch64-unknown-linux-gnu; \
        if [ "$(uname -m)" != "aarch64" ]; then \
          export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
                 CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc; \
        fi ;; \
    esac && \
    rustup target add "$RUST_TARGET" && \
    cargo build -p nico-rest-cert-manager --bin nico-rest-cert-manager --locked --release \
      --target "$RUST_TARGET" && \
    mkdir -p /artifacts/app && \
    cp "/cargo-target/$RUST_TARGET/release/nico-rest-cert-manager" /artifacts/app/nico-rest-cert-manager

# The runtime image is distroless with glibc and nothing else. The serving
# certificate is kept in memory, so the binary doesn't need a writable path.
FROM ${RUNTIME_BASE}

ARG VERSION=dev
ARG CI_COMMIT_SHORT_SHA
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${CI_COMMIT_SHORT_SHA}"
LABEL org.opencontainers.image.title="nico-rest-cert-manager"
LABEL org.opencontainers.image.description="NICo REST Cert Manager: issues the site and cloud TLS certificates"
LABEL org.opencontainers.image.vendor="NVIDIA"

COPY --from=builder /artifacts/app/ /app/

# The Helm chart and kustomize base run the pod with `runAsNonRoot`,
# `runAsUser: 1000` and `fsGroup: 1000`. The kubelet rejects a named user
# under `runAsNonRoot` with `CreateContainerConfigError`, so this uses a
# numeric UID:GID.
USER 1000:1000

# Port `8000` is the TLS listener (`--tls-port`) and port `8001` is the plain
# HTTP listener (`--insecure-port`).
EXPOSE 8000 8001

ENTRYPOINT ["/app/nico-rest-cert-manager"]
