<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Production Docker Images

This directory contains multi-stage Dockerfiles optimized for production deployments.

## Features

### Multi-Stage Builds

- **Build Stage**: `golang:1.26.4` - Full Go toolchain for compilation
- **Runtime Stage**: `nvcr.io/nvidia/distroless/go:v4.0.8` - Minimal distroless runtime environment

### Optimizations

- Static compilation with CGO disabled
- Strip debug symbols (`-w -s` flags)
- Minimal distroless base image for reduced attack surface
- Non-root user execution for security
- Proper signal handling

### Security Improvements

- Non-root user (`nvs` from distroless)
- Minimal distroless image with no shell or package manager
- CA certificates included
- Timezone data for proper logging

## Available Images

1. **Dockerfile.nico-rest-api** - REST API server
2. **Dockerfile.nico-rest-db** - Database Migrations
3. **Dockerfile.nico-rest-workflow** - Workflow Service
4. **Dockerfile.nico-rest-site-manager** - Site Manager service
5. **Dockerfile.nico-rest-site-agent** - Site Agent
6. **Dockerfile.nico-flow** - NICo Flow

The `nico-rest-cert-manager` image is not built from this directory. The Cert
Manager is a Rust binary in the Cargo workspace, and its Dockerfile is
[`crates/rest-api-cert-manager/Dockerfile`](../../../crates/rest-api-cert-manager/Dockerfile).
It builds with the monorepo root as the context, uses a digest-pinned
`rust:*-slim-bookworm` builder and a `gcr.io/distroless/cc-debian12` runtime,
and runs as UID/GID 1000.

## Building Images

### Build from the `rest-api` Directory

The Dockerfiles in this directory must be built with the `rest-api` directory as
the context, because they require access to multiple modules:

```bash
cd /path/to/infra-controller/rest-api

docker build \
  -f docker/production/Dockerfile.nico-rest-api \
  -t nico-rest-api:latest \
  .
```

Build the Cert Manager image from the monorepo root instead:

```bash
cd /path/to/infra-controller

docker build \
  -f crates/rest-api-cert-manager/Dockerfile \
  -t nico-rest-cert-manager:latest \
  .
```

### Build All Images

`make docker-build`, run from the `rest-api` directory, builds every REST image,
including `nico-rest-cert-manager` from its Rust Dockerfile:

```bash
make docker-build
```
