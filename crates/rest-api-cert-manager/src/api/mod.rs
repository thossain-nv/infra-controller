/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! The HTTP API. It contains the routes each listener serves, their handlers,
//! request/response models and request middleware. Statuses, media types and
//! bodies are fixed because Site Manager and other deployed clients depend on
//! them. These routes aren't in the REST OpenAPI spec, so the handler docs are
//! their reference.

mod error;
mod handler;
mod middleware;
mod model;
mod routes;
#[cfg(test)]
mod test_support;

use std::sync::Arc;

pub(crate) use middleware::{MetricsError, RequestMetrics};
pub(crate) use routes::{insecure_router, tls_router};

use crate::pki::CertificateAuthority;

/// Media type of every plain-text response, including the raw DER that
/// `GET /v1/pki/ca` returns.
const TEXT_PLAIN_UTF8: &str = "text/plain; charset=utf-8";

/// Media type of every `POST /v1/pki/cloud-cert` response, including failures.
const APPLICATION_JSON_UTF8: &str = "application/json; charset=utf-8";

/// State shared by the handlers. It's cloned for every request, so each field
/// is cheap to clone.
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) certificate_authority: Arc<CertificateAuthority>,
    /// Base DNS name appended to requested names that don't end in `.com` or
    /// `.local`. The `--ca-base-dns` flag sets it.
    pub(crate) base_dns: Arc<str>,
    pub(crate) request_metrics: RequestMetrics,
    /// Version string that `GET /version` returns.
    pub(crate) version: &'static str,
}
