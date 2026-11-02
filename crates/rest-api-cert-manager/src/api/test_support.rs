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

//! Shared fixtures for handler, middleware and router tests. They include an
//! [`AppState`] built on a generated CA, the observable parts of a response
//! and the expected request metric series.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::header::{CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use axum::response::Response;

use super::{APPLICATION_JSON_UTF8, AppState, RequestMetrics, TEXT_PLAIN_UTF8};
use crate::pki::test_support::TestCaPem;

/// Version string that `GET /version` returns for the test state.
pub(super) const TEST_VERSION: &str = "v1.2.3-test";

/// Histogram buckets as the exposition prints them. These are the Prometheus
/// client's default buckets, which dashboards and alerts rely on.
const HISTOGRAM_BUCKETS: [&str; 12] = [
    "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5", "10", "+Inf",
];

/// Returns state for `ca` with the default base DNS name and metric prefix.
pub(super) fn app_state(ca: &TestCaPem) -> AppState {
    AppState {
        certificate_authority: Arc::new(ca.load()),
        base_dns: Arc::from("temporal.local"),
        request_metrics: RequestMetrics::new("nico_rest_cert_manager")
            .expect("the default namespace is a valid metric prefix"),
        version: TEST_VERSION,
    }
}

/// Returns the DER of the first block in `certificate`, which is PEM text.
pub(super) fn der(certificate: &str) -> Vec<u8> {
    pem::parse(certificate)
        .expect("a PEM certificate")
        .into_contents()
}

/// Returns the exposition lines of one series of the histogram `name`. There's
/// a bucket line per default bucket and a sum line, all showing `value`. The
/// last line shows `count`.
pub(super) fn histogram_series(name: &str, labels: &str, value: &str, count: u64) -> Vec<String> {
    HISTOGRAM_BUCKETS
        .iter()
        .map(|bucket| format!("{name}_bucket{{{labels},le=\"{bucket}\"}} {value}"))
        .chain([
            format!("{name}_sum{{{labels}}} {value}"),
            format!("{name}_count{{{labels}}} {count}"),
        ])
        .collect()
}

/// The parts of a response that the wire contract defines.
#[derive(Debug, PartialEq)]
pub(super) struct Observed {
    pub(super) status: u16,
    pub(super) content_type: Option<String>,
    pub(super) content_type_options: Option<String>,
    pub(super) body: Vec<u8>,
}

impl Observed {
    /// Reads the whole response.
    pub(super) async fn from_response(response: Response) -> Self {
        let header = |name| {
            response
                .headers()
                .get(name)
                .map(|value: &axum::http::HeaderValue| {
                    value.to_str().expect("ASCII header").to_owned()
                })
        };
        let status = response.status().as_u16();
        let content_type = header(CONTENT_TYPE);
        let content_type_options = header(X_CONTENT_TYPE_OPTIONS);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read the response body")
            .to_vec();
        Self {
            status,
            content_type,
            content_type_options,
            body,
        }
    }

    /// Returns a `text/plain; charset=utf-8` response.
    pub(super) fn text(status: u16, body: impl AsRef<[u8]>) -> Self {
        Self {
            status,
            content_type: Some(TEXT_PLAIN_UTF8.to_owned()),
            content_type_options: None,
            body: body.as_ref().to_vec(),
        }
    }

    /// Returns an `application/json; charset=utf-8` response.
    pub(super) fn json(status: u16, body: &str) -> Self {
        Self {
            content_type: Some(APPLICATION_JSON_UTF8.to_owned()),
            ..Self::text(status, body)
        }
    }

    /// Returns a status without a media type or body, such as a `405`.
    pub(super) fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: None,
            content_type_options: None,
            body: Vec::new(),
        }
    }

    /// Returns the `404` for a path that no route matches.
    pub(super) fn not_found() -> Self {
        Self {
            content_type_options: Some("nosniff".to_owned()),
            ..Self::text(404, "404 page not found\n")
        }
    }
}
