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

//! The request metrics. Their names, labels, buckets and HELP text are an
//! existing contract that dashboards and alerts use.
//!
//! Existing metric contracts are preserved, but `carbide_instrument` events
//! can't express this one:
//! - The prefix is chosen at startup (`METRICS_NAMESPACE`).
//! - `_http_request_counts` doesn't have a `_total` suffix.
//! - The histogram uses the Prometheus client's default buckets.
//! - The HELP text predates the "Number of" convention.
//!
//! So these metrics use the `prometheus` crate directly. No process or runtime
//! series are exported.

use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use prometheus::{
    Histogram, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};

/// Error returned when the request metrics can't be registered.
#[derive(Debug, thiserror::Error)]
#[error("invalid metrics namespace {namespace:?}: {error}")]
pub(crate) struct MetricsError {
    namespace: String,
    error: prometheus::Error,
}

/// Duration and count of every request to a matched TLS route, kept in their
/// own registry. The `path` label is the matched route, so it has one of six
/// values.
#[derive(Clone)]
pub(crate) struct RequestMetrics {
    registry: Registry,
    duration_seconds: HistogramVec,
    /// Alias of `requests_total` with the same values. It exists for
    /// dashboards and alerts that use this name.
    request_counts: IntCounterVec,
    requests_total: IntCounterVec,
}

impl RequestMetrics {
    /// Registers `<namespace>_http_duration_seconds{path,method}` and the
    /// identical counters `<namespace>_http_request_counts` and
    /// `<namespace>_http_requests_total{path,method,status_code}`.
    pub(crate) fn new(namespace: &str) -> Result<Self, MetricsError> {
        let registered = Self::register(namespace);
        registered.map_err(|error| MetricsError {
            namespace: namespace.to_owned(),
            error,
        })
    }

    fn register(namespace: &str) -> Result<Self, prometheus::Error> {
        let duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                format!("{namespace}_http_duration_seconds"),
                "Duration of HTTP requests.",
            )
            .buckets(prometheus::DEFAULT_BUCKETS.to_vec()),
            &["path", "method"],
        )?;
        let counter = |name: &str| {
            IntCounterVec::new(
                Opts::new(format!("{namespace}_{name}"), "Counter of HTTP requests."),
                &["path", "method", "status_code"],
            )
        };
        let request_counts = counter("http_request_counts")?;
        let requests_total = counter("http_requests_total")?;

        let registry = Registry::new();
        registry.register(Box::new(duration_seconds.clone()))?;
        registry.register(Box::new(request_counts.clone()))?;
        registry.register(Box::new(requests_total.clone()))?;
        Ok(Self {
            registry,
            duration_seconds,
            request_counts,
            requests_total,
        })
    }

    /// Returns the current values in the Prometheus text exposition format.
    pub(crate) fn encode(&self) -> Result<String, prometheus::Error> {
        TextEncoder::new().encode_to_string(&self.registry.gather())
    }

    /// Starts recording a request to `path`. This creates the route's
    /// histogram series if it doesn't exist yet. So a scrape shows its own
    /// route's series, with the count of earlier requests.
    fn start_request<'a>(&'a self, path: &'a str, method: Method) -> RequestRecord<'a> {
        RequestRecord {
            duration_seconds: self
                .duration_seconds
                .with_label_values(&[path, method.as_str()]),
            started: Instant::now(),
            metrics: self,
            path,
            method,
            status_code: StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// One request in flight, recorded when it's dropped. The histogram observes
/// the elapsed time. Both counters count `status_code`.
///
/// The status is `503` until the handler responds. So a request that's
/// cancelled before then is counted as `503`, like a request that timed out.
/// For example, the client can reset its HTTP/2 stream, or shutdown can close
/// the connection after the drain. Either way the histogram count equals the
/// counter totals.
struct RequestRecord<'a> {
    duration_seconds: Histogram,
    started: Instant,
    metrics: &'a RequestMetrics,
    path: &'a str,
    method: Method,
    status_code: StatusCode,
}

impl Drop for RequestRecord<'_> {
    fn drop(&mut self) {
        self.duration_seconds
            .observe(self.started.elapsed().as_secs_f64());
        let labels = [self.path, self.method.as_str(), self.status_code.as_str()];
        for counter in [&self.metrics.request_counts, &self.metrics.requests_total] {
            counter.with_label_values(&labels).inc();
        }
    }
}

/// Records one request in the request metrics. See [`RequestRecord`].
pub(super) async fn record_request_metrics(
    State(metrics): State<RequestMetrics>,
    matched_path: MatchedPath,
    request: Request,
    next: Next,
) -> Response {
    let mut record = metrics.start_request(matched_path.as_str(), request.method().clone());
    let response = next.run(request).await;
    record.status_code = response.status();
    response
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::Router;
    use axum::body::Body;
    use axum::middleware::from_fn_with_state;
    use axum::routing::{get, post};
    use carbide_test_support::Outcome::*;
    use carbide_test_support::scenarios;
    use tower::ServiceExt;

    use super::*;
    use crate::api::test_support::histogram_series;

    /// Returns the exposition lines with histogram bucket and sum values
    /// masked. Those values depend on timing.
    fn masked(exposition: &str) -> Vec<String> {
        exposition
            .lines()
            .map(|line| match line.split_once(' ') {
                Some((series, _)) if series.contains("_bucket{") || series.contains("_sum{") => {
                    format!("{series} <timing>")
                }
                _ => line.to_owned(),
            })
            .collect()
    }

    #[test]
    fn new() {
        scenarios!(run = |namespace: &str| RequestMetrics::new(namespace).map(drop).map_err(|error| error.to_string());
            "a Prometheus metric name prefix" {
                "nico_rest_cert_manager" => Yields(()),
            }
            "a prefix that makes invalid metric names is a startup error" {
                "acme-cm" => FailsWith(
                    "invalid metrics namespace \"acme-cm\": Error: 'acme-cm_http_duration_seconds' is not a valid metric name".to_owned()
                ),
            }
        );
    }

    /// The handler of `GET /v1/pki/ca` never responds, so the client gives up
    /// after `1s`. Time is paused, so that second passes immediately.
    #[tokio::test(start_paused = true)]
    async fn record_request_metrics() {
        let metrics = RequestMetrics::new("acme_cm").unwrap();
        let router = Router::new()
            .route("/healthz", get(|| async { "ok\n" }))
            .route(
                "/v1/pki/cloud-cert",
                post(|| async { StatusCode::BAD_REQUEST }),
            )
            .route("/v1/pki/ca", get(std::future::pending::<()>))
            .route_layer(from_fn_with_state(
                metrics.clone(),
                super::record_request_metrics,
            ));
        for (method, path) in [
            (Method::GET, "/healthz"),
            (Method::GET, "/healthz"),
            (Method::POST, "/v1/pki/cloud-cert"),
            (Method::GET, "/v1/pki/ca"),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            let _answered_or_abandoned =
                tokio::time::timeout(Duration::from_secs(1), router.clone().oneshot(request)).await;
        }

        let histogram = |labels: &str, count: u64| {
            histogram_series("acme_cm_http_duration_seconds", labels, "<timing>", count)
        };
        let expected: Vec<String> = [
            "# HELP acme_cm_http_duration_seconds Duration of HTTP requests.".to_owned(),
            "# TYPE acme_cm_http_duration_seconds histogram".to_owned(),
        ]
        .into_iter()
        .chain(histogram("method=\"GET\",path=\"/healthz\"", 2))
        .chain(histogram("method=\"GET\",path=\"/v1/pki/ca\"", 1))
        .chain(histogram("method=\"POST\",path=\"/v1/pki/cloud-cert\"", 1))
        .chain(
            ["acme_cm_http_request_counts", "acme_cm_http_requests_total"]
                .into_iter()
                .flat_map(|name| {
                    [
                        format!("# HELP {name} Counter of HTTP requests."),
                        format!("# TYPE {name} counter"),
                        format!("{name}{{method=\"GET\",path=\"/healthz\",status_code=\"200\"}} 2"),
                        format!("{name}{{method=\"GET\",path=\"/v1/pki/ca\",status_code=\"503\"}} 1"),
                        format!(
                            "{name}{{method=\"POST\",path=\"/v1/pki/cloud-cert\",status_code=\"400\"}} 1"
                        ),
                    ]
                }),
        )
        .collect();
        assert_eq!(masked(&metrics.encode().unwrap()), expected);
    }
}
