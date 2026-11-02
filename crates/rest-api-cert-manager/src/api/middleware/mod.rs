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

//! Request middleware for the TLS listener's routes.
//!
//! The router applies [`request_stack`] to each route's handlers, never to its
//! fallbacks. So only requests that match a route are traced, metered and
//! timed out. `404` and `405` responses (including `HEAD` on a `GET` route)
//! aren't. That way the metrics' `path` label only has route values. The plain
//! HTTP listener doesn't use request middleware.

mod request_metrics;
mod request_span;
mod request_timeout;

use std::convert::Infallible;

use axum::extract::Request;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::Response;
use axum::routing::Route;
pub(crate) use request_metrics::{MetricsError, RequestMetrics};
use tower::{Layer, Service, ServiceBuilder};

/// Returns the middleware of every TLS route. From outermost to innermost, the
/// layers are the request span, the request metrics and the handler timeout.
/// The metrics layer runs outside the timeout, so it counts the timeout's
/// `503`. The `1 MiB` body limit is in the handler of the only route that
/// reads a body.
pub(super) fn request_stack(
    request_metrics: RequestMetrics,
) -> impl Layer<
    Route,
    Service: Service<Request, Response = Response, Error = Infallible, Future: Send + 'static>
                 + Clone
                 + Send
                 + Sync
                 + 'static,
> + Clone
+ Send
+ Sync
+ 'static {
    ServiceBuilder::new()
        .layer(from_fn(request_span::request_span))
        .layer(from_fn_with_state(
            request_metrics,
            request_metrics::record_request_metrics,
        ))
        .layer(from_fn(request_timeout::request_timeout))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases_async};
    use tower::ServiceExt;

    use super::*;
    use crate::api::test_support::Observed;

    /// The metrics layer runs outside the timeout, so a request that times out
    /// is counted with the `503` the client saw. Time is paused, so the `5s`
    /// deadline passes without the test waiting for it.
    #[tokio::test(start_paused = true)]
    async fn request_stack() {
        check_cases_async(
            [
                Case {
                    scenario: "a prompt handler is counted with its status",
                    input: Duration::from_millis(10),
                    expect: Yields((
                        Observed::text(200, "done\n"),
                        "nico_rest_cert_manager_http_requests_total{method=\"GET\",path=\"/work\",status_code=\"200\"} 1"
                            .to_owned(),
                    )),
                },
                Case {
                    scenario: "a timed-out handler is counted as 503",
                    input: Duration::from_secs(10),
                    expect: Yields((
                        Observed::text(503, "Request timed out in 5s\n"),
                        "nico_rest_cert_manager_http_requests_total{method=\"GET\",path=\"/work\",status_code=\"503\"} 1"
                            .to_owned(),
                    )),
                },
            ],
            |work: Duration| async move {
                let metrics = RequestMetrics::new("nico_rest_cert_manager").map_err(drop)?;
                let router = Router::new().route(
                    "/work",
                    get(move || async move {
                        tokio::time::sleep(work).await;
                        "done\n"
                    })
                    .route_layer(super::request_stack(metrics.clone())),
                );
                let request = Request::builder().uri("/work").body(Body::empty()).map_err(drop)?;
                let response = router.oneshot(request).await.map_err(drop)?;
                let observed = Observed::from_response(response).await;
                let exposition = metrics.encode().map_err(drop)?;
                let counted = exposition
                    .lines()
                    .find(|line| line.starts_with("nico_rest_cert_manager_http_requests_total{"))
                    .ok_or(())?
                    .to_owned();
                Ok::<_, ()>((observed, counted))
            },
        )
        .await;
    }
}
