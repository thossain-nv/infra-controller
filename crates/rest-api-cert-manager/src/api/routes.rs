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

//! Routers for both listeners, with their routes and middleware.

use axum::Router;
use axum::extract::Request;
use axum::http::header::{CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use axum::http::{Method, StatusCode};
use axum::middleware::{Next, from_fn};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use super::handler::{health, metrics, pki_ca_certificate, pki_cloud_certificate, version};
use super::{AppState, TEXT_PLAIN_UTF8, middleware};

/// Returns the router of the TLS listener. It serves the system routes, the CA
/// certificate and cloud certificate issuance. Every handler runs under
/// [`middleware::request_stack`].
pub(crate) fn tls_router(state: AppState) -> Router {
    let request_stack = middleware::request_stack(state.request_metrics.clone());
    Router::new()
        // System routes.
        .route(
            "/healthz",
            get(health::get_health).route_layer(request_stack.clone()),
        )
        .route(
            "/version",
            get(version::get_version).route_layer(request_stack.clone()),
        )
        .route(
            "/metrics",
            get(metrics::get_metrics).route_layer(request_stack.clone()),
        )
        // PKI routes.
        .route(
            "/v1/pki/ca",
            get(pki_ca_certificate::get_pki_ca_certificate).route_layer(request_stack.clone()),
        )
        .route(
            "/v1/pki/ca/pem",
            get(pki_ca_certificate::get_pki_ca_certificate_pem).route_layer(request_stack.clone()),
        )
        .route(
            "/v1/pki/cloud-cert",
            post(pki_cloud_certificate::create_pki_cloud_certificate).route_layer(request_stack),
        )
        .route_layer(from_fn(reject_head))
        .fallback(not_found)
        .with_state(state)
}

/// Returns the router of the plain HTTP listener. It serves health for kubelet
/// probes and the CA certificate for clients that don't trust the TLS listener
/// yet. These routes run without request middleware, so they aren't traced,
/// metered or timed out. The request metrics only count TLS requests.
pub(crate) fn insecure_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health::get_health))
        .route(
            "/v1/pki/ca",
            get(pki_ca_certificate::get_pki_ca_certificate),
        )
        .route(
            "/v1/pki/ca/pem",
            get(pki_ca_certificate::get_pki_ca_certificate_pem),
        )
        .route_layer(from_fn(reject_head))
        .fallback(not_found)
        .with_state(state)
}

/// Rejects `HEAD` on a `GET` route with `405` and an empty body. axum's `get`
/// would otherwise answer `HEAD` like `GET`, so this check runs before method
/// routing. No middleware sees these requests.
async fn reject_head(request: Request, next: Next) -> Response {
    if request.method() == Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    next.run(request).await
}

/// Returns `404` for every path a router doesn't match. The body is
/// `404 page not found` as plain text, with `nosniff`.
async fn not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        [
            (CONTENT_TYPE, TEXT_PLAIN_UTF8),
            (X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        "404 page not found\n",
    )
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases_async};
    use tower::ServiceExt;

    use super::*;
    use crate::api::test_support::{Observed, TEST_VERSION, app_state, der, histogram_series};
    use crate::pki::test_support::TestCaPem;

    struct Call {
        method: Method,
        path: &'static str,
        body: &'static str,
    }

    fn call(method: Method, path: &'static str) -> Call {
        Call {
            method,
            path,
            body: "",
        }
    }

    async fn send(router: Router, call: Call) -> Observed {
        let request = Request::builder()
            .method(call.method)
            .uri(call.path)
            .body(Body::from(call.body))
            .unwrap();
        Observed::from_response(router.oneshot(request).await.unwrap()).await
    }

    /// Returns the exposition of a router's first scrape. It contains only the
    /// histogram series of the scrape itself, which has no observations yet.
    fn first_scrape() -> String {
        let name = "nico_rest_cert_manager_http_duration_seconds";
        let lines: Vec<String> = [
            format!("# HELP {name} Duration of HTTP requests."),
            format!("# TYPE {name} histogram"),
        ]
        .into_iter()
        .chain(histogram_series(
            name,
            "method=\"GET\",path=\"/metrics\"",
            "0",
            0,
        ))
        .collect();
        lines.join("\n") + "\n"
    }

    #[tokio::test]
    async fn tls_router() {
        let ca = TestCaPem::p256();
        let not_allowed = || Yields(Observed::empty(405));
        check_cases_async(
            [
                Case {
                    scenario: "health",
                    input: call(Method::GET, "/healthz"),
                    expect: Yields(Observed::text(200, "ok\n")),
                },
                Case {
                    scenario: "version",
                    input: call(Method::GET, "/version"),
                    expect: Yields(Observed::text(200, format!("{TEST_VERSION}\n"))),
                },
                Case {
                    scenario: "metrics, which already holds the scrape's own histogram series",
                    input: call(Method::GET, "/metrics"),
                    expect: Yields(Observed {
                        content_type: Some(
                            "text/plain; version=0.0.4; charset=utf-8; escaping=underscores"
                                .to_owned(),
                        ),
                        ..Observed::text(200, first_scrape())
                    }),
                },
                Case {
                    scenario: "CA DER",
                    input: call(Method::GET, "/v1/pki/ca"),
                    expect: Yields(Observed::text(200, der(&ca.certificate))),
                },
                Case {
                    scenario: "CA PEM",
                    input: call(Method::GET, "/v1/pki/ca/pem"),
                    expect: Yields(Observed::text(200, &ca.certificate)),
                },
                Case {
                    scenario: "cloud certificate, reaching the handler's decoder",
                    input: Call {
                        method: Method::POST,
                        path: "/v1/pki/cloud-cert",
                        body: "not json",
                    },
                    expect: Yields(Observed::json(400, "{}")),
                },
                Case {
                    scenario: "HEAD on a GET route",
                    input: call(Method::HEAD, "/healthz"),
                    expect: not_allowed(),
                },
                Case {
                    scenario: "HEAD on the POST route",
                    input: call(Method::HEAD, "/v1/pki/cloud-cert"),
                    expect: not_allowed(),
                },
                Case {
                    scenario: "POST on a GET route",
                    input: call(Method::POST, "/healthz"),
                    expect: not_allowed(),
                },
                Case {
                    scenario: "OPTIONS on the CA route",
                    input: call(Method::OPTIONS, "/v1/pki/ca"),
                    expect: not_allowed(),
                },
                Case {
                    scenario: "GET on the POST route",
                    input: call(Method::GET, "/v1/pki/cloud-cert"),
                    expect: not_allowed(),
                },
                Case {
                    scenario: "root",
                    input: call(Method::GET, "/"),
                    expect: Yields(Observed::not_found()),
                },
                Case {
                    scenario: "unknown path",
                    input: call(Method::GET, "/nope"),
                    expect: Yields(Observed::not_found()),
                },
                Case {
                    scenario: "HEAD on an unknown path, its body dropped",
                    input: call(Method::HEAD, "/nope"),
                    expect: Yields(Observed {
                        body: Vec::new(),
                        ..Observed::not_found()
                    }),
                },
                Case {
                    scenario: "trailing slash",
                    input: call(Method::GET, "/v1/pki/ca/"),
                    expect: Yields(Observed::not_found()),
                },
                Case {
                    scenario: "paths are case-sensitive",
                    input: call(Method::GET, "/HEALTHZ"),
                    expect: Yields(Observed::not_found()),
                },
                Case {
                    scenario: "unclean paths are not redirected",
                    input: call(Method::GET, "/v1//pki/ca"),
                    expect: Yields(Observed::not_found()),
                },
            ],
            // Each case gets a fresh state, so every `/metrics` scrape is the
            // first.
            |call| {
                let router = super::tls_router(app_state(&ca));
                async move { Ok::<_, ()>(send(router, call).await) }
            },
        )
        .await;
    }

    #[tokio::test]
    async fn insecure_router() {
        let ca = TestCaPem::p256();
        let router = super::insecure_router(app_state(&ca));
        check_cases_async(
            [
                Case {
                    scenario: "health",
                    input: call(Method::GET, "/healthz"),
                    expect: Yields(Observed::text(200, "ok\n")),
                },
                Case {
                    scenario: "CA DER",
                    input: call(Method::GET, "/v1/pki/ca"),
                    expect: Yields(Observed::text(200, der(&ca.certificate))),
                },
                Case {
                    scenario: "CA PEM",
                    input: call(Method::GET, "/v1/pki/ca/pem"),
                    expect: Yields(Observed::text(200, &ca.certificate)),
                },
                Case {
                    scenario: "no version",
                    input: call(Method::GET, "/version"),
                    expect: Yields(Observed::not_found()),
                },
                Case {
                    scenario: "no metrics",
                    input: call(Method::GET, "/metrics"),
                    expect: Yields(Observed::not_found()),
                },
                Case {
                    scenario: "no cloud certificates",
                    input: Call {
                        method: Method::POST,
                        path: "/v1/pki/cloud-cert",
                        body: "{}",
                    },
                    expect: Yields(Observed::not_found()),
                },
                Case {
                    scenario: "HEAD on a GET route",
                    input: call(Method::HEAD, "/healthz"),
                    expect: Yields(Observed::empty(405)),
                },
                Case {
                    scenario: "POST on a GET route",
                    input: call(Method::POST, "/v1/pki/ca/pem"),
                    expect: Yields(Observed::empty(405)),
                },
            ],
            |call| {
                let router = router.clone();
                async move { Ok::<_, ()>(send(router, call).await) }
            },
        )
        .await;
    }

    /// Only requests that match a TLS route are counted, including every
    /// scrape. `404` responses, `405` responses (including `HEAD`) and plain
    /// HTTP requests aren't counted.
    #[tokio::test]
    async fn request_metrics_count_matched_tls_routes_only() {
        let state = app_state(&TestCaPem::p256());
        let tls = super::tls_router(state.clone());
        let insecure = super::insecure_router(state.clone());
        for call in [
            call(Method::GET, "/healthz"),
            call(Method::HEAD, "/healthz"),
            call(Method::POST, "/healthz"),
            call(Method::GET, "/nope"),
            call(Method::GET, "/v1/pki/cloud-cert"),
            call(Method::GET, "/metrics"),
        ] {
            send(tls.clone(), call).await;
        }
        send(insecure, call(Method::GET, "/healthz")).await;

        let exposition = state.request_metrics.encode().unwrap();
        let counted: Vec<&str> = exposition
            .lines()
            .filter(|line| line.starts_with("nico_rest_cert_manager_http_requests_total{"))
            .collect();
        assert_eq!(
            counted,
            [
                "nico_rest_cert_manager_http_requests_total{method=\"GET\",path=\"/healthz\",status_code=\"200\"} 1",
                "nico_rest_cert_manager_http_requests_total{method=\"GET\",path=\"/metrics\",status_code=\"200\"} 1",
            ]
        );
    }
}
