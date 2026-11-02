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

//! Handler deadline for the TLS routes.

use std::time::Duration;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::api::TEXT_PLAIN_UTF8;

/// How long a TLS route's handler can take to produce its response. It's
/// measured from the end of the request head and includes reading the body.
/// The service doesn't set a concurrency limit, so this timeout is what limits
/// the work each request can do.
const HANDLER_TIMEOUT: Duration = Duration::from_secs(5);

/// Returns `503` with the plain-text body `Request timed out in 5s` when the
/// handler doesn't finish within [`HANDLER_TIMEOUT`]. Issuance that's already
/// running on a blocking thread still finishes, but its result is discarded.
pub(super) async fn request_timeout(request: Request, next: Next) -> Response {
    let response = tokio::time::timeout(HANDLER_TIMEOUT, next.run(request)).await;
    match response {
        Ok(response) => response,
        Err(_) => {
            tracing::warn!(
                handler_timeout_seconds = HANDLER_TIMEOUT.as_secs(),
                "request timed out"
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(CONTENT_TYPE, TEXT_PLAIN_UTF8)],
                format!("Request timed out in {}s\n", HANDLER_TIMEOUT.as_secs()),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::middleware::from_fn;
    use axum::routing::get;
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases_async};
    use tower::ServiceExt;

    use super::*;
    use crate::api::test_support::Observed;

    /// Time only advances when the runtime is idle, so the test reaches the
    /// `5s` deadline without waiting for it.
    #[tokio::test(start_paused = true)]
    async fn request_timeout() {
        let router = Router::new()
            .route(
                "/sleep/{milliseconds}",
                get(
                    |axum::extract::Path(milliseconds): axum::extract::Path<u64>| async move {
                        tokio::time::sleep(Duration::from_millis(milliseconds)).await;
                        "done\n"
                    },
                ),
            )
            .route_layer(from_fn(super::request_timeout));
        check_cases_async(
            [
                Case {
                    scenario: "a handler that finishes inside the deadline answers",
                    input: 4_999,
                    expect: Yields(Observed::text(200, "done\n")),
                },
                Case {
                    scenario: "a handler past the deadline gets 503",
                    input: 5_001,
                    expect: Yields(Observed::text(503, "Request timed out in 5s\n")),
                },
            ],
            |milliseconds: u64| {
                let router = router.clone();
                async move {
                    let request = Request::builder()
                        .uri(format!("/sleep/{milliseconds}"))
                        .body(Body::empty())
                        .unwrap();
                    let response = router.oneshot(request).await.map_err(drop)?;
                    Ok::<_, ()>(Observed::from_response(response).await)
                }
            },
        )
        .await;
    }
}
