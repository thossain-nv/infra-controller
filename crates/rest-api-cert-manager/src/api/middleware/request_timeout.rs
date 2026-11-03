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
