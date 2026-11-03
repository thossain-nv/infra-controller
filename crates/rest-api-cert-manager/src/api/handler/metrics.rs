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

//! Handler for `GET /metrics`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};

use crate::api::AppState;

/// Media type of `GET /metrics`. It's the Prometheus text format `0.0.4`, with
/// metric names escaped using underscores. The handler doesn't offer Protobuf,
/// OpenMetrics or gzip responses.
const PROMETHEUS_TEXT_FORMAT: &str =
    "text/plain; version=0.0.4; charset=utf-8; escaping=underscores";

/// `GET /metrics` returns `200` with the request metrics in the Prometheus text
/// format. Only the TLS listener serves it. The request metrics count each
/// scrape too.
pub(in crate::api) async fn get_metrics(State(state): State<AppState>) -> Response {
    let exposition = state.request_metrics.encode();
    match exposition {
        Ok(exposition) => ([(CONTENT_TYPE, PROMETHEUS_TEXT_FORMAT)], exposition).into_response(),
        Err(error) => {
            tracing::error!(error = %error, "failed to encode the request metrics");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
