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

//! Handler for `GET /version`.

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;

use crate::api::{AppState, TEXT_PLAIN_UTF8};

/// `GET /version` returns `200` with the release version and a newline. For an
/// unstamped build, the version is `dev`. Only the TLS listener serves it.
pub(in crate::api) async fn get_version(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, TEXT_PLAIN_UTF8)],
        format!("{}\n", state.version),
    )
}
