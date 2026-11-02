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

//! Handler for `GET /healthz`.

use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;

use crate::api::TEXT_PLAIN_UTF8;

/// `GET /healthz` returns `200` with `ok` and a newline. Kubelet probes call it
/// on the plain HTTP listener.
pub(in crate::api) async fn get_health() -> impl IntoResponse {
    ([(CONTENT_TYPE, TEXT_PLAIN_UTF8)], "ok\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::test_support::Observed;

    #[tokio::test]
    async fn get_health() {
        let response = super::get_health().await.into_response();
        assert_eq!(
            Observed::from_response(response).await,
            Observed::text(200, "ok\n")
        );
    }
}
