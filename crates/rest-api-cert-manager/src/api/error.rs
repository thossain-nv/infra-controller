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

//! [`ApiError`] lists the failures that handlers report. Each one has a fixed
//! status, media type and body.

use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};

use super::{APPLICATION_JSON_UTF8, TEXT_PLAIN_UTF8};

/// Body of a failed `POST /v1/pki/cloud-cert`, which is an empty JSON object.
const EMPTY_JSON_OBJECT: &str = "{}";

/// Body of [`ApiError::DecodeCaCertificate`]. Clients may match on this text,
/// so it uses the legacy wording, including "CredsManager".
const DECODE_CA_CERTIFICATE_BODY: &str = "CredsManager error, internal code 9";

/// A failure a handler reports to the client. The handler logs the cause. The
/// response only contains the fixed body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ApiError {
    /// The cloud certificate request body could not be decoded.
    ParseRequest,
    /// The cloud certificate could not be issued.
    IssueCertificate,
    /// The CA certificate file's first PEM block isn't labelled `CERTIFICATE`.
    /// The cause is the server's CA file, but the status is `400`, not `500`.
    /// Clients depend on that status.
    DecodeCaCertificate,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::ParseRequest => (
                StatusCode::BAD_REQUEST,
                [(CONTENT_TYPE, APPLICATION_JSON_UTF8)],
                EMPTY_JSON_OBJECT,
            )
                .into_response(),
            Self::IssueCertificate => (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(CONTENT_TYPE, APPLICATION_JSON_UTF8)],
                EMPTY_JSON_OBJECT,
            )
                .into_response(),
            Self::DecodeCaCertificate => (
                StatusCode::BAD_REQUEST,
                [(CONTENT_TYPE, TEXT_PLAIN_UTF8)],
                DECODE_CA_CERTIFICATE_BODY,
            )
                .into_response(),
        }
    }
}
