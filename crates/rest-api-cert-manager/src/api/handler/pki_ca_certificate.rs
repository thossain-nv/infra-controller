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

//! `GET /v1/pki/ca` and `GET /v1/pki/ca/pem` return the CA certificate. Clients
//! use it to bootstrap trust in this service and the certificates it issues.

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;

use crate::api::error::ApiError;
use crate::api::{AppState, TEXT_PLAIN_UTF8};

/// Label that the CA file's first block must have before its DER is served.
const CERTIFICATE_LABEL: &str = "CERTIFICATE";

/// `GET /v1/pki/ca` returns `200` with the raw DER of the CA certificate file's
/// first PEM block. The media type is `text/plain; charset=utf-8`. If that
/// block isn't labelled `CERTIFICATE`, it returns
/// [`ApiError::DecodeCaCertificate`] instead.
pub(in crate::api) async fn get_pki_ca_certificate(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let block = &state.certificate_authority.certificate_block;
    if block.tag() != CERTIFICATE_LABEL {
        tracing::error!(
            pem_label = block.tag(),
            "CA certificate file does not start with a CERTIFICATE block"
        );
        return Err(ApiError::DecodeCaCertificate);
    }
    Ok(([(CONTENT_TYPE, TEXT_PLAIN_UTF8)], block.contents().to_vec()))
}

/// `GET /v1/pki/ca/pem` returns `200` with the CA certificate file exactly as
/// read. The file may be a bundle, have leading text or use CRLF line endings.
pub(in crate::api) async fn get_pki_ca_certificate_pem(
    State(state): State<AppState>,
) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, TEXT_PLAIN_UTF8)],
        state.certificate_authority.certificate_pem.clone(),
    )
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases_async};

    use super::*;
    use crate::api::test_support::{Observed, app_state, der};
    use crate::pki::test_support::TestCaPem;

    /// Returns `ca` with its certificate file replaced by `certificate`.
    fn with_certificate_file(ca: &TestCaPem, certificate: String) -> TestCaPem {
        TestCaPem {
            certificate,
            key: ca.key.clone(),
        }
    }

    /// Returns `ca` with its certificate file turned into a bundle. The bundle
    /// has a line of text ending in CRLF, the CA's own certificate, then
    /// another CA's certificate.
    fn leading_text_bundle(ca: &TestCaPem) -> TestCaPem {
        with_certificate_file(
            ca,
            format!(
                "Subject: the site CA\r\n{}{}",
                ca.certificate,
                TestCaPem::p256().certificate
            ),
        )
    }

    #[tokio::test]
    async fn get_pki_ca_certificate() {
        let ca = TestCaPem::p256();
        let bundle = leading_text_bundle(&ca);
        let relabelled = with_certificate_file(
            &ca,
            ca.certificate
                .replace("CERTIFICATE-----", "X509 CERTIFICATE-----"),
        );
        check_cases_async(
            [
                Case {
                    scenario: "a PEM certificate serves its DER",
                    input: &ca,
                    expect: Yields(Observed::text(200, der(&ca.certificate))),
                },
                Case {
                    scenario: "a bundle with leading text serves its first certificate",
                    input: &bundle,
                    expect: Yields(Observed::text(200, der(&ca.certificate))),
                },
                Case {
                    scenario: "a first block labelled X509 CERTIFICATE is 400",
                    input: &relabelled,
                    expect: Yields(Observed::text(400, "CredsManager error, internal code 9")),
                },
            ],
            |ca| async move {
                let response = super::get_pki_ca_certificate(State(app_state(ca)))
                    .await
                    .into_response();
                Ok::<_, ()>(Observed::from_response(response).await)
            },
        )
        .await;
    }

    #[tokio::test]
    async fn get_pki_ca_certificate_pem() {
        let ca = TestCaPem::p256();
        let bundle = leading_text_bundle(&ca);
        check_cases_async(
            [
                Case {
                    scenario: "a single certificate file is served as is",
                    input: &ca,
                    expect: Yields(Observed::text(200, &ca.certificate)),
                },
                Case {
                    scenario: "a bundle is served verbatim, leading text and CRLF included",
                    input: &bundle,
                    expect: Yields(Observed::text(200, &bundle.certificate)),
                },
            ],
            |ca| async move {
                let response = super::get_pki_ca_certificate_pem(State(app_state(ca)))
                    .await
                    .into_response();
                Ok::<_, ()>(Observed::from_response(response).await)
            },
        )
        .await;
    }
}
