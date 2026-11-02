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

//! `POST /v1/pki/cloud-cert` issues leaf certificates for NICo REST services.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use http_body_util::BodyExt;

use crate::api::AppState;
use crate::api::error::ApiError;
use crate::api::model::pki_cloud_certificate::{
    ApiPkiCloudCertificate, ApiPkiCloudCertificateCreateRequest,
};

/// Maximum number of request body bytes that are read, `1 MiB`. The decoder
/// stops after the first JSON value, so a body of any length is accepted if
/// that value ends within the limit. A longer value fails to decode with `400`,
/// never `413`.
const REQUEST_BODY_LIMIT_BYTES: usize = 1 << 20;

/// `POST /v1/pki/cloud-cert` issues an RSA-2048 leaf certificate for the DNS
/// name built from the request. It returns `200` with the key and certificate.
/// An undecodable body returns `400` and an issuance failure returns `500`,
/// both with `{}`.
///
/// Site Manager doesn't send a `Content-Type`, so the body doesn't need one.
/// That's why it's decoded here rather than by axum's `Json`. Reading stops
/// when a top-level object closes. So a client that sends a whole request but
/// less body than it announced still gets a response. The exception is an
/// HTTP/2 stream that ends before its `content-length`, which h2 resets as
/// malformed.
///
/// There's no authentication. Any client that reaches the TLS listener can get
/// a certificate for any name.
pub(in crate::api) async fn create_pki_cloud_certificate(
    State(state): State<AppState>,
    body: Body,
) -> Result<ApiPkiCloudCertificate, ApiError> {
    let body = read_first_value(body).await.map_err(|error| {
        tracing::error!(error = %error, "failed to read the cloud certificate request");
        ApiError::ParseRequest
    })?;
    let request =
        ApiPkiCloudCertificateCreateRequest::try_from(body.as_slice()).map_err(|error| {
            tracing::error!(error = %error, "failed to decode the cloud certificate request");
            ApiError::ParseRequest
        })?;

    let dns_name = request.dns_name(&state.base_dns);
    let ttl_hours = request.ttl_hours();
    let certificate_authority = Arc::clone(&state.certificate_authority);
    let dns_names = vec![dns_name.clone()];
    // Generating the RSA key takes tens of milliseconds of CPU.
    let issued = tokio::task::spawn_blocking(move || {
        certificate_authority.issue_certificate(&dns_names, ttl_hours)
    })
    .await;
    match issued {
        Ok(Ok(issued)) => Ok(issued.into()),
        Ok(Err(error)) => {
            tracing::error!(error = %error, dns_name, "failed to issue a cloud certificate");
            Err(ApiError::IssueCertificate)
        }
        Err(error) => {
            tracing::error!(error = %error, dns_name, "cloud certificate issuance task failed");
            Err(ApiError::IssueCertificate)
        }
    }
}

/// Reads the body up to and including the frame that closes its first value,
/// if that value is an object or array. Otherwise it reads to the end of the
/// body. It never reads more than [`REQUEST_BODY_LIMIT_BYTES`]. The rest of the
/// body isn't read.
async fn read_first_value(mut body: Body) -> Result<Vec<u8>, axum::Error> {
    let mut prefix = Vec::new();
    let mut nesting = Nesting::default();
    while prefix.len() < REQUEST_BODY_LIMIT_BYTES {
        let Some(frame) = body.frame().await else {
            break;
        };
        if let Ok(data) = frame?.into_data() {
            prefix.extend_from_slice(&data);
            if nesting.closes_value(&data) {
                break;
            }
        }
    }
    prefix.truncate(REQUEST_BODY_LIMIT_BYTES);
    Ok(prefix)
}

/// Bracket nesting of a JSON body that's read in pieces. Strings are skipped,
/// so brackets inside them don't count. The decoder validates everything else.
#[derive(Default)]
struct Nesting {
    depth: usize,
    in_string: bool,
    escaped: bool,
}

impl Nesting {
    /// Returns whether `bytes` close a top-level bracket, continuing from the
    /// bytes already seen. That bracket ends the first value when the value is
    /// an object or array.
    fn closes_value(&mut self, bytes: &[u8]) -> bool {
        for &byte in bytes {
            if self.in_string {
                match byte {
                    _ if self.escaped => self.escaped = false,
                    b'\\' => self.escaped = true,
                    b'"' => self.in_string = false,
                    _ => {}
                }
                continue;
            }
            match byte {
                b'"' => self.in_string = true,
                b'{' | b'[' => self.depth += 1,
                b'}' | b']' => {
                    self.depth = self.depth.saturating_sub(1);
                    if self.depth == 0 {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::time::Duration;

    use axum::response::IntoResponse;
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases_async};
    use futures_util::{StreamExt, stream};
    use tokio::time;
    use x509_parser::extensions::GeneralName;
    use x509_parser::prelude::{FromDer, X509Certificate};

    use super::*;
    use crate::api::test_support::{Observed, app_state};
    use crate::pki::test_support::TestCaPem;

    /// The reply a client sees. It has the status, plus the leaf's DNS names
    /// and validity in hours for a `200`.
    #[derive(Debug, PartialEq)]
    enum Reply {
        Issued {
            dns_names: Vec<String>,
            validity_hours: i64,
        },
        Error(Observed),
    }

    fn issued(dns_name: &str, validity_hours: i64) -> Reply {
        Reply::Issued {
            dns_names: vec![dns_name.to_owned()],
            validity_hours,
        }
    }

    /// Posts `body` and reads the reply. If a `200` has a certificate that
    /// can't be read back, this returns an error, so the failure names the
    /// case.
    async fn reply(state: AppState, body: Vec<u8>) -> Result<Reply, String> {
        let response = super::create_pki_cloud_certificate(State(state), Body::from(body))
            .await
            .into_response();
        let observed = Observed::from_response(response).await;
        if observed.status != 200 {
            return Ok(Reply::Error(observed));
        }
        let issued: serde_json::Value =
            serde_json::from_slice(&observed.body).map_err(|error| error.to_string())?;
        let certificate_pem = issued["certificate"]
            .as_str()
            .ok_or("the reply has no certificate")?;
        let certificate = pem::parse(certificate_pem).map_err(|error| error.to_string())?;
        let (_, certificate) =
            X509Certificate::from_der(certificate.contents()).map_err(|error| error.to_string())?;
        let subject_alt_name = certificate
            .subject_alternative_name()
            .map_err(|error| error.to_string())?
            .ok_or("the certificate has no subject alternative name")?;
        let dns_names = subject_alt_name
            .value
            .general_names
            .iter()
            .map(|name| match name {
                GeneralName::DNSName(name) => Ok((*name).to_owned()),
                other => Err(format!("unexpected subject alternative name {other:?}")),
            })
            .collect::<Result<_, String>>()?;
        let validity = certificate.validity();
        Ok(Reply::Issued {
            dns_names,
            validity_hours: (validity.not_after.timestamp() - validity.not_before.timestamp())
                / 3600,
        })
    }

    #[tokio::test]
    async fn create_pki_cloud_certificate() {
        let state = app_state(&TestCaPem::p256());
        let padded = |value: &str, length: usize| {
            let mut body = value.as_bytes().to_vec();
            body.resize(length, b' ');
            body
        };
        let oversized_value = format!("{{\"name\":\"{}\"}}", "a".repeat(REQUEST_BODY_LIMIT_BYTES));
        let value_of_exactly_the_limit = {
            let filler = REQUEST_BODY_LIMIT_BYTES - r#"{"name":"tb","x":""}"#.len();
            format!("{{\"name\":\"tb\",\"x\":\"{}\"}}", "a".repeat(filler))
        };
        check_cases_async(
            [
                Case {
                    scenario: "Site Manager's request: no Content-Type, trailing newline",
                    input: b"{\"name\":\"site.example\",\"ttl\":8760}\n".to_vec(),
                    expect: Yields(issued("site.example.temporal.local", 8760)),
                },
                Case {
                    scenario: "an empty object issues for the base name with the 90-day default",
                    input: b"{}".to_vec(),
                    expect: Yields(issued(".temporal.local", 2160)),
                },
                Case {
                    scenario: "a value of exactly 1 MiB is read whole",
                    input: value_of_exactly_the_limit.into_bytes(),
                    expect: Yields(issued("tb.temporal.local", 2160)),
                },
                Case {
                    scenario: "bytes past 1 MiB after the value are never read",
                    input: padded(r#"{"name":"tb"}"#, 2 * REQUEST_BODY_LIMIT_BYTES),
                    expect: Yields(issued("tb.temporal.local", 2160)),
                },
                Case {
                    scenario: "a value that does not end within 1 MiB is 400",
                    input: oversized_value.into_bytes(),
                    expect: Yields(Reply::Error(Observed::json(400, "{}"))),
                },
                Case {
                    scenario: "an empty body is 400",
                    input: Vec::new(),
                    expect: Yields(Reply::Error(Observed::json(400, "{}"))),
                },
                Case {
                    scenario: "a name that is not ASCII fails issuance with 500",
                    input: r#"{"name":"é"}"#.as_bytes().to_vec(),
                    expect: Yields(Reply::Error(Observed::json(500, "{}"))),
                },
            ],
            |body| reply(state.clone(), body),
        )
        .await;
    }

    /// Checks how many bytes are read from a body sent in `frames`. When the
    /// body doesn't end after them, reading must stop on its own. This is like
    /// a client that sends less than its `Content-Length`.
    #[tokio::test]
    async fn read_first_value() {
        let frames = |frames: &[&str]| -> Vec<String> {
            frames.iter().map(|frame| (*frame).to_owned()).collect()
        };
        check_cases_async(
            [
                Case {
                    scenario: "a body whose value is not an object or array is read to its end",
                    input: (frames(&["nu", "ll "]), true),
                    expect: Yields(5),
                },
                Case {
                    scenario: "a long body stops at the limit",
                    input: (vec![" ".repeat(REQUEST_BODY_LIMIT_BYTES + 1)], false),
                    expect: Yields(REQUEST_BODY_LIMIT_BYTES),
                },
                Case {
                    scenario: "reading stops with the frame that closes the first object",
                    input: (frames(&[r#"{"name":"#, r#""a"} "#, "{"]), false),
                    expect: Yields(13),
                },
                Case {
                    scenario: "brackets and escaped quotes inside a string do not close it",
                    input: (frames(&[r#"{"name":"}\"}""#, "}"]), false),
                    expect: Yields(15),
                },
                Case {
                    scenario: "nested values close with the outermost bracket",
                    input: (frames(&[r#"[{"a":[1]}"#, "]"]), false),
                    expect: Yields(11),
                },
            ],
            |(frames, ends): (Vec<String>, bool)| async move {
                let frames = stream::iter(frames.into_iter().map(Ok::<_, Infallible>));
                let body = if ends {
                    Body::from_stream(frames)
                } else {
                    Body::from_stream(frames.chain(stream::pending()))
                };
                let read = time::timeout(Duration::from_secs(1), super::read_first_value(body))
                    .await
                    .map_err(drop)?;
                read.map(|prefix| prefix.len()).map_err(drop)
            },
        )
        .await;
    }
}
