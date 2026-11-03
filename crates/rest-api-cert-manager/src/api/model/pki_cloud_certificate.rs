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

//! Request and response bodies of `POST /v1/pki/cloud-cert`.

use std::fmt;

use axum::Json;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;

use crate::api::APPLICATION_JSON_UTF8;
use crate::pki::IssuedCertificate;

/// Validity of a cloud certificate, `90 days`, when the request sets `ttl` to
/// zero or leaves it out.
const DEFAULT_TTL_HOURS: i64 = 90 * 24;

/// Request body of `POST /v1/pki/cloud-cert`.
///
/// Site Manager and other deployed clients depend on this lenient decoding:
/// - Field names match ASCII case-insensitively.
/// - The last of repeated fields wins.
/// - `null` leaves a field unchanged.
/// - Unknown fields are ignored.
/// - A top-level `null` is an empty request.
///
/// A `ttl` must be a JSON integer that fits in 64 bits. Keys must be valid
/// Unicode, so a key with invalid UTF-8 or an unpaired `\u` surrogate fails
/// the request instead of being ignored.
#[derive(Debug, Default, PartialEq, Eq)]
pub(in crate::api) struct ApiPkiCloudCertificateCreateRequest {
    /// The workload's name, used as the end of the certificate's DNS name.
    name: String,
    /// Optional application label, used as the start of the DNS name.
    app: String,
    /// Validity in hours. Zero means the default of `90 days`. A negative value
    /// is accepted and issues a certificate that's already expired.
    ttl: i64,
}

impl ApiPkiCloudCertificateCreateRequest {
    /// Returns the certificate's DNS name, which is also its common name. It's
    /// `<app>.<name>`, or `<name>` without an app. `.<base_dns>` is appended
    /// unless the name already ends in `.com` or `.local`. Names aren't
    /// validated, so an empty request gives `.<base_dns>`.
    pub(in crate::api) fn dns_name(&self, base_dns: &str) -> String {
        let name = if self.app.is_empty() {
            self.name.clone()
        } else {
            format!("{}.{}", self.app, self.name)
        };
        if name.ends_with(".com") || name.ends_with(".local") {
            name
        } else {
            format!("{name}.{base_dns}")
        }
    }

    /// Returns the validity in hours. Zero is replaced by the default of
    /// `90 days`.
    pub(in crate::api) fn ttl_hours(&self) -> i64 {
        if self.ttl == 0 {
            DEFAULT_TTL_HOURS
        } else {
            self.ttl
        }
    }
}

impl TryFrom<&[u8]> for ApiPkiCloudCertificateCreateRequest {
    type Error = serde_json::Error;

    /// Decodes the first JSON value in `body` and ignores any bytes after it.
    /// An empty body is an error.
    fn try_from(body: &[u8]) -> Result<Self, Self::Error> {
        let mut deserializer = serde_json::Deserializer::from_slice(body);
        let request = Option::<Self>::deserialize(&mut deserializer)?;
        Ok(request.unwrap_or_default())
    }
}

impl<'de> Deserialize<'de> for ApiPkiCloudCertificateCreateRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // A derived struct would also accept a JSON array, but an array body
        // must return `400`. So this uses `deserialize_map` instead.
        deserializer.deserialize_map(RequestVisitor)
    }
}

/// Visitor that applies the fields of a JSON object in document order.
struct RequestVisitor;

impl<'de> Visitor<'de> for RequestVisitor {
    type Value = ApiPkiCloudCertificateCreateRequest;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a cloud certificate request object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut request = ApiPkiCloudCertificateCreateRequest::default();
        while let Some(key) = map.next_key::<String>()? {
            if key.eq_ignore_ascii_case("name") {
                if let Some(name) = map.next_value::<Option<String>>()? {
                    request.name = name;
                }
            } else if key.eq_ignore_ascii_case("app") {
                if let Some(app) = map.next_value::<Option<String>>()? {
                    request.app = app;
                }
            } else if key.eq_ignore_ascii_case("ttl") {
                // serde_json reads `-0` as a float, but it's a `ttl` of zero.
                // `24.0` and `1e2` aren't integers and are rejected. So the
                // `ttl` is parsed from the raw literal.
                if let Some(ttl) = map.next_value::<Option<Box<RawValue>>>()? {
                    request.ttl = ttl.get().parse().map_err(|_| {
                        de::Error::invalid_value(
                            de::Unexpected::Other(ttl.get()),
                            &"a whole number of hours that fits in 64 bits",
                        )
                    })?;
                }
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(request)
    }
}

/// Response body of a successful `POST /v1/pki/cloud-cert`. It's serialized as
/// compact JSON with `key` before `certificate`, without a trailing newline.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub(in crate::api) struct ApiPkiCloudCertificate {
    /// The leaf's PKCS#1 `RSA PRIVATE KEY` PEM.
    key: String,
    /// The leaf certificate PEM, without the CA chain.
    certificate: String,
}

impl From<IssuedCertificate> for ApiPkiCloudCertificate {
    fn from(issued: IssuedCertificate) -> Self {
        Self {
            key: issued.private_key_pem,
            certificate: issued.certificate_pem,
        }
    }
}

impl IntoResponse for ApiPkiCloudCertificate {
    /// Returns `200` rather than `201`, because clients check for `200`.
    fn into_response(self) -> Response {
        // This header replaces the one `Json` sets, which doesn't include the
        // charset.
        ([(CONTENT_TYPE, APPLICATION_JSON_UTF8)], Json(self)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{scenarios, value_scenarios};

    use super::*;
    use crate::api::test_support::Observed;

    fn request(name: &str, app: &str, ttl: i64) -> ApiPkiCloudCertificateCreateRequest {
        ApiPkiCloudCertificateCreateRequest {
            name: name.to_owned(),
            app: app.to_owned(),
            ttl,
        }
    }

    #[test]
    fn try_from() {
        scenarios!(run = |body: &str| ApiPkiCloudCertificateCreateRequest::try_from(body.as_bytes()).map_err(drop);
            "an empty body is an error" {
                "" => Fails,
            }
            "a top-level null or empty object is an empty request" {
                "null" => Yields(request("", "", 0)),
                "{}" => Yields(request("", "", 0)),
            }
            "a top-level value that is not an object is an error" {
                "[]" => Fails,
                "1" => Fails,
            }
            "fields decode" {
                r#"{"name":"svc","app":"web","ttl":24}"# => Yields(request("svc", "web", 24)),
                "{\"name\":\"tb\",\"ttl\":8760}\n" => Yields(request("tb", "", 8760)),
            }
            "null fields leave their zero values" {
                r#"{"name":null,"app":null,"ttl":null}"# => Yields(request("", "", 0)),
                r#"{"name":"a","name":null}"# => Yields(request("a", "", 0)),
            }
            "unknown fields are ignored" {
                r#"{"name":"a","extra":{"nested":[1,2,3]}}"# => Yields(request("a", "", 0)),
            }
            "keys match ASCII case-insensitively and the last assignment wins" {
                r#"{"NAME":"upper"}"# => Yields(request("upper", "", 0)),
                r#"{"nAmE":"mixed","APP":"ap","TTL":5}"# => Yields(request("mixed", "ap", 5)),
                r#"{"name":"a","name":"b"}"# => Yields(request("b", "", 0)),
                r#"{"Name":"x","name":"y"}"# => Yields(request("y", "", 0)),
                r#"{"name":"y","Name":"x"}"# => Yields(request("x", "", 0)),
            }
            "only the first JSON value is read" {
                r#"{"name":"a"} trailing garbage"# => Yields(request("a", "", 0)),
                r#"{"name":"a"}{"name":"b"}"# => Yields(request("a", "", 0)),
            }
            "ttl must be an integer literal that fits in 64 bits" {
                r#"{"ttl":-0}"# => Yields(request("", "", 0)),
                r#"{"ttl":-1}"# => Yields(request("", "", -1)),
                r#"{"ttl":24.0}"# => Fails,
                r#"{"ttl":1e2}"# => Fails,
                r#"{"ttl":9223372036854775808}"# => Fails,
            }
            "name must be a string" {
                r#"{"name":5}"# => Fails,
            }
            "string contents are taken as given" {
                r#"{"name":"é"}"# => Yields(request("\u{e9}", "", 0)),
                r#"{"name":"*.wild"}"# => Yields(request("*.wild", "", 0)),
            }
        );
    }

    #[test]
    fn dns_name() {
        value_scenarios!(run = |(request, base_dns): (ApiPkiCloudCertificateCreateRequest, &str)| request.dns_name(base_dns);
            "the base DNS name is appended" {
                (request("svc", "", 0), "temporal.local") => "svc.temporal.local".to_owned(),
                (request("svc", "web", 0), "temporal.local") => "web.svc.temporal.local".to_owned(),
                (request("", "", 0), "temporal.local") => ".temporal.local".to_owned(),
                (request("", "onlyapp", 0), "temporal.local") => "onlyapp..temporal.local".to_owned(),
                (request("svc", "", 0), "") => "svc.".to_owned(),
            }
            "names ending in .com or .local are kept, case-sensitively" {
                (request("svc.example.com", "", 0), "temporal.local") => "svc.example.com".to_owned(),
                (request("x.com", "y", 0), "temporal.local") => "y.x.com".to_owned(),
                (request("a", "b.com", 0), "temporal.local") => "b.com.a.temporal.local".to_owned(),
                (request("svc.cluster.local", "", 0), "temporal.local") => "svc.cluster.local".to_owned(),
                (request("A.COM", "", 0), "temporal.local") => "A.COM.temporal.local".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn into_response() {
        let response = ApiPkiCloudCertificate {
            key: "-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n"
                .to_owned(),
            certificate: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"
                .to_owned(),
        }
        .into_response();
        assert_eq!(
            Observed::from_response(response).await,
            Observed::json(
                200,
                r#"{"key":"-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n","certificate":"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"}"#,
            ),
        );
    }
}
