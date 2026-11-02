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

//! Sets up the serving identity for the TLS listener.
//!
//! The serving certificate and key are kept only in memory and never written
//! to disk.

use std::sync::Arc;

use rustls::ServerConfig;
use rustls::crypto::aws_lc_rs;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::pki::IssuedCertificate;

/// Reasons the TLS listener's configuration couldn't be built.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TlsConfigError {
    #[error("failed to read the serving certificate: {0}")]
    Certificate(rustls_pki_types::pem::Error),
    #[error("failed to read the serving key: {0}")]
    Key(rustls_pki_types::pem::Error),
    #[error("failed to configure TLS: {0}")]
    Rustls(rustls::Error),
}

/// Builds the TLS listener's configuration. It supports TLS 1.2 and 1.3,
/// sends the leaf certificate without a chain and doesn't authenticate
/// clients. ALPN prefers HTTP/2 over HTTP/1.1.
pub(super) fn server_config(serving: &IssuedCertificate) -> Result<ServerConfig, TlsConfigError> {
    let certificate = CertificateDer::from_pem_slice(serving.certificate_pem.as_bytes())
        .map_err(TlsConfigError::Certificate)?;
    let key = PrivateKeyDer::from_pem_slice(serving.private_key_pem.as_bytes())
        .map_err(TlsConfigError::Key)?;
    // The workspace links both `aws-lc-rs` and `ring`, so rustls can't choose
    // a crypto provider by itself. This passes one explicitly.
    let mut config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(TlsConfigError::Rustls)?
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .map_err(TlsConfigError::Rustls)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases};

    use super::*;
    use crate::pki::test_support::TestCaPem;

    #[test]
    fn server_config() {
        let authority = TestCaPem::p256().load();
        let serving = authority
            .issue_certificate(&["localhost".to_owned()], 1)
            .unwrap();
        let without_key = IssuedCertificate {
            certificate_pem: serving.certificate_pem.clone(),
            private_key_pem: String::new(),
        };
        check_cases(
            [
                Case {
                    scenario: "an issued leaf serves h2 and HTTP/1.1",
                    input: &serving,
                    expect: Yields(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
                },
                Case {
                    scenario: "a missing key is an error",
                    input: &without_key,
                    expect: Fails,
                },
            ],
            |serving| {
                super::server_config(serving)
                    .map(|config| config.alpn_protocols)
                    .map_err(drop)
            },
        );
    }
}
