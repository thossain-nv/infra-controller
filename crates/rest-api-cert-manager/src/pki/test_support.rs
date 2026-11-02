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

//! Test CAs are generated in the test process, so no private key is checked in.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, SignatureAlgorithm,
};

use super::CertificateAuthority;

/// A self-signed CA certificate and its private key, both PEM encoded.
pub(crate) struct TestCaPem {
    pub(crate) certificate: String,
    pub(crate) key: String,
}

impl TestCaPem {
    /// Self-signs `params` with `key`. The key is stored as PKCS#8.
    pub(crate) fn self_signed(params: &CertificateParams, key: &KeyPair) -> Self {
        Self {
            certificate: params
                .self_signed(key)
                .expect("self-sign the test CA")
                .pem(),
            key: key.serialize_pem(),
        }
    }

    /// Generates a CA with a fresh key for `algorithm`.
    pub(crate) fn generate(algorithm: &'static SignatureAlgorithm) -> Self {
        let key = KeyPair::generate_for(algorithm).expect("generate the test CA key");
        Self::self_signed(&ca_params("Test CA"), &key)
    }

    /// Generates a P-256 CA. P-256 keys are the quickest to generate and sign
    /// with.
    pub(crate) fn p256() -> Self {
        Self::generate(&PKCS_ECDSA_P256_SHA256)
    }

    /// Loads this CA the way the service does.
    pub(crate) fn load(&self) -> CertificateAuthority {
        CertificateAuthority::from_pem(self.certificate.clone().into_bytes(), self.key.as_bytes())
            .expect("load the test CA")
    }
}

/// Builds parameters that match the Site CA's. They set an organization and a
/// common name, CA basic constraints and key usages for signing certificates
/// and CRLs.
pub(crate) fn ca_params(common_name: &str) -> CertificateParams {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::OrganizationName, "NVIDIA");
    distinguished_name.push(DnType::CommonName, common_name);
    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params
}
