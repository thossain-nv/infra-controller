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

//! [`CertificateAuthority`] is the Site CA. This module loads it from a
//! certificate file and a key file, then uses it to issue leaf certificates.

use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;

use pkcs1::der::{Decode, EncodePem};
use rcgen::string::{Ia5String, PrintableString};
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, DnType, DnValue,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA512, PKCS_RSA_SHA256, PublicKeyData, RsaKeySize,
    SanType, SerialNumber, SignatureAlgorithm,
};
use rustls_pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use time::{Duration, OffsetDateTime};
use x509_parser::certificate::X509Certificate;
use x509_parser::error::X509Error;
use x509_parser::extensions::ParsedExtension;
use x509_parser::nom;
use x509_parser::prelude::FromDer;

/// The API returns each leaf key as a PKCS#1 `RSA PRIVATE KEY`, so leaf keys
/// are RSA-2048 regardless of the CA key type.
const LEAF_KEY_SIZE: RsaKeySize = RsaKeySize::_2048;

/// Each serial number is `128` random bits, so serials don't repeat in
/// practice.
const SERIAL_NUMBER_BYTES: usize = 16;

/// The `BasicConstraints` extension OID.
const BASIC_CONSTRAINTS_OID: &[u64] = &[2, 5, 29, 19];

/// The end-entity `BasicConstraints` value, an empty `SEQUENCE {}`. Since cA
/// is FALSE and there's no path length, DER requires the sequence to be empty.
/// Every leaf includes it as a critical extension. rcgen's
/// `IsCa::ExplicitNoCa` would encode an explicit FALSE, which DER forbids. It
/// would also add a subject key identifier.
const END_ENTITY_BASIC_CONSTRAINTS: [u8; 2] = [0x30, 0x00];

/// After a malformed block, [`first_pem_block`] skips past this marker and
/// searches again.
const PEM_BEGIN: &[u8] = b"-----BEGIN ";

/// A CA certificate file and its private key file.
#[derive(Debug, Clone)]
pub(crate) struct CaFiles {
    /// The PEM certificate file. If it's a bundle, the first block is the
    /// signing certificate.
    pub(crate) certificate: PathBuf,
    /// The PEM private key file for the first certificate.
    pub(crate) key: PathBuf,
}

impl CaFiles {
    /// Returns whether both paths are set. A pair is only tried when they are.
    fn is_configured(&self) -> bool {
        !self.certificate.as_os_str().is_empty() && !self.key.as_os_str().is_empty()
    }
}

/// Which of the two configured pairs a CA was loaded from, or failed to load
/// from.
#[derive(Debug, Clone, Copy)]
enum CaSource {
    Primary,
    Alternate,
}

impl fmt::Display for CaSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Primary => f.write_str("primary"),
            Self::Alternate => f.write_str("alternate"),
        }
    }
}

/// An error explaining why no CA could be loaded at startup.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LoadError {
    /// Neither pair has both of its paths set.
    #[error("ca certificate required: no paths configured")]
    Unconfigured,
    /// Every configured pair failed. The primary pair's failure is listed
    /// first. The message says "not found" regardless of the actual failure.
    #[error(
        "ca certificate required but not found: {}",
        .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ")
    )]
    NoUsablePair(Vec<CaFilesError>),
}

/// An error explaining why one configured pair couldn't be used.
#[derive(Debug, thiserror::Error)]
#[error("{ca_source} path ({}): {error}", certificate_path.display())]
pub(crate) struct CaFilesError {
    ca_source: CaSource,
    certificate_path: PathBuf,
    error: CaError,
}

/// An error explaining why a CA certificate and key couldn't be used to sign.
#[derive(Debug, thiserror::Error)]
pub(super) enum CaError {
    #[error("failed to read ca certificate file: {0}")]
    ReadCertificate(std::io::Error),
    #[error("failed to read ca private key file: {0}")]
    ReadKey(std::io::Error),
    #[error("failed to decode ca certificate pem")]
    DecodeCertificatePem,
    #[error("failed to parse ca certificate: {0}")]
    ParseCertificate(nom::Err<X509Error>),
    #[error("failed to parse ca certificate: trailing data")]
    CertificateTrailingData,
    #[error("certificate is not a ca")]
    NotCa,
    #[error("failed to decode ca private key pem")]
    DecodeKeyPem,
    #[error("unsupported private key type: {0}")]
    UnsupportedKeyType(String),
    #[error("failed to parse ca private key: {0}")]
    ParseKey(rcgen::Error),
    #[error("unsupported private key type in {label}: {algorithm:?}")]
    UnsupportedKeyAlgorithm {
        label: String,
        algorithm: &'static SignatureAlgorithm,
    },
    #[error("ca private key does not match the ca certificate")]
    KeyMismatch,
    #[error("failed to use the ca certificate as an issuer: {0}")]
    Issuer(rcgen::Error),
    #[error("failed to sign with the ca key: {0}")]
    Sign(rcgen::Error),
    #[error("failed to parse the certificate signed to check the issuer name: {0}")]
    ParseProbe(nom::Err<X509Error>),
    #[error("ca subject cannot be reproduced byte for byte as the issuer name of its leaves")]
    IssuerNameMismatch,
}

/// An error explaining why a leaf certificate couldn't be issued.
#[derive(Debug, thiserror::Error)]
pub(crate) enum IssueError {
    #[error("at least one non-empty DNS name is required to issue a certificate")]
    NoDnsName,
    #[error("DNS name {name:?} is not ASCII: {error}")]
    DnsName { name: String, error: rcgen::Error },
    #[error("certificate TTL of {0} hours is out of range")]
    TtlOutOfRange(i64),
    #[error("failed to generate key: {0}")]
    GenerateKey(rcgen::Error),
    #[error("failed to create certificate: {0}")]
    Sign(rcgen::Error),
    #[error("failed to encode the private key as PKCS#1: {0}")]
    EncodeKey(pkcs1::Error),
}

/// A leaf certificate and its private key, both PEM encoded with LF line
/// endings.
pub(crate) struct IssuedCertificate {
    /// The leaf's `CERTIFICATE` block, without the CA chain.
    pub(crate) certificate_pem: String,
    /// The leaf's private key as a PKCS#1 `RSA PRIVATE KEY` block.
    pub(crate) private_key_pem: String,
}

/// The signing CA. It doesn't change after loading, so it's shared without a
/// lock.
pub(crate) struct CertificateAuthority {
    /// The CA certificate file, exactly as read. It may be a bundle, have text
    /// before the first block or use CRLF line endings.
    pub(crate) certificate_pem: Vec<u8>,
    /// The file's first well-formed PEM block, regardless of its label. It
    /// contains the signing certificate.
    pub(crate) certificate_block: pem::Pem,
    issuer: Issuer<'static, KeyPair>,
    /// Whether the CA certificate has a subject key identifier. Leaves get an
    /// authority key identifier with the same value only when the CA has one.
    has_subject_key_id: bool,
}

impl CertificateAuthority {
    /// Loads the CA from `primary`, or from `alternate` if the primary pair is
    /// unset or can't be used. A pair is skipped unless both of its paths are
    /// set.
    pub(crate) fn load(primary: &CaFiles, alternate: &CaFiles) -> Result<Self, LoadError> {
        let mut failures = Vec::new();
        for (ca_source, files) in [
            (CaSource::Primary, primary),
            (CaSource::Alternate, alternate),
        ] {
            if !files.is_configured() {
                continue;
            }
            let read = Self::read(files);
            match read {
                Ok(authority) => {
                    tracing::info!(
                        %ca_source,
                        ca_certificate_path = %files.certificate.display(),
                        "loaded CA"
                    );
                    return Ok(authority);
                }
                Err(error) => failures.push(CaFilesError {
                    ca_source,
                    certificate_path: files.certificate.clone(),
                    error,
                }),
            }
        }
        if failures.is_empty() {
            Err(LoadError::Unconfigured)
        } else {
            Err(LoadError::NoUsablePair(failures))
        }
    }

    fn read(files: &CaFiles) -> Result<Self, CaError> {
        let certificate_pem =
            std::fs::read(&files.certificate).map_err(CaError::ReadCertificate)?;
        let key_pem = std::fs::read(&files.key).map_err(CaError::ReadKey)?;
        Self::from_pem(certificate_pem, &key_pem)
    }

    /// Builds the CA from the first well-formed PEM block in the certificate
    /// file and in the key file. See [`first_pem_block`].
    ///
    /// The certificate must be a CA. The key's PEM label decides its format.
    /// `RSA PRIVATE KEY` is read as PKCS#1, `EC PRIVATE KEY` as SEC1 and
    /// `PRIVATE KEY` as PKCS#8. The signer only supports RSA keys of `2048` to
    /// `8192` bits and ECDSA P-256, P-384 or P-521 keys.
    ///
    /// This fails if the key doesn't match the certificate, or if the CA
    /// subject wouldn't be reproduced byte for byte as its leaves' issuer name.
    /// Failing early lets [`load`](Self::load) try the alternate pair instead
    /// of every issuance failing later.
    pub(super) fn from_pem(certificate_pem: Vec<u8>, key_pem: &[u8]) -> Result<Self, CaError> {
        let certificate_block =
            first_pem_block(&certificate_pem).ok_or(CaError::DecodeCertificatePem)?;
        let (remainder, certificate) = X509Certificate::from_der(certificate_block.contents())
            .map_err(CaError::ParseCertificate)?;
        if !remainder.is_empty() {
            return Err(CaError::CertificateTrailingData);
        }
        if !certificate.is_ca() {
            return Err(CaError::NotCa);
        }

        let signing_key = parse_private_key(key_pem)?;
        if signing_key.der_bytes() != certificate.public_key().subject_public_key.data.as_ref() {
            return Err(CaError::KeyMismatch);
        }

        let has_subject_key_id = certificate.extensions().iter().any(|extension| {
            matches!(
                extension.parsed_extension(),
                ParsedExtension::SubjectKeyIdentifier(_)
            )
        });
        let subject = certificate.subject().as_raw().to_vec();
        let issuer = Issuer::from_ca_cert_der(
            &CertificateDer::from(certificate_block.contents()),
            signing_key,
        )
        .map_err(CaError::Issuer)?;

        let authority = Self {
            certificate_pem,
            certificate_block,
            issuer,
            has_subject_key_id,
        };
        authority.ensure_issuer_name_round_trips(&subject)?;
        Ok(authority)
    }

    /// Issues an RSA-2048 leaf for `dns_names`, valid from now for `ttl_hours`.
    /// A negative TTL is accepted and gives a leaf that expires before it
    /// becomes valid. X.509 dates can only express the years 0 to 9999. So a
    /// TTL whose end date falls outside them fails with
    /// [`IssueError::TtlOutOfRange`].
    ///
    /// The first name becomes the subject common name. If it's empty, the
    /// subject is left empty. Every distinct non-empty name becomes a DNS
    /// subject alternative name, in order. Names must be ASCII, but aren't
    /// otherwise checked.
    pub(crate) fn issue_certificate(
        &self,
        dns_names: &[String],
        ttl_hours: i64,
    ) -> Result<IssuedCertificate, IssueError> {
        let mut seen = HashSet::new();
        let subject_alt_names = dns_names
            .iter()
            .filter(|name| !name.is_empty() && seen.insert(name.as_str()))
            .map(|name| {
                Ia5String::try_from(name.as_str())
                    .map(SanType::DnsName)
                    .map_err(|error| IssueError::DnsName {
                        name: name.clone(),
                        error,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if subject_alt_names.is_empty() {
            return Err(IssueError::NoDnsName);
        }

        // rcgen panics on a date it can't encode. `time` already rejects years
        // after 9999, so only the year 0 lower limit is checked explicitly.
        let not_before = OffsetDateTime::now_utc();
        let not_after = ttl_hours
            .checked_mul(3600)
            .map(Duration::seconds)
            .and_then(|ttl| not_before.checked_add(ttl))
            .filter(|not_after| not_after.year() >= 0)
            .ok_or(IssueError::TtlOutOfRange(ttl_hours))?;

        let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, LEAF_KEY_SIZE)
            .map_err(IssueError::GenerateKey)?;

        let mut basic_constraints = CustomExtension::from_oid_content(
            BASIC_CONSTRAINTS_OID,
            END_ENTITY_BASIC_CONSTRAINTS.to_vec(),
        );
        basic_constraints.set_criticality(true);

        let mut params = CertificateParams::default();
        params.serial_number = Some(SerialNumber::from_slice(&rand::random::<
            [u8; SERIAL_NUMBER_BYTES],
        >()));
        params.distinguished_name = subject(dns_names.first().map_or("", String::as_str));
        params.not_before = not_before;
        params.not_after = not_after;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.subject_alt_names = subject_alt_names;
        params.is_ca = IsCa::NoCa;
        params.custom_extensions = vec![basic_constraints];
        params.use_authority_key_identifier_extension = self.has_subject_key_id;

        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(IssueError::Sign)?;
        Ok(IssuedCertificate {
            certificate_pem: certificate.pem(),
            private_key_pem: rsa_private_key_pem(&key).map_err(IssueError::EncodeKey)?,
        })
    }

    /// Checks that rcgen writes the CA subject byte for byte as a leaf's issuer
    /// name. rcgen re-encodes the subject instead of copying its DER. It also
    /// merges repeated attribute types, such as two `OU`s. Leaves from a CA
    /// whose subject changes this way wouldn't chain. So this signs a throwaway
    /// certificate and rejects the CA if the issuer name doesn't match.
    fn ensure_issuer_name_round_trips(&self, ca_subject: &[u8]) -> Result<(), CaError> {
        let mut params = CertificateParams::default();
        params.serial_number = Some(SerialNumber::from(1u64));
        let probe = params
            .signed_by(self.issuer.key(), &self.issuer)
            .map_err(CaError::Sign)?;
        let (_, probe) = X509Certificate::from_der(probe.der()).map_err(CaError::ParseProbe)?;
        if probe.issuer().as_raw() != ca_subject {
            return Err(CaError::IssuerNameMismatch);
        }
        Ok(())
    }
}

/// Parses the key file's first PEM block in the format its label names. Only
/// RSA keys and ECDSA P-256, P-384 or P-521 keys are accepted for signing.
fn parse_private_key(key_pem: &[u8]) -> Result<KeyPair, CaError> {
    let block = first_pem_block(key_pem).ok_or(CaError::DecodeKeyPem)?;
    let der = block.contents();
    let rsa = [&PKCS_RSA_SHA256];
    let ecdsa = [
        &PKCS_ECDSA_P256_SHA256,
        &PKCS_ECDSA_P384_SHA384,
        &PKCS_ECDSA_P521_SHA512,
    ];
    let (key_der, allowed): (PrivateKeyDer<'_>, &[&SignatureAlgorithm]) = match block.tag() {
        "RSA PRIVATE KEY" => (PrivatePkcs1KeyDer::from(der).into(), &rsa),
        "EC PRIVATE KEY" => (PrivateSec1KeyDer::from(der).into(), &ecdsa),
        "PRIVATE KEY" => (
            PrivatePkcs8KeyDer::from(der).into(),
            &[rsa.as_slice(), ecdsa.as_slice()].concat(),
        ),
        label => return Err(CaError::UnsupportedKeyType(label.to_owned())),
    };
    let key = KeyPair::try_from(&key_der).map_err(CaError::ParseKey)?;
    if !allowed.contains(&key.algorithm()) {
        return Err(CaError::UnsupportedKeyAlgorithm {
            label: block.tag().to_owned(),
            algorithm: key.algorithm(),
        });
    }
    Ok(key)
}

/// Returns the first well-formed PEM block in `input`, regardless of its
/// label. It skips leading text, such as the description `openssl x509 -text`
/// writes. It also skips any malformed block before it.
fn first_pem_block(input: &[u8]) -> Option<pem::Pem> {
    let mut rest = input;
    loop {
        if let Ok(block) = pem::parse(rest) {
            return Some(block);
        }
        let begin = rest
            .windows(PEM_BEGIN.len())
            .position(|window| window == PEM_BEGIN)?;
        rest = &rest[begin + PEM_BEGIN.len()..];
    }
}

/// Builds a leaf subject with `common_name` as its only attribute, or an empty
/// subject for an empty name. The name is a PrintableString when every
/// character is in that set. Names with other characters, such as `*`, `_` or
/// `&`, are a UTF8String.
fn subject(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    if !common_name.is_empty() {
        let value = PrintableString::try_from(common_name)
            .map(DnValue::PrintableString)
            .unwrap_or_else(|_| DnValue::Utf8String(common_name.to_owned()));
        name.push(DnType::CommonName, value);
    }
    name
}

/// Converts an RSA `key` to a PKCS#1 PEM block. rcgen stores generated keys as
/// PKCS#8, but the API returns PKCS#1.
fn rsa_private_key_pem(key: &KeyPair) -> Result<String, pkcs1::Error> {
    let private_key_info = pkcs8::PrivateKeyInfo::from_der(key.serialized_der())?;
    private_key_info
        .algorithm
        .assert_algorithm_oid(pkcs1::ALGORITHM_OID)?;
    let rsa_key = pkcs1::RsaPrivateKey::from_der(private_key_info.private_key)?;
    Ok(rsa_key.to_pem(pkcs1::LineEnding::LF)?)
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases, value_scenarios};
    use pem::{EncodeConfig, LineEnding};
    use rcgen::PKCS_ED25519;
    use x509_parser::certificate::BasicExtension;
    use x509_parser::der_parser::asn1_rs::Tag;
    use x509_parser::extensions::{ExtendedKeyUsage, GeneralName, SubjectAlternativeName};
    use x509_parser::oid_registry::{
        OID_PKCS1_SHA256WITHRSA, OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ECDSA_WITH_SHA384,
        OID_SIG_ECDSA_WITH_SHA512, OID_X509_EXT_BASIC_CONSTRAINTS,
    };
    use x509_parser::x509::X509Version;

    use super::*;
    use crate::pki::test_support::{TestCaPem, ca_params};

    /// One CA per key format. The cases of a table share them.
    struct Fixtures {
        rsa_pkcs1: TestCaPem,
        rsa_pkcs8: TestCaPem,
        p256_sec1: TestCaPem,
        p256_pkcs8: TestCaPem,
        p384_pkcs8: TestCaPem,
        p521_pkcs8: TestCaPem,
    }

    impl Fixtures {
        fn generate() -> Self {
            let rsa_key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
            let rsa_pkcs8 = TestCaPem::self_signed(&ca_params("RSA CA"), &rsa_key);
            let rsa_pkcs1 = TestCaPem {
                key: super::rsa_private_key_pem(&rsa_key).unwrap(),
                ..TestCaPem::self_signed(&ca_params("RSA CA"), &rsa_key)
            };
            let p256_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let p256_pkcs8 = TestCaPem::self_signed(&ca_params("P-256 CA"), &p256_key);
            let p256_sec1 = TestCaPem {
                key: sec1_pem(&p256_key),
                ..TestCaPem::self_signed(&ca_params("P-256 CA"), &p256_key)
            };
            Self {
                rsa_pkcs1,
                rsa_pkcs8,
                p256_sec1,
                p256_pkcs8,
                p384_pkcs8: TestCaPem::generate(&PKCS_ECDSA_P384_SHA384),
                p521_pkcs8: TestCaPem::generate(&PKCS_ECDSA_P521_SHA512),
            }
        }
    }

    /// Extracts the SEC1 `EC PRIVATE KEY` from a generated PKCS#8 key.
    fn sec1_pem(key: &KeyPair) -> String {
        let private_key_info = pkcs8::PrivateKeyInfo::from_der(key.serialized_der()).unwrap();
        pem::encode(&pem::Pem::new(
            "EC PRIVATE KEY",
            private_key_info.private_key,
        ))
    }

    /// Replaces the `from` label with `to` in the BEGIN and END lines of
    /// `pem_text`.
    fn relabel(pem_text: &str, from: &str, to: &str) -> String {
        pem_text
            .replace(&format!("BEGIN {from}-----"), &format!("BEGIN {to}-----"))
            .replace(&format!("END {from}-----"), &format!("END {to}-----"))
    }

    /// Converts a parse failure inside a table operation into the case's error.
    /// That way the failure message names the case.
    fn failure(error: impl fmt::Display) -> String {
        error.to_string()
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn from_pem() {
        let fixtures = Fixtures::generate();
        let ed25519 = TestCaPem::generate(&PKCS_ED25519);
        let not_ca = {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let mut params = ca_params("Not a CA");
            params.is_ca = IsCa::NoCa;
            TestCaPem::self_signed(&params, &key)
        };
        let repeated_attribute = {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let mut params = ca_params("Repeated OU CA");
            // Both variants encode OID `2.5.4.11`. rcgen reads them back as a
            // single `OU`, so the issuer name of the CA's leaves would differ.
            params
                .distinguished_name
                .push(DnType::OrganizationalUnitName, "Platform");
            params
                .distinguished_name
                .push(DnType::CustomDnType(vec![2, 5, 4, 11]), "Infra");
            TestCaPem::self_signed(&params, &key)
        };
        let p256 = &fixtures.p256_pkcs8;
        let other_p256 = TestCaPem::p256();
        let ec_parameters_first = format!(
            "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n{}",
            fixtures.p256_sec1.key
        );
        let garbage_der = pem::encode(&pem::Pem::new("CERTIFICATE", b"not der".to_vec()));
        let trailing_der = {
            let block = super::first_pem_block(p256.certificate.as_bytes()).unwrap();
            let mut der = block.into_contents();
            der.push(0);
            pem::encode(&pem::Pem::new("CERTIFICATE", der))
        };

        check_cases(
            [
                Case {
                    scenario: "PKCS#1 RSA PRIVATE KEY",
                    input: (fixtures.rsa_pkcs1.certificate.as_str(), fixtures.rsa_pkcs1.key.as_str()),
                    expect: Yields(()),
                },
                Case {
                    scenario: "PKCS#8 PRIVATE KEY holding RSA",
                    input: (fixtures.rsa_pkcs8.certificate.as_str(), fixtures.rsa_pkcs8.key.as_str()),
                    expect: Yields(()),
                },
                Case {
                    scenario: "SEC1 EC PRIVATE KEY",
                    input: (fixtures.p256_sec1.certificate.as_str(), fixtures.p256_sec1.key.as_str()),
                    expect: Yields(()),
                },
                Case {
                    scenario: "PKCS#8 PRIVATE KEY holding P-384",
                    input: (fixtures.p384_pkcs8.certificate.as_str(), fixtures.p384_pkcs8.key.as_str()),
                    expect: Yields(()),
                },
                Case {
                    scenario: "PKCS#8 PRIVATE KEY holding P-521",
                    input: (fixtures.p521_pkcs8.certificate.as_str(), fixtures.p521_pkcs8.key.as_str()),
                    expect: Yields(()),
                },
                Case {
                    scenario: "certificate file without a PEM block",
                    input: ("not pem", p256.key.as_str()),
                    expect: FailsWith("failed to decode ca certificate pem".to_owned()),
                },
                Case {
                    scenario: "certificate block that is not DER",
                    input: (garbage_der.as_str(), p256.key.as_str()),
                    expect: Fails,
                },
                Case {
                    scenario: "certificate DER with trailing bytes",
                    input: (trailing_der.as_str(), p256.key.as_str()),
                    expect: FailsWith("failed to parse ca certificate: trailing data".to_owned()),
                },
                Case {
                    scenario: "certificate that is not a CA",
                    input: (not_ca.certificate.as_str(), not_ca.key.as_str()),
                    expect: FailsWith("certificate is not a ca".to_owned()),
                },
                Case {
                    scenario: "key file without a PEM block",
                    input: (p256.certificate.as_str(), "not pem"),
                    expect: FailsWith("failed to decode ca private key pem".to_owned()),
                },
                Case {
                    scenario: "key file starting with EC PARAMETERS, as openssl ecparam writes",
                    input: (fixtures.p256_sec1.certificate.as_str(), ec_parameters_first.as_str()),
                    expect: FailsWith("unsupported private key type: EC PARAMETERS".to_owned()),
                },
                Case {
                    scenario: "key block whose DER is not a key",
                    input: (
                        p256.certificate.as_str(),
                        "-----BEGIN RSA PRIVATE KEY-----\nAQI=\n-----END RSA PRIVATE KEY-----\n",
                    ),
                    expect: FailsWith("failed to parse ca private key: Could not parse key pair".to_owned()),
                },
                Case {
                    scenario: "RSA PRIVATE KEY label around an EC key",
                    input: (
                        p256.certificate.as_str(),
                        &relabel(&p256.key, "PRIVATE KEY", "RSA PRIVATE KEY"),
                    ),
                    expect: FailsWith(
                        "unsupported private key type in RSA PRIVATE KEY: PKCS_ECDSA_P256_SHA256".to_owned(),
                    ),
                },
                Case {
                    scenario: "Ed25519 PKCS#8 key",
                    input: (ed25519.certificate.as_str(), ed25519.key.as_str()),
                    expect: FailsWith("unsupported private key type in PRIVATE KEY: PKCS_ED25519".to_owned()),
                },
                Case {
                    scenario: "key of another CA",
                    input: (p256.certificate.as_str(), other_p256.key.as_str()),
                    expect: FailsWith("ca private key does not match the ca certificate".to_owned()),
                },
                Case {
                    scenario: "subject with a repeated attribute type",
                    input: (repeated_attribute.certificate.as_str(), repeated_attribute.key.as_str()),
                    expect: FailsWith(
                        "ca subject cannot be reproduced byte for byte as the issuer name of its leaves"
                            .to_owned(),
                    ),
                },
            ],
            |(certificate, key)| {
                CertificateAuthority::from_pem(certificate.as_bytes().to_vec(), key.as_bytes())
                    .map(drop)
                    .map_err(failure)
            },
        );
    }

    #[test]
    fn load() {
        let directory = tempfile::tempdir().unwrap();
        let write = |name: &str, contents: &str| {
            let path = directory.path().join(name);
            std::fs::write(&path, contents).unwrap();
            path
        };
        let primary_ca = TestCaPem::p256();
        let alternate_ca = TestCaPem::p256();
        let primary = CaFiles {
            certificate: write("primary.crt", &primary_ca.certificate),
            key: write("primary.key", &primary_ca.key),
        };
        let alternate = CaFiles {
            certificate: write("alternate.crt", &alternate_ca.certificate),
            key: write("alternate.key", &alternate_ca.key),
        };
        let missing = CaFiles {
            certificate: directory.path().join("missing.crt"),
            key: directory.path().join("missing.key"),
        };
        let missing_key = CaFiles {
            key: missing.key.clone(),
            ..primary.clone()
        };
        let unset = CaFiles {
            certificate: PathBuf::new(),
            key: PathBuf::new(),
        };
        let certificate_only = CaFiles {
            key: PathBuf::new(),
            ..primary.clone()
        };
        let not_found = |ca_source: &str, files: &CaFiles| {
            format!(
                "{ca_source} path ({}): failed to read ca certificate file: No such file or directory (os error 2)",
                files.certificate.display()
            )
        };

        check_cases(
            [
                Case {
                    scenario: "the primary pair wins when it loads",
                    input: (&primary, &alternate),
                    expect: Yields(primary_ca.certificate.into_bytes()),
                },
                Case {
                    scenario: "an unreadable primary pair falls back to the alternate",
                    input: (&missing, &alternate),
                    expect: Yields(alternate_ca.certificate.clone().into_bytes()),
                },
                Case {
                    scenario: "an unset primary pair falls back to the alternate",
                    input: (&unset, &alternate),
                    expect: Yields(alternate_ca.certificate.into_bytes()),
                },
                Case {
                    scenario: "a pair with only a certificate path counts as unset",
                    input: (&certificate_only, &unset),
                    expect: FailsWith("ca certificate required: no paths configured".to_owned()),
                },
                Case {
                    scenario: "both pairs failing reports both, primary first",
                    input: (&missing, &missing),
                    expect: FailsWith(format!(
                        "ca certificate required but not found: {}; {}",
                        not_found("primary", &missing),
                        not_found("alternate", &missing)
                    )),
                },
                Case {
                    scenario: "only the alternate pair set and failing",
                    input: (&unset, &missing),
                    expect: FailsWith(format!(
                        "ca certificate required but not found: {}",
                        not_found("alternate", &missing)
                    )),
                },
                Case {
                    scenario: "a readable certificate with a missing key",
                    input: (&missing_key, &unset),
                    expect: FailsWith(format!(
                        "ca certificate required but not found: primary path ({}): failed to read ca private key \
                         file: No such file or directory (os error 2)",
                        missing_key.certificate.display()
                    )),
                },
            ],
            |(primary, alternate)| {
                CertificateAuthority::load(primary, alternate)
                    .map(|authority| authority.certificate_pem)
                    .map_err(failure)
            },
        );
    }

    /// How a leaf's subject common name is encoded.
    #[derive(Debug, PartialEq)]
    enum CommonName {
        /// The subject is the empty sequence.
        None,
        Printable(String),
        Utf8(String),
    }

    /// The label of a PEM text and whether the text is canonical. Canonical
    /// text is that one block alone, in LF lines of at most `64` columns.
    #[derive(Debug, PartialEq)]
    struct PemText {
        label: String,
        canonical: bool,
    }

    /// What a leaf's authority key identifier contains.
    #[derive(Debug, PartialEq)]
    enum AuthorityKeyId {
        Absent,
        /// The CA's subject key identifier.
        CaSubjectKeyId,
        /// Any other value.
        Other,
    }

    /// What a test observes about an issued leaf and its key. [`leaf`] returns
    /// the values every leaf shares, so each case only sets what it changes.
    #[derive(Debug, PartialEq)]
    struct Leaf {
        certificate_pem: PemText,
        key_pem: PemText,
        version: X509Version,
        issuer_is_ca_subject: bool,
        /// Whether the CA key signed the leaf. If the validity window isn't
        /// empty, rustls also accepted the chain to the CA for serverAuth
        /// within that window.
        signed_by_ca: bool,
        /// Whether the serial is positive and at most `128` bits long.
        positive_128_bit_serial: bool,
        common_name: CommonName,
        dns_names: Vec<String>,
        subject_alt_name_critical: bool,
        key_usage: Option<BasicExtension<String>>,
        extended_key_usage: Option<BasicExtension<Vec<&'static str>>>,
        basic_constraints: Option<BasicExtension<Vec<u8>>>,
        has_subject_key_id: bool,
        authority_key_id: AuthorityKeyId,
        signature_algorithm: String,
        validity_seconds: i64,
        key_bits: usize,
        key_matches_certificate: bool,
    }

    /// Describes a `48h` leaf issued by a P-256 CA that has a subject key
    /// identifier.
    fn leaf(common_name: CommonName, dns_names: &[&str]) -> Leaf {
        Leaf {
            certificate_pem: PemText {
                label: "CERTIFICATE".to_owned(),
                canonical: true,
            },
            key_pem: PemText {
                label: "RSA PRIVATE KEY".to_owned(),
                canonical: true,
            },
            version: X509Version::V3,
            issuer_is_ca_subject: true,
            signed_by_ca: true,
            positive_128_bit_serial: true,
            common_name,
            dns_names: names(dns_names),
            subject_alt_name_critical: false,
            key_usage: Some(BasicExtension::new(
                true,
                "Digital Signature, Key Encipherment".to_owned(),
            )),
            extended_key_usage: Some(BasicExtension::new(false, vec!["serverAuth", "clientAuth"])),
            basic_constraints: Some(BasicExtension::new(
                true,
                END_ENTITY_BASIC_CONSTRAINTS.to_vec(),
            )),
            has_subject_key_id: false,
            authority_key_id: AuthorityKeyId::CaSubjectKeyId,
            signature_algorithm: OID_SIG_ECDSA_WITH_SHA256.to_id_string(),
            validity_seconds: 48 * 3600,
            key_bits: 2048,
            key_matches_certificate: true,
        }
    }

    impl Leaf {
        /// Parses `issued` and checks it against the CA that issued it.
        fn read(ca: &TestCaPem, issued: &IssuedCertificate) -> Result<Self, String> {
            let ca_der = pem::parse(&ca.certificate)
                .map_err(failure)?
                .into_contents();
            let (_, ca) = X509Certificate::from_der(&ca_der).map_err(failure)?;
            let (certificate_pem, leaf_der) = pem_text(&issued.certificate_pem)?;
            let (_, leaf) = X509Certificate::from_der(&leaf_der).map_err(failure)?;
            let (key_pem, key_der) = pem_text(&issued.private_key_pem)?;
            let rsa_key = pkcs1::RsaPrivateKey::from_der(&key_der).map_err(failure)?;
            let key_pair = KeyPair::try_from(&PrivateKeyDer::from(PrivatePkcs1KeyDer::from(
                key_der.as_slice(),
            )))
            .map_err(failure)?;
            let subject_alt_name = leaf
                .subject_alternative_name()
                .map_err(failure)?
                .ok_or("no subject alternative name")?;
            let validity = leaf.validity();
            Ok(Self {
                certificate_pem,
                key_pem,
                version: leaf.version(),
                issuer_is_ca_subject: leaf.issuer().as_raw() == ca.subject().as_raw(),
                signed_by_ca: signed_by_ca(&ca_der, &ca, &leaf_der, &leaf),
                positive_128_bit_serial: is_positive_128_bit(leaf.raw_serial()),
                common_name: common_name(&leaf)?,
                dns_names: dns_names(subject_alt_name.value)?,
                subject_alt_name_critical: subject_alt_name.critical,
                key_usage: leaf
                    .key_usage()
                    .map_err(failure)?
                    .map(|usage| BasicExtension::new(usage.critical, usage.value.to_string())),
                extended_key_usage: leaf
                    .extended_key_usage()
                    .map_err(failure)?
                    .map(|usage| BasicExtension::new(usage.critical, purposes(usage.value))),
                basic_constraints: leaf
                    .get_extension_unique(&OID_X509_EXT_BASIC_CONSTRAINTS)
                    .map_err(failure)?
                    .map(|extension| {
                        BasicExtension::new(extension.critical, extension.value.to_vec())
                    }),
                has_subject_key_id: subject_key_id(&leaf).is_some(),
                authority_key_id: authority_key_id(&leaf, &ca),
                signature_algorithm: leaf.signature_algorithm.algorithm.to_id_string(),
                validity_seconds: validity.not_after.timestamp() - validity.not_before.timestamp(),
                key_bits: rsa_key.modulus.as_bytes().len() * 8,
                key_matches_certificate: key_pair.der_bytes()
                    == leaf.public_key().subject_public_key.data.as_ref(),
            })
        }
    }

    /// Parses a PEM text and describes its layout. See [`PemText`].
    fn pem_text(text: &str) -> Result<(PemText, Vec<u8>), String> {
        let block = pem::parse(text).map_err(failure)?;
        let lf_encoding =
            pem::encode_config(&block, EncodeConfig::new().set_line_ending(LineEnding::LF));
        let pem_text = PemText {
            label: block.tag().to_owned(),
            canonical: lf_encoding == text,
        };
        Ok((pem_text, block.into_contents()))
    }

    /// Checks whether the CA key signed `leaf`. If the validity window isn't
    /// empty, rustls verifies the signature, the chain and serverAuth at the
    /// window's start. Unlike x509-parser, rustls can verify ecdsa-with-SHA512.
    /// For an empty window, x509-parser only verifies the signature.
    fn signed_by_ca(
        ca_der: &[u8],
        ca: &X509Certificate<'_>,
        leaf_der: &[u8],
        leaf: &X509Certificate<'_>,
    ) -> bool {
        let validity = leaf.validity();
        let Ok(not_before) = u64::try_from(validity.not_before.timestamp()) else {
            return false;
        };
        if validity.not_after.timestamp() <= validity.not_before.timestamp() {
            return leaf.verify_signature(Some(ca.public_key())).is_ok();
        }
        let mut roots = rustls::RootCertStore::empty();
        let Ok(()) = roots.add(CertificateDer::from(ca_der)) else {
            return false;
        };
        let leaf_der = CertificateDer::from(leaf_der);
        let Ok(leaf) = rustls::server::ParsedCertificate::try_from(&leaf_der) else {
            return false;
        };
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &leaf,
            &roots,
            &[],
            rustls_pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                not_before,
            )),
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .all,
        )
        .is_ok()
    }

    /// Returns whether `serial` is positive and at most `128` bits long. DER
    /// integers are signed, so a positive serial has its first bit clear. A
    /// `128`-bit serial with its top bit set needs a leading zero byte.
    fn is_positive_128_bit(serial: &[u8]) -> bool {
        let magnitude = serial.strip_prefix(&[0]).unwrap_or(serial);
        serial.first().is_some_and(|byte| byte & 0x80 == 0)
            && magnitude.len() <= SERIAL_NUMBER_BYTES
    }

    fn common_name(leaf: &X509Certificate<'_>) -> Result<CommonName, String> {
        let Some(attribute) = leaf.subject().iter_common_name().next() else {
            return match leaf.subject().as_raw() {
                [0x30, 0x00] => Ok(CommonName::None),
                _ => Err(format!("subject {} has no common name", leaf.subject())),
            };
        };
        let value = String::from_utf8(attribute.as_slice().to_vec()).map_err(failure)?;
        match attribute.attr_value().tag() {
            Tag::PrintableString => Ok(CommonName::Printable(value)),
            Tag::Utf8String => Ok(CommonName::Utf8(value)),
            tag => Err(format!("common name {value:?} has tag {tag:?}")),
        }
    }

    fn dns_names(names: &SubjectAlternativeName<'_>) -> Result<Vec<String>, String> {
        names
            .general_names
            .iter()
            .map(|name| match name {
                GeneralName::DNSName(name) => Ok((*name).to_owned()),
                other => Err(format!("unexpected subject alternative name {other:?}")),
            })
            .collect()
    }

    /// Lists the purposes in an extended key usage extension.
    fn purposes(usage: &ExtendedKeyUsage<'_>) -> Vec<&'static str> {
        [
            (usage.any, "any"),
            (usage.server_auth, "serverAuth"),
            (usage.client_auth, "clientAuth"),
            (usage.code_signing, "codeSigning"),
            (usage.email_protection, "emailProtection"),
            (usage.time_stamping, "timeStamping"),
            (usage.ocsp_signing, "OCSPSigning"),
            (!usage.other.is_empty(), "other"),
        ]
        .into_iter()
        .filter_map(|(listed, purpose)| listed.then_some(purpose))
        .collect()
    }

    fn subject_key_id<'a>(certificate: &X509Certificate<'a>) -> Option<&'a [u8]> {
        certificate
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(key_id) => Some(key_id.0),
                _ => None,
            })
    }

    fn authority_key_id(leaf: &X509Certificate<'_>, ca: &X509Certificate<'_>) -> AuthorityKeyId {
        let key_id =
            leaf.extensions()
                .iter()
                .find_map(|extension| match extension.parsed_extension() {
                    ParsedExtension::AuthorityKeyIdentifier(key_id) => {
                        Some(key_id.key_identifier.as_ref().map(|key_id| key_id.0))
                    }
                    _ => None,
                });
        match key_id {
            None => AuthorityKeyId::Absent,
            Some(key_id) if key_id == subject_key_id(ca) => AuthorityKeyId::CaSubjectKeyId,
            Some(_) => AuthorityKeyId::Other,
        }
    }

    struct Issue<'a> {
        ca: &'a TestCaPem,
        dns_names: &'a [&'a str],
        ttl_hours: i64,
    }

    #[test]
    fn issue_certificate() {
        let fixtures = Fixtures::generate();
        let no_subject_key_id = {
            // `IsCa::Ca` always writes a subject key identifier, so this marks
            // the certificate as a CA with a hand-written basic constraints
            // extension instead.
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let mut params = ca_params("CA without SKI");
            params.is_ca = IsCa::NoCa;
            let mut ca_constraints = CustomExtension::from_oid_content(
                BASIC_CONSTRAINTS_OID,
                vec![0x30, 0x03, 0x01, 0x01, 0xff],
            );
            ca_constraints.set_criticality(true);
            params.custom_extensions = vec![ca_constraints];
            TestCaPem::self_signed(&params, &key)
        };
        let p256 = &fixtures.p256_pkcs8;
        let out_of_range = |ttl_hours: i64| {
            FailsWith(format!(
                "certificate TTL of {ttl_hours} hours is out of range"
            ))
        };

        check_cases(
            [
                Case {
                    scenario: "RSA CA signs with sha256WithRSAEncryption",
                    input: Issue {
                        ca: &fixtures.rsa_pkcs1,
                        dns_names: &["svc.ns.local"],
                        ttl_hours: 48,
                    },
                    expect: Yields(Leaf {
                        signature_algorithm: OID_PKCS1_SHA256WITHRSA.to_id_string(),
                        ..leaf(
                            CommonName::Printable("svc.ns.local".to_owned()),
                            &["svc.ns.local"],
                        )
                    }),
                },
                Case {
                    scenario: "P-256 CA signs with ecdsa-with-SHA256",
                    input: Issue {
                        ca: &fixtures.p256_sec1,
                        dns_names: &["svc.ns.local"],
                        ttl_hours: 48,
                    },
                    expect: Yields(leaf(
                        CommonName::Printable("svc.ns.local".to_owned()),
                        &["svc.ns.local"],
                    )),
                },
                Case {
                    scenario: "P-384 CA signs with ecdsa-with-SHA384",
                    input: Issue {
                        ca: &fixtures.p384_pkcs8,
                        dns_names: &["svc.ns.local"],
                        ttl_hours: 48,
                    },
                    expect: Yields(Leaf {
                        signature_algorithm: OID_SIG_ECDSA_WITH_SHA384.to_id_string(),
                        ..leaf(
                            CommonName::Printable("svc.ns.local".to_owned()),
                            &["svc.ns.local"],
                        )
                    }),
                },
                Case {
                    scenario: "P-521 CA signs with ecdsa-with-SHA512",
                    input: Issue {
                        ca: &fixtures.p521_pkcs8,
                        dns_names: &["svc.ns.local"],
                        ttl_hours: 48,
                    },
                    expect: Yields(Leaf {
                        signature_algorithm: OID_SIG_ECDSA_WITH_SHA512.to_id_string(),
                        ..leaf(
                            CommonName::Printable("svc.ns.local".to_owned()),
                            &["svc.ns.local"],
                        )
                    }),
                },
                Case {
                    scenario: "a CA without a subject key identifier gives no AKI",
                    input: Issue {
                        ca: &no_subject_key_id,
                        dns_names: &["svc.ns.local"],
                        ttl_hours: 48,
                    },
                    expect: Yields(Leaf {
                        authority_key_id: AuthorityKeyId::Absent,
                        ..leaf(
                            CommonName::Printable("svc.ns.local".to_owned()),
                            &["svc.ns.local"],
                        )
                    }),
                },
                Case {
                    scenario: "names are deduplicated in order with blanks dropped",
                    input: Issue {
                        ca: p256,
                        dns_names: &["svc.ns", "", "localhost", "svc.ns", "svc.ns.svc"],
                        ttl_hours: 48,
                    },
                    expect: Yields(leaf(
                        CommonName::Printable("svc.ns".to_owned()),
                        &["svc.ns", "localhost", "svc.ns.svc"],
                    )),
                },
                Case {
                    scenario: "a wildcard common name is a UTF8String",
                    input: Issue {
                        ca: p256,
                        dns_names: &["*.svc.local"],
                        ttl_hours: 48,
                    },
                    expect: Yields(leaf(
                        CommonName::Utf8("*.svc.local".to_owned()),
                        &["*.svc.local"],
                    )),
                },
                Case {
                    scenario: "an empty first name leaves the subject empty and the SAN critical",
                    input: Issue {
                        ca: p256,
                        dns_names: &["", "localhost"],
                        ttl_hours: 48,
                    },
                    expect: Yields(Leaf {
                        subject_alt_name_critical: true,
                        ..leaf(CommonName::None, &["localhost"])
                    }),
                },
                Case {
                    scenario: "a negative TTL issues a leaf that expires before it starts",
                    input: Issue {
                        ca: p256,
                        dns_names: &["svc.local"],
                        ttl_hours: -1,
                    },
                    expect: Yields(Leaf {
                        validity_seconds: -3600,
                        ..leaf(
                            CommonName::Printable("svc.local".to_owned()),
                            &["svc.local"],
                        )
                    }),
                },
                Case {
                    scenario: "a TTL of more than 292 years keeps its exact end date",
                    input: Issue {
                        ca: p256,
                        dns_names: &["svc.local"],
                        ttl_hours: 2_562_048,
                    },
                    expect: Yields(Leaf {
                        validity_seconds: 2_562_048 * 3600,
                        ..leaf(
                            CommonName::Printable("svc.local".to_owned()),
                            &["svc.local"],
                        )
                    }),
                },
                Case {
                    scenario: "a TTL whose seconds overflow 64 bits",
                    input: Issue {
                        ca: p256,
                        dns_names: &["svc.local"],
                        ttl_hours: i64::MAX,
                    },
                    expect: out_of_range(i64::MAX),
                },
                Case {
                    scenario: "an end date after year 9999",
                    input: Issue {
                        ca: p256,
                        dns_names: &["svc.local"],
                        ttl_hours: 100_000_000,
                    },
                    expect: out_of_range(100_000_000),
                },
                Case {
                    scenario: "an end date before year 0",
                    input: Issue {
                        ca: p256,
                        dns_names: &["svc.local"],
                        ttl_hours: -20_000_000,
                    },
                    expect: out_of_range(-20_000_000),
                },
                Case {
                    scenario: "no names",
                    input: Issue {
                        ca: p256,
                        dns_names: &[],
                        ttl_hours: 48,
                    },
                    expect: FailsWith(
                        "at least one non-empty DNS name is required to issue a certificate"
                            .to_owned(),
                    ),
                },
                Case {
                    scenario: "only empty names",
                    input: Issue {
                        ca: p256,
                        dns_names: &["", ""],
                        ttl_hours: 48,
                    },
                    expect: FailsWith(
                        "at least one non-empty DNS name is required to issue a certificate"
                            .to_owned(),
                    ),
                },
                Case {
                    scenario: "a non-ASCII name",
                    input: Issue {
                        ca: p256,
                        dns_names: &["\u{e9}.local"],
                        ttl_hours: 48,
                    },
                    expect: Fails,
                },
            ],
            |input| {
                let issued = input
                    .ca
                    .load()
                    .issue_certificate(&names(input.dns_names), input.ttl_hours)
                    .map_err(failure)?;
                Leaf::read(input.ca, &issued)
            },
        );
    }

    #[test]
    fn first_pem_block() {
        value_scenarios!(run = |input: &str| super::first_pem_block(input.as_bytes()).map(|block| (block.tag().to_owned(), block.into_contents()));
            "the first well-formed block, whatever its label" {
                "-----BEGIN A-----\nAQI=\n-----END A-----\n" => Some(("A".to_owned(), vec![1, 2])),
                "-----BEGIN A-----\r\nAQI=\r\n-----END A-----\r\n" => Some(("A".to_owned(), vec![1, 2])),
            }
            "leading text and malformed blocks are skipped" {
                "leading text\n-----BEGIN A-----\nAQI=\n-----END A-----\n" => Some(("A".to_owned(), vec![1, 2])),
                "-----BEGIN A-----\n!!\n-----END A-----\n-----BEGIN B-----\nAw==\n-----END B-----\n" => Some(("B".to_owned(), vec![3])),
            }
            "no well-formed block" {
                "-----BEGIN A-----\nAQI=\n-----END B-----\n" => None,
                "no block" => None,
            }
        );
    }
}
