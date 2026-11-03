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

//! Parses the command line (flags, environment variables and defaults) and
//! derives the values the server uses.
//!
//! Each setting is read once at startup. A flag overrides its environment
//! variable, which overrides the default. A variable that's set but empty
//! gives an empty value, not the default.

use std::convert::Infallible;
use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use clap::{ArgAction, Parser};

use crate::pki::CaFiles;

/// Name shown by `--help` and `--version`.
pub(crate) const APP_NAME: &str = "NICo REST Cert Manager";

/// Value of `--dns-name` when the flag isn't passed. `credsmgr.csm` is the
/// service's legacy in-cluster name. Deployments pass their own list, but the
/// default is kept for any deployment that relied on it.
const DEFAULT_DNS_NAMES: &str = "credsmgr.csm,localhost";

/// Environment variable that overrides the request metric name prefix. There's
/// no matching flag.
const METRICS_NAMESPACE_ENV: &str = "METRICS_NAMESPACE";

/// Request metric name prefix used when `METRICS_NAMESPACE` is unset or empty.
const DEFAULT_METRICS_NAMESPACE: &str = "nico_rest_cert_manager";

/// Command-line options. Long flags accept both `--flag value` and
/// `--flag=value`.
#[derive(Parser)]
#[command(
    name = "nico-rest-cert-manager",
    about = APP_NAME,
    disable_version_flag = true,
    // A repeated single-value flag uses its last value instead of failing, so
    // a later deployment argument overrides an earlier one.
    args_override_self = true
)]
pub(crate) struct Options {
    #[arg(
        long,
        action = ArgAction::Set,
        num_args = 0..=1,
        require_equals = true,
        default_value = "false",
        default_missing_value = "true",
        value_parser = parse_bool,
        help = "Log this service's debug messages"
    )]
    pub(crate) debug: bool,

    #[arg(long, default_value_t = 8000, help = "TLS port to listen on")]
    tls_port: u16,

    #[arg(long, default_value_t = 8001, help = "Plain HTTP port to listen on")]
    insecure_port: u16,

    #[arg(
        long = "dns-name",
        value_name = "DNS_NAME",
        value_delimiter = ',',
        value_parser = parse_dns_name,
        default_value = DEFAULT_DNS_NAMES,
        help = "DNS name for in-cluster TLS access. Repeat or comma-separate to cover every \
                hostname clients dial; the first value supplied replaces the default rather \
                than adding to it"
    )]
    pub(crate) dns_names: Vec<String>,

    #[arg(
        long,
        default_value = "temporal.local",
        help = "Base DNS name appended to requested certificate names"
    )]
    pub(crate) ca_base_dns: String,

    #[arg(
        long,
        env = "SENTRY_DSN",
        default_value = "",
        hide_env_values = true,
        help = "Deprecated and ignored: Sentry reporting was removed"
    )]
    pub(crate) sentry_dsn: String,

    // Deployments still pass these two flags, so they're accepted but have no
    // effect. The CA is loaded from files and its name comes from its
    // certificate.
    #[arg(
        long = "ca-common-name",
        value_name = "CA_COMMON_NAME",
        env = "CA_COMMON_NAME",
        default_value = "NICo Local CA",
        help = "Accepted for compatibility; has no effect"
    )]
    _ca_common_name: String,

    #[arg(
        long = "ca-organization",
        value_name = "CA_ORGANIZATION",
        env = "CA_ORGANIZATION",
        default_value = "NVIDIA",
        help = "Accepted for compatibility; has no effect"
    )]
    _ca_organization: String,

    #[arg(
        long,
        env = "CA_CERT_FILE",
        value_parser = parse_path,
        default_value = "/vault/secrets/vault-root-ca-certificate/certificate",
        help = "Path to CA certificate file; this pair is tried first, if both paths are set"
    )]
    ca_cert_file: PathBuf,

    #[arg(
        long,
        env = "CA_KEY_FILE",
        value_parser = parse_path,
        default_value = "/vault/secrets/vault-root-ca-private-key/privatekey",
        help = "Path to CA private key file"
    )]
    ca_key_file: PathBuf,

    #[arg(
        long,
        env = "ALT_CA_CERT_FILE",
        value_parser = parse_path,
        default_value = "/etc/pki/ca/tls.crt",
        help = "Alternate path to CA certificate file; this pair is tried next, if both paths \
                are set"
    )]
    alt_ca_cert_file: PathBuf,

    #[arg(
        long,
        env = "ALT_CA_KEY_FILE",
        value_parser = parse_path,
        default_value = "/etc/pki/ca/tls.key",
        help = "Alternate path to CA private key file"
    )]
    alt_ca_key_file: PathBuf,

    #[arg(short = 'v', long, help = "Print the version")]
    pub(crate) version: bool,

    /// Prefix of the request metric names. It's `METRICS_NAMESPACE` when that's
    /// set and non-empty, otherwise `nico_rest_cert_manager`.
    #[arg(skip = metrics_namespace(std::env::var(METRICS_NAMESPACE_ENV).ok()))]
    pub(crate) metrics_namespace: String,
}

impl Options {
    /// Returns the TLS listener's address. It covers every interface, IPv4 and
    /// IPv6 where the host supports both.
    pub(crate) fn tls_listen_address(&self) -> SocketAddr {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, self.tls_port))
    }

    /// Returns the plain HTTP listener's address. It covers the same
    /// interfaces as the TLS one.
    pub(crate) fn insecure_listen_address(&self) -> SocketAddr {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, self.insecure_port))
    }

    /// Returns the CA certificate and key paths tried first.
    pub(crate) fn primary_ca_files(&self) -> CaFiles {
        CaFiles {
            certificate: self.ca_cert_file.clone(),
            key: self.ca_key_file.clone(),
        }
    }

    /// Returns the CA certificate and key paths tried when the primary pair is
    /// unset or fails.
    pub(crate) fn alternate_ca_files(&self) -> CaFiles {
        CaFiles {
            certificate: self.alt_ca_cert_file.clone(),
            key: self.alt_ca_key_file.clone(),
        }
    }
}

/// Returns the release version stamped into the build, or `dev` for an
/// unstamped build.
pub(crate) fn version() -> &'static str {
    match carbide_version::v!(build_version) {
        "" => "dev",
        version => version,
    }
}

/// Parses `--debug=<value>`. `1`, `t`, `T`, `TRUE`, `true` and `True` mean
/// true. `0`, `f`, `F`, `FALSE`, `false` and `False` mean false.
fn parse_bool(value: &str) -> Result<bool, String> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(format!("invalid boolean value {value:?}")),
    }
}

/// Trims each comma-separated `--dns-name` item. Empty items are kept, but
/// certificate issuance drops them.
fn parse_dns_name(value: &str) -> Result<String, Infallible> {
    Ok(value.trim().to_owned())
}

/// Accepts an empty path, which leaves its CA pair unset. clap's own path
/// parser rejects an empty path.
fn parse_path(value: &str) -> Result<PathBuf, Infallible> {
    Ok(PathBuf::from(value))
}

/// Resolves the metric name prefix from the `METRICS_NAMESPACE` value, if any.
fn metrics_namespace(configured: Option<String>) -> String {
    configured
        .filter(|namespace| !namespace.is_empty())
        .unwrap_or_else(|| DEFAULT_METRICS_NAMESPACE.to_owned())
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases, scenarios, value_scenarios};
    use clap::CommandFactory;
    use clap::error::ErrorKind;
    use serial_test::serial;

    use super::*;

    /// Every environment variable the options read. Each case sets or clears
    /// all of them, so the caller's environment can't affect a case.
    const OPTION_ENV_VARS: [&str; 8] = [
        "SENTRY_DSN",
        "CA_COMMON_NAME",
        "CA_ORGANIZATION",
        "CA_CERT_FILE",
        "CA_KEY_FILE",
        "ALT_CA_CERT_FILE",
        "ALT_CA_KEY_FILE",
        METRICS_NAMESPACE_ENV,
    ];

    struct Invocation {
        args: &'static [&'static str],
        env: &'static [(&'static str, &'static str)],
    }

    /// The parsed values a deployment can observe.
    #[derive(Debug, PartialEq)]
    struct Parsed {
        debug: bool,
        version: bool,
        tls_listen_address: SocketAddr,
        insecure_listen_address: SocketAddr,
        dns_names: Vec<String>,
        ca_base_dns: String,
        sentry_dsn: String,
        primary_ca_files: [PathBuf; 2],
        alternate_ca_files: [PathBuf; 2],
        metrics_namespace: String,
    }

    impl Parsed {
        fn defaults() -> Self {
            Self {
                debug: false,
                version: false,
                tls_listen_address: "[::]:8000".parse().unwrap(),
                insecure_listen_address: "[::]:8001".parse().unwrap(),
                dns_names: names(&["credsmgr.csm", "localhost"]),
                ca_base_dns: "temporal.local".to_owned(),
                sentry_dsn: String::new(),
                primary_ca_files: [
                    "/vault/secrets/vault-root-ca-certificate/certificate".into(),
                    "/vault/secrets/vault-root-ca-private-key/privatekey".into(),
                ],
                alternate_ca_files: ["/etc/pki/ca/tls.crt".into(), "/etc/pki/ca/tls.key".into()],
                metrics_namespace: "nico_rest_cert_manager".to_owned(),
            }
        }
    }

    impl From<Options> for Parsed {
        fn from(options: Options) -> Self {
            let primary = options.primary_ca_files();
            let alternate = options.alternate_ca_files();
            Self {
                debug: options.debug,
                version: options.version,
                tls_listen_address: options.tls_listen_address(),
                insecure_listen_address: options.insecure_listen_address(),
                dns_names: options.dns_names,
                ca_base_dns: options.ca_base_dns,
                sentry_dsn: options.sentry_dsn,
                primary_ca_files: [primary.certificate, primary.key],
                alternate_ca_files: [alternate.certificate, alternate.key],
                metrics_namespace: options.metrics_namespace,
            }
        }
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    /// Sets `name` to `value`, or removes the variable when `value` is `None`.
    fn set_option_env(name: &str, value: Option<&str>) {
        // SAFETY: Only `#[serial]` tests call this. Every other test in this
        // crate that parses `Options` reads these variables, so those tests are
        // `#[serial]` too (`help_marks_ignored_options`, `server::tests::run`).
        // std serializes its own environment access. However, this doesn't
        // prove Unix process-wide exclusion from environment readers on other
        // test threads, such as a C library calling `getenv`.
        unsafe {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }

    fn parse(invocation: Invocation) -> Result<Parsed, ErrorKind> {
        for name in OPTION_ENV_VARS {
            let value = invocation
                .env
                .iter()
                .find(|(set_name, _)| *set_name == name)
                .map(|(_, value)| *value);
            set_option_env(name, value);
        }
        let argv = std::iter::once("nico-rest-cert-manager").chain(invocation.args.iter().copied());
        Options::try_parse_from(argv)
            .map(Parsed::from)
            .map_err(|error| error.kind())
    }

    #[test]
    #[serial]
    fn options() {
        check_cases(
            [
                Case {
                    scenario: "no arguments yields the defaults",
                    input: Invocation {
                        args: &[],
                        env: &[],
                    },
                    expect: Yields(Parsed::defaults()),
                },
                Case {
                    scenario: "both flag syntaxes set ports and the base DNS name",
                    input: Invocation {
                        args: &[
                            "--tls-port=9000",
                            "--insecure-port",
                            "9001",
                            "--ca-base-dns=nico.local",
                        ],
                        env: &[],
                    },
                    expect: Yields(Parsed {
                        tls_listen_address: "[::]:9000".parse().unwrap(),
                        insecure_listen_address: "[::]:9001".parse().unwrap(),
                        ca_base_dns: "nico.local".to_owned(),
                        ..Parsed::defaults()
                    }),
                },
                Case {
                    scenario: "a repeated single-value flag takes its last value",
                    input: Invocation {
                        args: &["--tls-port=1", "--tls-port", "2"],
                        env: &[],
                    },
                    expect: Yields(Parsed {
                        tls_listen_address: "[::]:2".parse().unwrap(),
                        ..Parsed::defaults()
                    }),
                },
                Case {
                    scenario: "one --dns-name replaces the default list",
                    input: Invocation {
                        args: &["--dns-name=a"],
                        env: &[],
                    },
                    expect: Yields(Parsed {
                        dns_names: names(&["a"]),
                        ..Parsed::defaults()
                    }),
                },
                Case {
                    scenario: "comma-separated --dns-name items are trimmed",
                    input: Invocation {
                        args: &["--dns-name", "a, b ,c"],
                        env: &[],
                    },
                    expect: Yields(Parsed {
                        dns_names: names(&["a", "b", "c"]),
                        ..Parsed::defaults()
                    }),
                },
                Case {
                    scenario: "repeated --dns-name flags append in order",
                    input: Invocation {
                        args: &["--dns-name", "a", "--dns-name=b,c"],
                        env: &[],
                    },
                    expect: Yields(Parsed {
                        dns_names: names(&["a", "b", "c"]),
                        ..Parsed::defaults()
                    }),
                },
                Case {
                    scenario: "empty --dns-name items are kept for issuance to drop",
                    input: Invocation {
                        args: &["--dns-name=a,,b"],
                        env: &[],
                    },
                    expect: Yields(Parsed {
                        dns_names: names(&["a", "", "b"]),
                        ..Parsed::defaults()
                    }),
                },
                Case {
                    scenario: "an empty --dns-name is one empty name",
                    input: Invocation {
                        args: &["--dns-name="],
                        env: &[],
                    },
                    expect: Yields(Parsed {
                        dns_names: names(&[""]),
                        ..Parsed::defaults()
                    }),
                },
                Case {
                    scenario: "bare --debug enables debug logging",
                    input: Invocation {
                        args: &["--debug"],
                        env: &[],
                    },
                    expect: Yields(Parsed {
                        debug: true,
                        ..Parsed::defaults()
                    }),
                },
                Case {
                    scenario: "--debug=false disables debug logging",
                    input: Invocation {
                        args: &["--debug=false"],
                        env: &[],
                    },
                    expect: Yields(Parsed::defaults()),
                },
                Case {
                    scenario: "--debug takes no separate value argument",
                    input: Invocation {
                        args: &["--debug", "false"],
                        env: &[],
                    },
                    expect: FailsWith(ErrorKind::UnknownArgument),
                },
                Case {
                    scenario: "--debug rejects other words",
                    input: Invocation {
                        args: &["--debug=yes"],
                        env: &[],
                    },
                    expect: FailsWith(ErrorKind::ValueValidation),
                },
                Case {
                    scenario: "-v asks for the version",
                    input: Invocation {
                        args: &["-v"],
                        env: &[],
                    },
                    expect: Yields(Parsed {
                        version: true,
                        ..Parsed::defaults()
                    }),
                },
                Case {
                    scenario: "environment variables replace the defaults",
                    input: Invocation {
                        args: &[],
                        env: &[
                            ("CA_CERT_FILE", "/env/ca.crt"),
                            ("CA_KEY_FILE", "/env/ca.key"),
                            ("ALT_CA_CERT_FILE", "/env/alt.crt"),
                            ("ALT_CA_KEY_FILE", "/env/alt.key"),
                            ("SENTRY_DSN", "https://key@sentry.example/1"),
                        ],
                    },
                    expect: Yields(Parsed {
                        primary_ca_files: ["/env/ca.crt".into(), "/env/ca.key".into()],
                        alternate_ca_files: ["/env/alt.crt".into(), "/env/alt.key".into()],
                        sentry_dsn: "https://key@sentry.example/1".to_owned(),
                        ..Parsed::defaults()
                    }),
                },
                Case {
                    scenario: "a flag wins over its environment variable",
                    input: Invocation {
                        args: &["--ca-cert-file=/flag/ca.crt"],
                        env: &[("CA_CERT_FILE", "/env/ca.crt")],
                    },
                    expect: Yields(Parsed {
                        primary_ca_files: [
                            "/flag/ca.crt".into(),
                            "/vault/secrets/vault-root-ca-private-key/privatekey".into(),
                        ],
                        ..Parsed::defaults()
                    }),
                },
                Case {
                    scenario: "a set but empty environment variable yields an empty path",
                    input: Invocation {
                        args: &[],
                        env: &[("CA_CERT_FILE", "")],
                    },
                    expect: Yields(Parsed {
                        primary_ca_files: [
                            "".into(),
                            "/vault/secrets/vault-root-ca-private-key/privatekey".into(),
                        ],
                        ..Parsed::defaults()
                    }),
                },
                Case {
                    scenario: "the CA naming options parse and have no effect",
                    input: Invocation {
                        args: &[
                            "--ca-common-name=NICo Local Dev CA",
                            "--ca-organization=Example",
                        ],
                        env: &[],
                    },
                    expect: Yields(Parsed::defaults()),
                },
                Case {
                    scenario: "METRICS_NAMESPACE replaces the metric name prefix",
                    input: Invocation {
                        args: &[],
                        env: &[("METRICS_NAMESPACE", "acme_cm")],
                    },
                    expect: Yields(Parsed {
                        metrics_namespace: "acme_cm".to_owned(),
                        ..Parsed::defaults()
                    }),
                },
                Case {
                    scenario: "an empty METRICS_NAMESPACE keeps the default prefix",
                    input: Invocation {
                        args: &[],
                        env: &[("METRICS_NAMESPACE", "")],
                    },
                    expect: Yields(Parsed::defaults()),
                },
            ],
            parse,
        );
        for name in OPTION_ENV_VARS {
            set_option_env(name, None);
        }
    }

    // Rendering the help reads every option's environment variable, which
    // `options` sets and removes. So this test is `#[serial]` too.
    #[test]
    #[serial]
    fn help_marks_ignored_options() {
        let help = Options::command().render_help().to_string();
        value_scenarios!(run = |text: &str| help.contains(text);
            "environment variables of the CA naming options" {
                "[env: CA_COMMON_NAME=" => true,
                "[env: CA_ORGANIZATION=" => true,
            }
            "deprecation and no-op notes" {
                "Deprecated and ignored" => true,
                "has no effect" => true,
            }
        );
    }

    #[test]
    fn parse_bool() {
        scenarios!(super::parse_bool:
            "Go's spellings are accepted" {
                "t" => Yields(true),
                "False" => Yields(false),
            }
            "other spellings are rejected" {
                "yes" => Fails,
                "tRUE" => Fails,
            }
        );
    }
}
