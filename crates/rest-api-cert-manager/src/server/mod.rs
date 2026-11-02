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

//! Runs the service from startup to shutdown. It loads the CA, issues the
//! serving certificate and binds both listeners. Then it serves until
//! cancelled and drains the connections.
//!
//! Listeners are TCP only. Each one binds its port on every interface, IPv4
//! and IPv6 where the host allows both.

mod connection;
mod listener;
#[cfg(test)]
mod test_support;
mod tls;

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use tokio::net::TcpListener;
use tokio::task::{JoinError, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::api::{self, AppState, MetricsError, RequestMetrics};
use crate::config::{self, Options};
use crate::pki::{CertificateAuthority, IssueError, LoadError};
use crate::server::connection::ConnectionTimeouts;
use crate::server::tls::TlsConfigError;

/// Validity in hours of the serving certificate issued at each start, which
/// is ten years.
const SERVING_CERTIFICATE_TTL_HOURS: i64 = 10 * 365 * 24;

/// The two listeners. Logs and bind errors name them by their `Display` value.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Listener {
    Tls,
    Plain,
}

impl fmt::Display for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tls => "TLS",
            Self::Plain => "plain HTTP",
        })
    }
}

/// Reasons the service couldn't start or stopped abnormally.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ServerError {
    #[error(transparent)]
    Metrics(#[from] MetricsError),
    #[error(transparent)]
    LoadCa(#[from] LoadError),
    #[error("failed to issue the serving certificate: {0}")]
    ServingCertificate(IssueError),
    #[error(transparent)]
    TlsConfig(#[from] TlsConfigError),
    #[error("failed to bind the {listener} listener on {listen_address}: {error}")]
    Bind {
        listener: Listener,
        listen_address: SocketAddr,
        error: std::io::Error,
    },
    #[error("startup task failed: {0}")]
    StartupTask(JoinError),
    #[error("the {listener} listener failed: {error}")]
    Serve {
        listener: Listener,
        error: std::io::Error,
    },
    #[error("listener task failed: {0}")]
    ListenerTask(JoinError),
}

/// Serves until `cancel` is cancelled and both listeners have drained. It
/// fails before serving if the CA can't be loaded, the serving certificate
/// can't be issued, the metric prefix is invalid or a port can't be bound.
pub(crate) async fn run(options: &Options, cancel: CancellationToken) -> Result<(), ServerError> {
    let request_metrics = RequestMetrics::new(&options.metrics_namespace)?;

    let primary = options.primary_ca_files();
    let alternate = options.alternate_ca_files();
    let dns_names = options.dns_names.clone();
    // Reading the CA files and generating the serving key are blocking calls.
    let identity = tokio::task::spawn_blocking(move || {
        let certificate_authority = CertificateAuthority::load(&primary, &alternate)?;
        let serving_certificate = certificate_authority
            .issue_certificate(&dns_names, SERVING_CERTIFICATE_TTL_HOURS)
            .map_err(ServerError::ServingCertificate)?;
        Ok::<_, ServerError>((certificate_authority, serving_certificate))
    })
    .await;
    let (certificate_authority, serving_certificate) =
        identity.map_err(ServerError::StartupTask)??;
    let tls_config = RustlsConfig::from_config(Arc::new(tls::server_config(&serving_certificate)?));

    let state = AppState {
        certificate_authority: Arc::new(certificate_authority),
        base_dns: Arc::from(options.ca_base_dns.as_str()),
        request_metrics,
        version: config::version(),
    };

    // Both listeners bind before either one serves, so a port conflict fails
    // startup instead of leaving half of the service running.
    let tls_listener = bind(Listener::Tls, options.tls_listen_address()).await?;
    let insecure_listener = bind(Listener::Plain, options.insecure_listen_address()).await?;

    let mut listeners = JoinSet::new();
    let served = [
        (
            Listener::Tls,
            tls_listener,
            Some(tls_config),
            api::tls_router(state.clone()),
        ),
        (
            Listener::Plain,
            insecure_listener,
            None,
            api::insecure_router(state),
        ),
    ];
    for (kind, tcp_listener, tls_config, router) in served {
        let cancel = cancel.clone();
        listeners.spawn(async move {
            listener::serve(
                tcp_listener,
                tls_config,
                router,
                ConnectionTimeouts::DEFAULT,
                cancel,
            )
            .await
            .map_err(|error| ServerError::Serve {
                listener: kind,
                error,
            })
        });
    }

    // A listener returns after `cancel` is cancelled and its connections
    // drain. Only a failure ends a listener sooner. In that case the other
    // listener is stopped too.
    let mut failure = None;
    while let Some(joined) = listeners.join_next().await {
        let served = match joined {
            Ok(served) => served,
            Err(error) => Err(ServerError::ListenerTask(error)),
        };
        if let Err(error) = served {
            cancel.cancel();
            failure.get_or_insert(error);
        }
    }
    failure.map_or(Ok(()), Err)
}

async fn bind(listener: Listener, listen_address: SocketAddr) -> Result<TcpListener, ServerError> {
    let bound = metrics_endpoint::bind_tcp_listener(listen_address).await;
    let tcp_listener = bound.map_err(|error| ServerError::Bind {
        listener,
        listen_address,
        error,
    })?;
    tracing::info!(%listener, %listen_address, "listening");
    Ok(tcp_listener)
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases_async};
    use clap::Parser;
    use serial_test::serial;

    use super::*;
    use crate::pki::test_support::TestCaPem;

    struct Startup {
        args: Vec<String>,
        metrics_namespace: &'static str,
    }

    // Parsing `Options` reads this crate's environment variables, which the
    // `#[serial]` tests in `config` set and remove. `#[serial]` keeps those
    // writes from overlapping this parse. However, it doesn't prove Unix
    // process-wide exclusion from environment readers on other test threads.
    #[tokio::test]
    #[serial]
    async fn run() {
        let directory = tempfile::tempdir().unwrap();
        let ca = TestCaPem::p256();
        let certificate = directory.path().join("ca.crt");
        let key = directory.path().join("ca.key");
        std::fs::write(&certificate, &ca.certificate).unwrap();
        std::fs::write(&key, &ca.key).unwrap();
        let occupied = std::net::TcpListener::bind("[::]:0")
            .or_else(|_| std::net::TcpListener::bind("0.0.0.0:0"))
            .unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();

        // Every row sets both CA pairs with flags, so no environment variable
        // is used.
        let args = |extra: &[&str]| -> Vec<String> {
            [
                format!("--ca-cert-file={}", certificate.display()),
                format!("--ca-key-file={}", key.display()),
                "--alt-ca-cert-file=".to_owned(),
                "--alt-ca-key-file=".to_owned(),
                "--tls-port=0".to_owned(),
                "--insecure-port=0".to_owned(),
            ]
            .into_iter()
            .chain(extra.iter().map(|arg| (*arg).to_owned()))
            .collect()
        };
        check_cases_async(
            [
                Case {
                    scenario: "a loadable CA starts both listeners, which stop on cancel",
                    input: Startup { args: args(&[]), metrics_namespace: "nico_rest_cert_manager" },
                    expect: Yields(()),
                },
                Case {
                    scenario: "no usable CA",
                    input: Startup {
                        args: args(&["--ca-key-file=", "--alt-ca-cert-file=/missing.crt", "--alt-ca-key-file=/missing.key"]),
                        metrics_namespace: "nico_rest_cert_manager",
                    },
                    expect: FailsWith(
                        "ca certificate required but not found: alternate path (/missing.crt): failed to read ca \
                         certificate file: No such file or directory (os error 2)"
                            .to_owned(),
                    ),
                },
                Case {
                    scenario: "no DNS name for the serving certificate",
                    input: Startup { args: args(&["--dns-name="]), metrics_namespace: "nico_rest_cert_manager" },
                    expect: FailsWith(
                        "failed to issue the serving certificate: at least one non-empty DNS name is required to \
                         issue a certificate"
                            .to_owned(),
                    ),
                },
                Case {
                    scenario: "a metric prefix that makes invalid names",
                    input: Startup { args: args(&[]), metrics_namespace: "acme-cm" },
                    expect: Fails,
                },
                Case {
                    scenario: "a port already in use",
                    input: Startup {
                        args: args(&[&format!("--insecure-port={occupied_port}")]),
                        metrics_namespace: "nico_rest_cert_manager",
                    },
                    expect: Fails,
                },
            ],
            |startup| async move {
                let argv = std::iter::once("nico-rest-cert-manager".to_owned()).chain(startup.args);
                let mut options = Options::try_parse_from(argv).map_err(|error| error.to_string())?;
                options.metrics_namespace = startup.metrics_namespace.to_owned();
                let cancel = CancellationToken::new();
                cancel.cancel();
                super::run(&options, cancel).await.map_err(|error| error.to_string())
            },
        )
        .await;
    }
}
