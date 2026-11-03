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

//! Serves both listeners and drains their connections at shutdown.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use axum::Router;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use tokio::net::TcpListener;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::connection::ConnectionTimeouts;

/// How long open connections have to finish their requests once shutdown
/// starts. Connections still open after that are closed. Together with the
/// `1s` span flush in `main`, this fits in the pod's `5s` termination grace
/// period.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(3);

/// Serves `router` on `listener` until `cancel` is cancelled. It uses TLS with
/// `tls_config` when that's set, otherwise plain HTTP/1. Every connection uses
/// `timeouts`. On cancel, the listening socket is closed so new connections
/// are refused. Open connections get [`DRAIN_TIMEOUT`] to finish, then the
/// rest are closed. Handlers can read each request's peer address as
/// `ConnectInfo<SocketAddr>`.
pub(super) async fn serve(
    listener: TcpListener,
    tls_config: Option<RustlsConfig>,
    router: Router,
    timeouts: ConnectionTimeouts,
    cancel: CancellationToken,
) -> io::Result<()> {
    let handle = Handle::<SocketAddr>::new();
    let server = axum_server::Server::from_listener(listener).handle(handle.clone());
    let service = router.into_make_service_with_connect_info::<SocketAddr>();
    let mut serving: Pin<Box<dyn Future<Output = io::Result<()>> + Send>> = match tls_config {
        None => {
            let mut server = server.acceptor(timeouts.acceptor()).http1_only();
            timeouts.configure_http(server.http_builder());
            Box::pin(server.serve(service))
        }
        Some(tls_config) => {
            let mut server = server.acceptor(timeouts.tls_acceptor(tls_config));
            timeouts.configure_http(server.http_builder());
            Box::pin(server.serve(service))
        }
    };

    if let Some(served) = cancel.run_until_cancelled(&mut serving).await {
        return served;
    }
    // Idle connections close right away while requests in flight finish. The
    // server closes anything still open after the drain timeout.
    let draining = Instant::now();
    handle.graceful_shutdown(Some(DRAIN_TIMEOUT));
    let served = serving.await;
    if draining.elapsed() >= DRAIN_TIMEOUT {
        tracing::warn!(
            drain_timeout_seconds = DRAIN_TIMEOUT.as_secs(),
            "closed connections still open after the drain timeout"
        );
    }
    served
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases_async};
    use tokio::net::TcpStream;
    use tokio::time;

    use super::*;
    use crate::server::test_support;

    /// What a client sees when shutdown starts during its request.
    #[derive(Debug, PartialEq)]
    struct Drain {
        /// The status line of the response, if it arrives.
        response: Option<String>,
        /// Whether a new connection is refused during the drain.
        new_connection_refused: bool,
        /// Whole seconds from cancellation until `serve` returns.
        stopped_after_seconds: u64,
    }

    /// After cancellation, new connections are refused right away. A request
    /// in progress still gets its response if it finishes within the drain
    /// timeout, otherwise its connection is closed. Either way, `serve`
    /// returns.
    #[tokio::test]
    async fn serve_drains_on_cancel() {
        check_cases_async(
            [
                Case {
                    scenario: "a request that finishes within the drain timeout is answered",
                    input: 1000,
                    expect: Yields(Drain {
                        response: Some("HTTP/1.1 200 OK".to_owned()),
                        new_connection_refused: true,
                        stopped_after_seconds: 1,
                    }),
                },
                Case {
                    scenario: "a request still running at the drain timeout is cut off",
                    input: 10_000,
                    expect: Yields(Drain {
                        response: None,
                        new_connection_refused: true,
                        stopped_after_seconds: DRAIN_TIMEOUT.as_secs(),
                    }),
                },
            ],
            |handler_milliseconds: u64| async move {
                let running = test_support::start(false, ConnectionTimeouts::DEFAULT).await;
                let mut stream = TcpStream::connect(running.address).await.map_err(drop)?;
                let request = format!(
                    "GET /sleep/{handler_milliseconds} HTTP/1.1\r\nHost: localhost\r\n\r\n"
                );
                let response =
                    tokio::spawn(
                        async move { test_support::exchange(&mut stream, &request).await },
                    );
                running.handler_started.notified().await;
                let cancelled = Instant::now();
                running.cancel.cancel();
                // Gives the server time to see the cancellation before the
                // test connects again.
                time::sleep(Duration::from_millis(100)).await;
                let connected = TcpStream::connect(running.address).await;
                let new_connection_refused =
                    connected.is_err_and(|error| error.kind() == io::ErrorKind::ConnectionRefused);
                running.serving.await.map_err(drop)?.map_err(drop)?;
                Ok::<_, ()>(Drain {
                    response: response.await.map_err(drop)?,
                    new_connection_refused,
                    stopped_after_seconds: cancelled.elapsed().as_secs(),
                })
            },
        )
        .await;
    }
}
