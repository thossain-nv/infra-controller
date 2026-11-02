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

//! Test helpers that start a listener on a loopback port and connect clients
//! to it.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::Path;
use axum::routing::get;
use axum_server::tls_rustls::RustlsConfig;
use rustls::crypto::aws_lc_rs;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

use super::connection::ConnectionTimeouts;
use super::listener;
use crate::pki::test_support::TestCaPem;

/// A running listener, plus what a client needs to connect to it.
pub(super) struct Running {
    pub(super) address: SocketAddr,
    ca_certificate: CertificateDer<'static>,
    pub(super) cancel: CancellationToken,
    pub(super) serving: JoinHandle<io::Result<()>>,
    /// Notified when a `/sleep` handler starts.
    pub(super) handler_started: Arc<Notify>,
}

/// Size of the `GET /large` response. It's larger than the socket buffers of
/// a loopback connection, so a client that doesn't read the response blocks
/// the server's writes.
const LARGE_RESPONSE_BYTES: usize = 32 << 20;

/// Starts a listener on a loopback port, over TLS when `tls` is set.
/// `GET /` and `POST /` return `ok`. `GET /large` returns
/// [`LARGE_RESPONSE_BYTES`] bytes. `GET /sleep/{milliseconds}` returns `done`
/// after sleeping for that long.
pub(super) async fn start(tls: bool, timeouts: ConnectionTimeouts) -> Running {
    let ca = TestCaPem::p256();
    let serving_certificate = ca
        .load()
        .issue_certificate(&["localhost".to_owned()], 1)
        .unwrap();
    let tls_config = tls.then(|| {
        RustlsConfig::from_config(Arc::new(
            super::tls::server_config(&serving_certificate).unwrap(),
        ))
    });
    let handler_started = Arc::new(Notify::new());
    let notify = Arc::clone(&handler_started);
    let router = Router::new()
        .route("/", get(|| async { "ok\n" }).post(|| async { "ok\n" }))
        .route("/large", get(|| async { vec![b'x'; LARGE_RESPONSE_BYTES] }))
        .route(
            "/sleep/{milliseconds}",
            get(|Path(milliseconds): Path<u64>| async move {
                notify.notify_one();
                tokio::time::sleep(Duration::from_millis(milliseconds)).await;
                "done\n"
            }),
        );
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tcp_listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let serving = tokio::spawn(listener::serve(
        tcp_listener,
        tls_config,
        router,
        timeouts,
        cancel.clone(),
    ));
    Running {
        address,
        ca_certificate: CertificateDer::from_pem_slice(ca.certificate.as_bytes()).unwrap(),
        cancel,
        serving,
        handler_started,
    }
}

/// Completes a TLS handshake with `running` that offers `alpn`. Returns
/// `None` when the connection or the handshake fails.
pub(super) async fn tls_connect(running: &Running, alpn: &[&[u8]]) -> Option<TlsStream<TcpStream>> {
    let mut roots = RootCertStore::empty();
    roots.add(running.ca_certificate.clone()).ok()?;
    let mut config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .ok()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    let tcp = TcpStream::connect(running.address).await.ok()?;
    TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").ok()?, tcp)
        .await
        .ok()
}

/// Sends an HTTP/1.1 `request` and reads its response with [`read_response`].
pub(super) async fn exchange(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    request: &str,
) -> Option<String> {
    stream.write_all(request.as_bytes()).await.ok()?;
    read_response(stream).await
}

/// Reads one whole HTTP/1.1 response and returns its status line. The body
/// length comes from `Content-Length`. Returns `None` when the connection ends
/// before the whole response arrives.
pub(super) async fn read_response(stream: &mut (impl AsyncRead + Unpin)) -> Option<String> {
    let mut received = Vec::new();
    let head_end = loop {
        if let Some(end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
        let mut chunk = [0; 1024];
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        received.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&received[..head_end]).into_owned();
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut body = vec![0; (head_end + 4 + content_length).saturating_sub(received.len())];
    stream.read_exact(&mut body).await.ok()?;
    head.lines().next().map(str::to_owned)
}
