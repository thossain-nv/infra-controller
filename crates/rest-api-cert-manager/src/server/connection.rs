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

//! Every accepted connection receives the following: socket options, timeouts
//! expressing socket/task limits.

use std::future::{self, Ready};
use std::io;
use std::pin::Pin;
use std::time::Duration;

use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto;
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tokio_io_timeout::TimeoutStream;

/// TCP keepalive settings for every accepted socket. The first probe is sent
/// after `15s` without traffic, then one every `15s`. The operating system's
/// probe count sets how many unanswered probes it takes to drop the peer. The
/// probes keep NAT and firewall state alive while a keep-alive connection is
/// idle.
const TCP_KEEPALIVE: TcpKeepalive = TcpKeepalive::new()
    .with_time(Duration::from_secs(15))
    .with_interval(Duration::from_secs(15));

/// Timeouts for each step of a connection. A connection that times out is
/// closed without a response. The number of connections isn't limited, so
/// these timeouts limit how long each connection can use a socket and a task.
#[derive(Clone, Copy, Debug)]
pub(super) struct ConnectionTimeouts {
    /// How long the TLS listener waits after accept for the TLS handshake to
    /// complete.
    tls_handshake: Duration,
    /// How long an HTTP/1 connection waits for a complete request head. hyper
    /// starts this timer each time the connection waits for a request, so a
    /// keep-alive connection that's idle this long is closed too.
    request_head: Duration,
    /// How long one socket read may wait for data. This closes an idle HTTP/2
    /// connection. hyper doesn't start an HTTP/1 timer until the first bytes
    /// show which protocol the client uses. So this also closes a TLS
    /// connection whose client doesn't send anything after the handshake.
    read: Duration,
    /// How long one socket write may wait for the client to read data. A
    /// client that stops reading its response is disconnected once a write
    /// waits this long.
    write: Duration,
}

impl ConnectionTimeouts {
    /// The timeouts both listeners use. `request_head` doesn't cover the
    /// request body, but the `5s` handler timeout on the TLS routes does.
    pub(super) const DEFAULT: Self = Self {
        tls_handshake: Duration::from_secs(5),
        request_head: Duration::from_secs(5),
        read: Duration::from_secs(120),
        write: Duration::from_secs(10),
    };

    /// Returns the acceptor for the plain listener.
    pub(super) fn acceptor(self) -> ConnectionAcceptor {
        ConnectionAcceptor { timeouts: self }
    }

    /// Returns the acceptor for the TLS listener. It runs [`Self::acceptor`]
    /// first, then the TLS handshake.
    pub(super) fn tls_acceptor(
        self,
        tls_config: RustlsConfig,
    ) -> RustlsAcceptor<ConnectionAcceptor> {
        RustlsAcceptor::new(tls_config)
            .handshake_timeout(self.tls_handshake)
            .acceptor(self.acceptor())
    }

    /// Sets hyper's request head timeout on `builder`, plus the timer hyper
    /// uses to enforce the timeout.
    pub(super) fn configure_http(self, builder: &mut auto::Builder<TokioExecutor>) {
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(self.request_head);
    }
}

/// Acceptor that prepares each accepted TCP connection. It sets the socket
/// options and applies [`ConnectionTimeouts::read`] and
/// [`ConnectionTimeouts::write`] to the socket. When the listener uses TLS,
/// the handshake runs on top of this acceptor.
#[derive(Clone, Copy, Debug)]
pub(super) struct ConnectionAcceptor {
    timeouts: ConnectionTimeouts,
}

impl<S> Accept<TcpStream, S> for ConnectionAcceptor {
    type Stream = Pin<Box<TimeoutStream<TcpStream>>>;
    type Service = S;
    type Future = Ready<io::Result<(Self::Stream, S)>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        if let Err(error) = configure_socket(&stream) {
            tracing::debug!(error = %error, peer_address = ?stream.peer_addr().ok(), "failed to set socket options");
        }
        let mut stream = TimeoutStream::new(stream);
        stream.set_read_timeout(Some(self.timeouts.read));
        stream.set_write_timeout(Some(self.timeouts.write));
        future::ready(Ok((Box::pin(stream), service)))
    }
}

/// Turns off Nagle's algorithm so responses are sent without delay. It also
/// turns on [`TCP_KEEPALIVE`].
fn configure_socket(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    SockRef::from(stream).set_tcp_keepalive(&TCP_KEEPALIVE)
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases_async};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{self, Instant};

    use super::*;
    use crate::server::test_support::{self, Running};

    /// Resolution the tests use to tell timeouts apart. Each [`SHORT`] timeout
    /// is a different multiple of this step.
    const STEP: Duration = Duration::from_millis(300);

    /// Timeouts short enough for the tests to run in real time. They're far
    /// enough apart that the time a connection closes shows which timeout it
    /// hit.
    const SHORT: ConnectionTimeouts = ConnectionTimeouts {
        tls_handshake: Duration::from_millis(300),
        request_head: Duration::from_millis(600),
        write: Duration::from_millis(1200),
        read: Duration::from_millis(1800),
    };

    /// ALPN protocol names.
    const HTTP1: &[u8] = b"http/1.1";
    const H2: &[u8] = b"h2";

    const GET: &str = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";

    /// The HTTP/2 client preface followed by an empty SETTINGS frame.
    const HTTP2_START: &[u8] =
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";

    /// `GET /` as a HEADERS frame on stream 1, with `END_STREAM` and
    /// `END_HEADERS` set. The header block uses HPACK static table indexes for
    /// `:method GET`, `:scheme https` and `:path /`. It sends
    /// `:authority: localhost` as a literal.
    const HTTP2_GET: &[u8] = b"\x00\x00\x0e\x01\x05\x00\x00\x00\x01\x82\x87\x84\x41\x09localhost";

    /// The HTTP/2 HEADERS frame type.
    const HEADERS: u8 = 0x1;

    /// `configure_socket` turns off Nagle's algorithm. It also sets TCP
    /// keepalive to probe an idle peer every `15s`.
    #[tokio::test]
    async fn configure_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        super::configure_socket(&stream).unwrap();
        let socket = SockRef::from(&stream);
        assert_eq!(
            (
                stream.nodelay().unwrap(),
                socket.keepalive().unwrap(),
                socket.tcp_keepalive_time().unwrap(),
                socket.tcp_keepalive_interval().unwrap(),
            ),
            (true, true, Duration::from_secs(15), Duration::from_secs(15)),
        );
    }

    /// Sends `GET /` over HTTP/2 and returns the response status. Returns
    /// `None` when the connection ends before the response. It only
    /// recognizes `200` (HPACK static index `8`), since that's the only status
    /// `/` returns.
    async fn http2_status(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> Option<String> {
        stream.write_all(HTTP2_START).await.ok()?;
        stream.write_all(HTTP2_GET).await.ok()?;
        loop {
            let mut header = [0; 9];
            stream.read_exact(&mut header).await.ok()?;
            let length =
                usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
            let mut payload = vec![0; length];
            stream.read_exact(&mut payload).await.ok()?;
            let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
            if header[3] == HEADERS && stream_id & 0x7fff_ffff == 1 {
                let status = if payload.first() == Some(&0x88) {
                    "200"
                } else {
                    "not 200"
                };
                return Some(format!("HTTP/2 {status}"));
            }
        }
    }

    #[derive(Clone, Copy)]
    enum Client {
        /// A TCP connection to the plain listener.
        Plain,
        /// A TCP connection to the TLS listener that never starts the
        /// handshake.
        NoHandshake,
        /// A TLS connection whose completed handshake offered these ALPN
        /// protocols.
        Tls(&'static [&'static [u8]]),
    }

    trait ByteStream: AsyncRead + AsyncWrite + Unpin + Send {}

    impl<T: AsyncRead + AsyncWrite + Unpin + Send> ByteStream for T {}

    impl Client {
        /// Opens this client's connection. Returns `None` when the connection
        /// or its TLS handshake fails.
        async fn connect(self, plain: &Running, tls: &Running) -> Option<Box<dyn ByteStream>> {
            Some(match self {
                Self::Plain => Box::new(TcpStream::connect(plain.address).await.ok()?),
                Self::NoHandshake => Box::new(TcpStream::connect(tls.address).await.ok()?),
                Self::Tls(alpn) => Box::new(test_support::tls_connect(tls, alpn).await?),
            })
        }
    }

    /// Each row yields the protocol ALPN selected and the status of `GET /`
    /// over that protocol.
    #[tokio::test]
    async fn serve() {
        let plain = test_support::start(false, ConnectionTimeouts::DEFAULT).await;
        let tls = test_support::start(true, ConnectionTimeouts::DEFAULT).await;
        check_cases_async(
            [
                Case {
                    scenario: "plain HTTP/1.1",
                    input: Client::Plain,
                    expect: Yields((None, Some("HTTP/1.1 200 OK".to_owned()))),
                },
                Case {
                    scenario: "TLS with HTTP/1.1 offered over ALPN",
                    input: Client::Tls(&[HTTP1]),
                    expect: Yields((Some(HTTP1.to_vec()), Some("HTTP/1.1 200 OK".to_owned()))),
                },
                Case {
                    scenario: "TLS without ALPN speaks HTTP/1.1",
                    input: Client::Tls(&[]),
                    expect: Yields((None, Some("HTTP/1.1 200 OK".to_owned()))),
                },
                Case {
                    scenario: "TLS prefers HTTP/2 when the client offers both",
                    input: Client::Tls(&[H2, HTTP1]),
                    expect: Yields((Some(H2.to_vec()), Some("HTTP/2 200".to_owned()))),
                },
            ],
            |client| {
                let (plain, tls) = (&plain, &tls);
                async move {
                    let Client::Tls(alpn) = client else {
                        let mut stream = client.connect(plain, tls).await.ok_or(())?;
                        return Ok((None, test_support::exchange(&mut stream, GET).await));
                    };
                    let mut stream = test_support::tls_connect(tls, alpn).await.ok_or(())?;
                    let negotiated = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                    let status = if negotiated.as_deref() == Some(H2) {
                        http2_status(&mut stream).await
                    } else {
                        test_support::exchange(&mut stream, GET).await
                    };
                    Ok::<_, ()>((negotiated, status))
                }
            },
        )
        .await;
    }

    /// What a client sends to a listener. An optional request is answered
    /// first. Then the client sends `then` and waits for the server to close
    /// the connection.
    struct Script {
        client: Client,
        earlier: Option<&'static str>,
        /// Empty when the client sends nothing.
        then: &'static [u8],
    }

    fn rounded_to_step(elapsed: Duration) -> Duration {
        let step = STEP.as_millis();
        let steps = (elapsed.as_millis() + step / 2) / step;
        STEP * u32::try_from(steps).unwrap()
    }

    /// A connection that stops sending is closed by the timeout of the step it
    /// stopped in. Each row yields the time from sending `then` until the
    /// connection closed, rounded to [`STEP`].
    #[tokio::test]
    async fn serve_enforces_timeouts() {
        let plain = test_support::start(false, SHORT).await;
        let tls = test_support::start(true, SHORT).await;
        check_cases_async(
            [
                Case {
                    scenario: "a client that never starts the TLS handshake",
                    input: Script {
                        client: Client::NoHandshake,
                        earlier: None,
                        then: b"",
                    },
                    expect: Yields(SHORT.tls_handshake),
                },
                Case {
                    scenario: "a plain client that sends nothing",
                    input: Script {
                        client: Client::Plain,
                        earlier: None,
                        then: b"",
                    },
                    expect: Yields(SHORT.request_head),
                },
                Case {
                    scenario: "a TLS client that sends nothing after the handshake",
                    input: Script {
                        client: Client::Tls(&[HTTP1]),
                        earlier: None,
                        then: b"",
                    },
                    expect: Yields(SHORT.read),
                },
                Case {
                    scenario: "a TLS keep-alive connection that idles after a response",
                    input: Script {
                        client: Client::Tls(&[HTTP1]),
                        earlier: Some(GET),
                        then: b"",
                    },
                    expect: Yields(SHORT.request_head),
                },
                Case {
                    scenario: "an HTTP/2 connection that idles after its preface",
                    input: Script {
                        client: Client::Tls(&[H2]),
                        earlier: None,
                        then: HTTP2_START,
                    },
                    expect: Yields(SHORT.read),
                },
            ],
            |script| {
                let (plain, tls) = (&plain, &tls);
                async move {
                    let mut stream = script.client.connect(plain, tls).await.ok_or(())?;
                    if let Some(request) = script.earlier {
                        test_support::exchange(&mut stream, request)
                            .await
                            .ok_or(())?;
                    }
                    let started = Instant::now();
                    stream.write_all(script.then).await.map_err(drop)?;
                    // Anything the server sends, such as HTTP/2 SETTINGS, is
                    // read and discarded until the connection closes. A
                    // connection still open well past every timeout fails the
                    // row, so the test doesn't hang.
                    let mut discarded = [0; 1024];
                    let closed = async {
                        while stream.read(&mut discarded).await.is_ok_and(|read| read > 0) {}
                    };
                    time::timeout(SHORT.read * 2, closed).await.map_err(drop)?;
                    Ok::<_, ()>(rounded_to_step(started.elapsed()))
                }
            },
        )
        .await;
    }

    /// When a client stops reading a response, the connection is closed once a
    /// write has waited [`ConnectionTimeouts::write`]. Each row yields the
    /// status line if the whole response arrives.
    #[tokio::test]
    async fn serve_cuts_off_an_unread_response() {
        let plain = test_support::start(false, SHORT).await;
        check_cases_async(
            [
                Case {
                    scenario: "reading starts before the write timeout",
                    input: SHORT.write / 2,
                    expect: Yields(Some("HTTP/1.1 200 OK".to_owned())),
                },
                Case {
                    scenario: "reading starts after the write timeout",
                    input: (SHORT.write + SHORT.read) / 2,
                    expect: Yields(None),
                },
            ],
            |pause| {
                let plain = &plain;
                async move {
                    let mut stream = TcpStream::connect(plain.address).await.map_err(drop)?;
                    let request = "GET /large HTTP/1.1\r\nHost: localhost\r\n\r\n";
                    stream.write_all(request.as_bytes()).await.map_err(drop)?;
                    time::sleep(pause).await;
                    Ok::<_, ()>(test_support::read_response(&mut stream).await)
                }
            },
        )
        .await;
    }
}
