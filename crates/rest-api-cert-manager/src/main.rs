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
#![cfg_attr(not(test), deny(dead_code_pub_in_binary))]

//! NICo REST Cert Manager issues TLS certificates from the Site CA. At startup
//! it issues a serving certificate for itself. Over HTTPS, it issues leaf
//! certificates for NICo REST services (Site Manager).

mod api;
mod config;
mod pki;
mod server;

use std::process::ExitCode;
use std::time::Duration;

use carbide_instrument::otlp_tracing;
use clap::Parser;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::config::Options;

/// Value of the log `component` field and the OpenTelemetry `service.name`.
const SERVICE_NAME: &str = "nico-rest-cert-manager";

/// Time limit for the final span export after the listeners drain. The pod
/// gets `terminationGracePeriodSeconds: 5` and the drain takes at most `3s`
/// (`DRAIN_TIMEOUT` in `server/listener.rs`). So this `1s` flush leaves time
/// for the process to exit.
const TRACING_FLUSH_TIMEOUT: Duration = Duration::from_secs(1);

fn main() -> ExitCode {
    let options = match Options::try_parse() {
        Ok(options) => options,
        Err(error) => {
            // A usage error exits with `1` instead of clap's `2`. `--help`
            // exits with `0`.
            let exit_code = if error.use_stderr() {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            };
            error.print().ok();
            return exit_code;
        }
    };
    if options.version {
        println!("{} version {}", config::APP_NAME, config::version());
        return ExitCode::SUCCESS;
    }

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("failed to start the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let exit_code = runtime.block_on(run(options));
    // Dropping the runtime would wait for every blocking task, including a span
    // flush that ran past `TRACING_FLUSH_TIMEOUT`. This lets the process exit
    // within the time limit instead.
    runtime.shutdown_background();
    exit_code
}

/// Serves until a shutdown signal arrives or startup fails, then flushes spans.
async fn run(options: Options) -> ExitCode {
    let tracing = match setup_tracing(options.debug) {
        Ok(tracing) => tracing,
        Err(error) => {
            eprintln!("failed to initialize logging: {error}");
            return ExitCode::FAILURE;
        }
    };
    if !options.sentry_dsn.is_empty() {
        tracing::warn!("--sentry-dsn is deprecated and ignored; Sentry reporting was removed");
    }

    let served = serve_until_signalled(&options).await;
    let exit_code = match served {
        Ok(()) => {
            tracing::info!("stopped");
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(error = %error, "stopped on error");
            ExitCode::FAILURE
        }
    };

    let flushed = tokio::time::timeout(TRACING_FLUSH_TIMEOUT, tracing.shutdown()).await;
    if flushed.is_err() {
        tracing::warn!(
            flush_timeout_seconds = TRACING_FLUSH_TIMEOUT.as_secs(),
            "span export did not finish before exit"
        );
    }
    exit_code
}

/// Runs the server until the first `SIGINT` or `SIGTERM`, then lets it drain.
/// A second signal makes the process exit right away with status `1`.
async fn serve_until_signalled(options: &Options) -> Result<(), Box<dyn std::error::Error>> {
    // The handlers are registered before serving. Once registered, neither
    // signal kills the process with its default action.
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;

    let cancel = CancellationToken::new();
    let server = server::run(options, cancel.clone());
    tokio::pin!(server);

    tokio::select! {
        served = &mut server => return Ok(served?),
        signal_name = next_signal(&mut interrupt, &mut terminate) => {
            tracing::info!(signal = signal_name, "shutdown requested; draining connections");
        }
    }
    cancel.cancel();
    tokio::select! {
        served = &mut server => Ok(served?),
        signal_name = next_signal(&mut interrupt, &mut terminate) => {
            tracing::warn!(signal = signal_name, "second shutdown signal; exiting immediately");
            std::process::exit(1);
        }
    }
}

/// Waits for `SIGINT` or `SIGTERM` and returns the name of the one that
/// arrived.
async fn next_signal(interrupt: &mut Signal, terminate: &mut Signal) -> &'static str {
    tokio::select! {
        _ = interrupt.recv() => "SIGINT",
        _ = terminate.recv() => "SIGTERM",
    }
}

/// Installs logfmt logging and OTLP span export. The log level defaults to
/// `INFO` and can be set with `RUST_LOG`. `--debug` raises this service's own
/// target to `DEBUG`. Spans are exported only when an
/// `OTEL_EXPORTER_OTLP_*ENDPOINT` variable is set.
fn setup_tracing(debug: bool) -> Result<otlp_tracing::Tracing, Box<dyn std::error::Error>> {
    let log_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        .add_directive("hyper=warn".parse()?)
        .add_directive("h2=warn".parse()?)
        .add_directive("tower=warn".parse()?)
        .add_directive("rustls=warn".parse()?);
    let log_filter = if debug {
        log_filter.add_directive(format!("{}=debug", module_path!()).parse()?)
    } else {
        log_filter
    };

    // The span layer has its own filter, so the log filter only applies to the
    // log layer. This keeps `RUST_LOG` from limiting span export.
    let (span_layer, tracing) = otlp_tracing::setup(otlp_tracing::Config::new(SERVICE_NAME));
    tracing_subscriber::registry()
        .with(span_layer)
        .with(
            logfmt::layer()
                .with_event_fields([logfmt::EventField::with_default("component", SERVICE_NAME)])
                .with_filter(log_filter),
        )
        .try_init()?;
    tracing.report();

    Ok(tracing)
}
