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

//! Request span for the TLS routes.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument;

/// Runs the request inside an `INFO` span named after its method and route.
/// The span is exported over OTLP. When it closes, a logfmt `level=SPAN` line
/// is logged with the final `http_status`. If the request has a W3C
/// `traceparent`, the span becomes a child in the caller's trace. Handler logs
/// include the span's `span_id`.
pub(super) async fn request_span(
    matched_path: MatchedPath,
    request: Request,
    next: Next,
) -> Response {
    let span = tracing::info_span!(
        "request",
        otel.name = %format_args!("{} {}", request.method(), matched_path.as_str()),
        otel.kind = "server",
        span_id = %format_args!("{:#x}", rand::random::<u64>()),
        http_method = %request.method(),
        http_route = matched_path.as_str(),
        peer_address = tracing::field::Empty,
        http_status = tracing::field::Empty,
    );
    // The server adds the peer address to every connection's requests.
    if let Some(ConnectInfo(peer_address)) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
        span.record("peer_address", tracing::field::display(peer_address));
    }
    // The parent must be set before the span is first entered.
    trace_propagation::set_span_parent_from_headers(&span, request.headers());

    let response = next.run(request).instrument(span.clone()).await;
    span.record("http_status", response.status().as_u16());
    response
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::body::Body;
    use axum::middleware::from_fn;
    use axum::routing::get;
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases_async};
    use opentelemetry::Value;
    use opentelemetry::trace::{SpanId, SpanKind, TraceContextExt, TraceId, TracerProvider as _};
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use opentelemetry_sdk::trace::{InMemorySpanExporter, Sampler, SdkTracerProvider, SpanData};
    use tower::ServiceExt;
    use tracing::Dispatch;
    use tracing::instrument::WithSubscriber;
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    // Fixed IDs make the caller's trace easy to recognize.
    const CALLER_TRACE: u128 = 0x42;
    const CALLER_SPAN: u64 = 0x55;

    /// Where the exported span is placed in a trace.
    #[derive(Debug, PartialEq)]
    enum Parent {
        /// The span doesn't have a parent and starts its own trace.
        Root,
        /// The parent is the caller's span, in the caller's trace.
        Caller,
        Other,
    }

    /// What the request span exported, plus whether the handler ran in the
    /// span's trace. The handler's own outbound calls would continue that
    /// trace.
    #[derive(Debug, PartialEq)]
    struct Exported {
        name: String,
        kind: SpanKind,
        parent: Parent,
        handler_in_span_trace: bool,
        http_method: Option<Value>,
        http_route: Option<Value>,
        peer_address: Option<Value>,
        http_status: Option<Value>,
    }

    impl Exported {
        fn read(span: &SpanData, handler_trace_id: Option<TraceId>) -> Self {
            let attribute = |key: &str| {
                span.attributes
                    .iter()
                    .find(|attribute| attribute.key.as_str() == key)
                    .map(|attribute| attribute.value.clone())
            };
            let trace_id = span.span_context.trace_id();
            let parent = if span.parent_span_id == SpanId::INVALID {
                Parent::Root
            } else if span.parent_span_id == SpanId::from(CALLER_SPAN)
                && trace_id == TraceId::from(CALLER_TRACE)
            {
                Parent::Caller
            } else {
                Parent::Other
            };
            Self {
                name: span.name.to_string(),
                kind: span.span_kind.clone(),
                parent,
                handler_in_span_trace: handler_trace_id == Some(trace_id),
                http_method: attribute("http_method"),
                http_route: attribute("http_route"),
                peer_address: attribute("peer_address"),
                http_status: attribute("http_status"),
            }
        }
    }

    /// Serves `GET /v1/pki/ca` under [`super::request_span`] with an
    /// OpenTelemetry layer that exports to memory. Then reads back the only
    /// span that was exported.
    async fn served(traceparent: Option<String>) -> Result<Exported, String> {
        let handler_trace_id = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&handler_trace_id);
        let router = Router::new()
            .route(
                "/v1/pki/ca",
                get(move || async move {
                    let span_context = tracing::Span::current()
                        .context()
                        .span()
                        .span_context()
                        .clone();
                    if span_context.is_valid()
                        && let Ok(mut trace_id) = captured.lock()
                    {
                        *trace_id = Some(span_context.trace_id());
                    }
                }),
            )
            .route_layer(from_fn(super::request_span));
        let request = |traceparent: Option<&str>| {
            let mut builder = Request::builder().uri("/v1/pki/ca");
            if let Some(traceparent) = traceparent {
                builder = builder.header("traceparent", traceparent);
            }
            let mut request = builder
                .body(Body::empty())
                .map_err(|error| error.to_string())?;
            // Adds the peer address, like the server does for every request.
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 4242))));
            Ok::<_, String>(request)
        };

        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_sampler(Sampler::AlwaysOn)
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = Dispatch::new(tracing_subscriber::registry().with(
            tracing_opentelemetry::layer().with_tracer(provider.tracer("request-span-test")),
        ));

        // tracing caches each callsite's interest for the whole process. While
        // this subscriber is the only one, another test thread can register
        // the span's callsite and cache "never" from that thread's empty
        // default. So register the callsite with one unobserved request, then
        // rebuild the cache in this subscriber's scope.
        let unobserved = router.clone().oneshot(request(None)?).await;
        unobserved.map_err(|error| error.to_string())?;
        tracing::dispatcher::with_default(&subscriber, tracing::callsite::rebuild_interest_cache);

        let response = router
            .oneshot(request(traceparent.as_deref())?)
            .with_subscriber(subscriber)
            .await
            .map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!("served {}", response.status()));
        }

        let handler_trace_id = *handler_trace_id.lock().map_err(|error| error.to_string())?;
        let spans = exporter
            .get_finished_spans()
            .map_err(|error| error.to_string())?;
        match spans.as_slice() {
            [span] => Ok(Exported::read(span, handler_trace_id)),
            spans => Err(format!("{} spans exported", spans.len())),
        }
    }

    #[tokio::test]
    async fn request_span() {
        let exported = |parent| Exported {
            name: "GET /v1/pki/ca".to_owned(),
            kind: SpanKind::Server,
            parent,
            handler_in_span_trace: true,
            http_method: Some(Value::from("GET")),
            http_route: Some(Value::from("/v1/pki/ca")),
            peer_address: Some(Value::from("10.0.0.1:4242")),
            http_status: Some(Value::from("200")),
        };
        check_cases_async(
            [
                Case {
                    scenario: "a request without trace context starts a trace",
                    input: None,
                    expect: Yields(exported(Parent::Root)),
                },
                Case {
                    scenario: "a traceparent continues the caller's trace",
                    input: Some(format!("00-{CALLER_TRACE:032x}-{CALLER_SPAN:016x}-01")),
                    expect: Yields(exported(Parent::Caller)),
                },
                Case {
                    scenario: "a malformed traceparent starts a trace",
                    input: Some("not-a-traceparent".to_owned()),
                    expect: Yields(exported(Parent::Root)),
                },
            ],
            served,
        )
        .await;
    }
}
