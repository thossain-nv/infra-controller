// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/trace"

	"github.com/NVIDIA/infra-controller/rest-api/site-manager/internal/logger"
)

// requestLogger stores a request-scoped logger in each request context,
// derived from log with the request path, method and remote address, a
// six-digit request sequence number, and the span and trace IDs when the
// incoming context carries them.
func requestLogger(log *logrus.Entry) mux.MiddlewareFunc {
	var sequence atomic.Uint64

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fields := logrus.Fields{
				"path":        r.URL.Path,
				"method":      r.Method,
				"ip":          r.RemoteAddr,
				"http_req_id": fmt.Sprintf("%06d", sequence.Add(1)%1000000),
			}
			spanCtx := trace.SpanContextFromContext(r.Context())
			if spanCtx.HasSpanID() {
				fields["span_id"] = spanCtx.SpanID().String()
			}
			if spanCtx.HasTraceID() {
				fields["trace_id"] = spanCtx.TraceID().String()
			}

			ctx := logger.NewContext(r.Context(), log.WithFields(fields))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
