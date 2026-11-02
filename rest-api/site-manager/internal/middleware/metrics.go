// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"strconv"

	"github.com/felixge/httpsnoop"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/NVIDIA/infra-controller/rest-api/site-manager/internal/logger"
)

// requestMetrics registers request metrics with the default Prometheus
// registry and records every request in them:
//
//   - <namespace>_http_duration_seconds{path,method}, a histogram
//   - <namespace>_http_requests_total{path,method,status_code}, a counter
//   - <namespace>_http_request_counts{path,method,status_code}, the same
//     counter under its legacy name, kept for existing dashboards and alerts
//
// path is the request URL path, not the route template, so a route such as
// /v1/site/{uuid} gets one series per UUID. status_code is the first status
// written, 200 when the handler writes a body without one.
func requestMetrics(namespace string) mux.MiddlewareFunc {
	latency := promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: namespace + "_http_duration_seconds",
		Help: "Duration of HTTP requests.",
	}, []string{"path", "method"})

	var counts []*prometheus.CounterVec
	for _, name := range []string{"http_request_counts", "http_requests_total"} {
		counts = append(counts, promauto.NewCounterVec(prometheus.CounterOpts{
			Name: namespace + "_" + name,
			Help: "Counter of HTTP requests.",
		}, []string{"path", "method", "status_code"}))
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log := logger.FromContext(r.Context())
			recorder := newStatusRecorder(w)
			defer func() {
				log.WithField("status_code", recorder.statusCode).Debugf("Handler finished")
				for _, count := range counts {
					count.WithLabelValues(r.URL.Path, r.Method, strconv.Itoa(recorder.statusCode)).Inc()
				}
			}()
			log.Debugf("Handler started")

			timer := prometheus.NewTimer(latency.WithLabelValues(r.URL.Path, r.Method))
			next.ServeHTTP(recorder.writer, r)
			timer.ObserveDuration()
		})
	}
}

// statusRecorder remembers the first status code written through writer.
// httpsnoop keeps the optional interfaces (http.Flusher, io.ReaderFrom, ...)
// of the wrapped http.ResponseWriter.
type statusRecorder struct {
	writer     http.ResponseWriter
	statusCode int
}

func newStatusRecorder(w http.ResponseWriter) *statusRecorder {
	recorder := &statusRecorder{}
	recorder.writer = httpsnoop.Wrap(w, httpsnoop.Hooks{
		Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(b []byte) (int, error) {
				if recorder.statusCode == 0 {
					recorder.statusCode = http.StatusOK
				}
				return next(b)
			}
		},
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(statusCode int) {
				if recorder.statusCode == 0 {
					recorder.statusCode = statusCode
				}
				next(statusCode)
			}
		},
	})
	return recorder
}
