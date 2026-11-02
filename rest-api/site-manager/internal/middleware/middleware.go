// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package middleware wraps Site Manager's routes with request logging,
// request metrics, a handler timeout and a request body limit.
package middleware

import (
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

const (
	// handlerTimeout bounds each handler. A slower handler's request context
	// is canceled and the client gets 503 "Request timed out in 5s\n".
	handlerTimeout = 5 * time.Second

	// requestBodyLimit caps every request body at 1 MiB.
	requestBodyLimit = 1 << 20

	// metricsNamespaceEnv overrides the metric name prefix passed to New. Site
	// Manager reads no config file, so an environment variable is the only
	// override available to an operator.
	metricsNamespaceEnv = "METRICS_NAMESPACE"
)

// New returns the middleware stack for router.Use, outermost first: request
// logger, request metrics, handler timeout, request body limit. Metric names
// start with metricsNamespace unless METRICS_NAMESPACE is set and non-empty.
//
// gorilla/mux runs router middleware for matched routes only, so 404 and 405
// responses are not logged or counted.
func New(log *logrus.Entry, metricsNamespace string) []mux.MiddlewareFunc {
	envNamespace := os.Getenv(metricsNamespaceEnv)
	if envNamespace != "" {
		metricsNamespace = envNamespace
	}

	return []mux.MiddlewareFunc{
		requestLogger(log),
		requestMetrics(metricsNamespace),
		timeout(handlerTimeout),
		bodyLimit(requestBodyLimit),
	}
}
