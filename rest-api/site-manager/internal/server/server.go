// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package server runs Site Manager's TLS HTTP listener.
package server

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/NVIDIA/infra-controller/rest-api/site-manager/internal/logger"
)

const (
	// readTimeout, writeTimeout and idleTimeout are the http.Server limits
	// applied to every connection on the listener.
	readTimeout  = 5 * time.Second
	writeTimeout = 10 * time.Second
	idleTimeout  = 120 * time.Second

	// shutdownGracePeriod bounds http.Server.Shutdown once the Start context
	// is canceled; connections still open after it are closed. The command
	// waits 5 seconds after cancellation before it returns, so the drain fits
	// inside that wait.
	shutdownGracePeriod = 3 * time.Second
)

// HTTPService is a gorilla/mux router served over TLS on a TCP address.
// Routes and middleware are added through the embedded Router before Start.
type HTTPService struct {
	*mux.Router

	addr              string
	certFile, keyFile string
}

// NewTLSService returns a service that will listen on addr (for example
// ":8100", or ":0" for any free port) with the certificate and key in
// certFile and keyFile.
func NewTLSService(addr, certFile, keyFile string) *HTTPService {
	return &HTTPService{
		Router:   mux.NewRouter(),
		addr:     addr,
		certFile: certFile,
		keyFile:  keyFile,
	}
}

// AddHealthRoute serves GET /healthz with "ok\n"; the Kubernetes probes use it.
func (s *HTTPService) AddHealthRoute() {
	s.Path("/healthz").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("ok\n"))
		if err != nil {
			logger.FromContext(r.Context()).Error(err)
		}
	})
}

// AddVersionRoute serves GET /version with version and a trailing newline.
func (s *HTTPService) AddVersionRoute(version string) {
	s.Path("/version").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(version + "\n"))
		if err != nil {
			logger.FromContext(r.Context()).Error(err)
		}
	})
}

// AddMetricsRoute serves GET /metrics from the default Prometheus registry.
func (s *HTTPService) AddMetricsRoute() {
	s.Path("/metrics").Methods(http.MethodGet).Handler(promhttp.Handler())
}

// Start binds the listener and serves TLS in the background until ctx is
// canceled, then drains for shutdownGracePeriod. It returns the bound
// listener so callers can learn the port when addr asked for ":0".
func (s *HTTPService) Start(ctx context.Context) (net.Listener, error) {
	log := logger.FromContext(ctx)

	server := &http.Server{
		Handler:      s.Router,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	log.Infof("Initializing tcp listener at %q ...", s.addr)
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return nil, err
	}

	go func() {
		log.Infof("Serving HTTPS at: %v", listener.Addr())
		serveErr := server.ServeTLS(listener, s.certFile, s.keyFile)
		if serveErr != nil {
			log.Error(serveErr)
		}
	}()

	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
		defer cancel()

		log.Infof("Shutting down HTTPService at %v", listener.Addr())
		shutdownErr := server.Shutdown(shutdownCtx)
		if shutdownErr != nil {
			// Shutdown leaves the connections that missed the deadline open.
			log.Infof("failed to terminate HTTPService at %v, err: %v", listener.Addr(), shutdownErr)
			closeErr := server.Close()
			if closeErr != nil {
				log.Infof("failed to close HTTPService at %v, err: %v", listener.Addr(), closeErr)
			}
			return
		}
		log.Infof("Terminated HTTPService at %v", listener.Addr())
	}()

	return listener, nil
}
