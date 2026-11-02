// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHTTPService_AddHealthRoute(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "GET answers ok",
			method:     http.MethodGet,
			wantStatus: http.StatusOK,
			wantBody:   "ok\n",
		},
		{
			name:       "other methods are not allowed",
			method:     http.MethodPost,
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewTLSService(":0", "", "")
			s.AddHealthRoute()

			response := httptest.NewRecorder()
			s.ServeHTTP(response, httptest.NewRequest(tt.method, "/healthz", nil))

			assert.Equal(t, tt.wantStatus, response.Code)
			assert.Equal(t, tt.wantBody, response.Body.String())
		})
	}
}

func TestHTTPService_AddVersionRoute(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "GET answers the version and a newline",
			method:     http.MethodGet,
			wantStatus: http.StatusOK,
			wantBody:   "v-test\n",
		},
		{
			name:       "other methods are not allowed",
			method:     http.MethodPost,
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewTLSService(":0", "", "")
			s.AddVersionRoute("v-test")

			response := httptest.NewRecorder()
			s.ServeHTTP(response, httptest.NewRequest(tt.method, "/version", nil))

			assert.Equal(t, tt.wantStatus, response.Code)
			assert.Equal(t, tt.wantBody, response.Body.String())
		})
	}
}

func TestHTTPService_AddMetricsRoute(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		wantStatus   int
		wantContains string
	}{
		{
			name:         "GET serves the default Prometheus registry",
			method:       http.MethodGet,
			wantStatus:   http.StatusOK,
			wantContains: "# TYPE go_goroutines gauge\n",
		},
		{
			name:       "other methods are not allowed",
			method:     http.MethodPost,
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewTLSService(":0", "", "")
			s.AddMetricsRoute()

			response := httptest.NewRecorder()
			s.ServeHTTP(response, httptest.NewRequest(tt.method, "/metrics", nil))

			assert.Equal(t, tt.wantStatus, response.Code)
			assert.Contains(t, response.Body.String(), tt.wantContains)
		})
	}
}
