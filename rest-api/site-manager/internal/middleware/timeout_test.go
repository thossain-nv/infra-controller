// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTimeout(t *testing.T) {
	const limit = 50 * time.Millisecond

	tests := []struct {
		name            string
		handlerDuration time.Duration
		wantStatus      int
		wantBody        string
	}{
		{
			name:       "a handler inside the limit answers normally",
			wantStatus: http.StatusOK,
			wantBody:   "ok\n",
		},
		{
			name:            "a slower handler is canceled and answered with 503",
			handlerDuration: 30 * time.Second,
			wantStatus:      http.StatusServiceUnavailable,
			wantBody:        "Request timed out in 50ms\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := timeout(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-r.Context().Done():
				case <-time.After(tt.handlerDuration):
					_, _ = w.Write([]byte("ok\n"))
				}
			}))

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

			assert.Equal(t, tt.wantStatus, response.Code)
			assert.Equal(t, tt.wantBody, response.Body.String())
		})
	}
}
