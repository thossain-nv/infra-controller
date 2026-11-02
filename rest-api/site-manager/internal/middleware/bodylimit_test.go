// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBodyLimit(t *testing.T) {
	const limit = 10

	tests := []struct {
		name            string
		body            string
		wantRead        string
		wantMaxBytesErr bool
	}{
		{
			name:     "a body within the limit is read whole",
			body:     "123",
			wantRead: "123",
		},
		{
			name:            "a longer body fails the read",
			body:            "123456789abcdef",
			wantRead:        "123456789a",
			wantMaxBytesErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				read    []byte
				readErr error
			)
			handler := bodyLimit(limit)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				read, readErr = io.ReadAll(r.Body)
			}))

			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body)))

			assert.Equal(t, tt.wantRead, string(read))
			var maxBytesErr *http.MaxBytesError
			assert.Equal(t, tt.wantMaxBytesErr, errors.As(readErr, &maxBytesErr), "read error: %v", readErr)
		})
	}
}
