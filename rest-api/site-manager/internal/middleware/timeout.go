// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// timeout cancels the request context of a handler that runs longer than d
// and answers 503 with "Request timed out in <d>\n" in its place.
func timeout(d time.Duration) mux.MiddlewareFunc {
	message := fmt.Sprintf("Request timed out in %v\n", d)
	return func(next http.Handler) http.Handler {
		return http.TimeoutHandler(next, d, message)
	}
}
