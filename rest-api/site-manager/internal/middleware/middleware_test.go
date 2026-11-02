// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/infra-controller/rest-api/site-manager/internal/logger"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name             string
		metricsNamespace string
		envNamespace     string
		want             string
	}{
		{
			name:             "an empty METRICS_NAMESPACE leaves the supplied namespace alone",
			metricsNamespace: "nico_rest_site_manager",
			want:             "nico_rest_site_manager",
		},
		{
			name:             "METRICS_NAMESPACE takes precedence",
			metricsNamespace: "nico_rest_site_manager",
			envNamespace:     "acme_site_manager",
			want:             "acme_site_manager",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(metricsNamespaceEnv, tt.envNamespace)
			// New registers its metrics with the default registerer.
			registry := prometheus.NewRegistry()
			previousRegisterer := prometheus.DefaultRegisterer
			prometheus.DefaultRegisterer = registry
			t.Cleanup(func() { prometheus.DefaultRegisterer = previousRegisterer })

			router := mux.NewRouter()
			router.HandleFunc("/sitecreds", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusCreated)
			}).Methods(http.MethodPost)
			router.Use(New(logger.New(), tt.metricsNamespace)...)
			scrape := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})

			for _, wantCount := range []int{1, 2} {
				response := httptest.NewRecorder()
				router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/sitecreds", nil))
				require.Equal(t, http.StatusCreated, response.Code)
				unmatched := httptest.NewRecorder()
				router.ServeHTTP(unmatched, httptest.NewRequest(http.MethodGet, "/unknown", nil))
				require.Equal(t, http.StatusNotFound, unmatched.Code)

				metrics := httptest.NewRecorder()
				scrape.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
				require.Equal(t, http.StatusOK, metrics.Code)
				body := metrics.Body.String()

				histogram := tt.want + "_http_duration_seconds"
				assert.Contains(t, body, "# HELP "+histogram+" Duration of HTTP requests.\n")
				assert.Contains(t, body, "# TYPE "+histogram+" histogram\n")
				assert.Contains(t, body, fmt.Sprintf("%s_count{method=\"POST\",path=\"/sitecreds\"} %d\n", histogram, wantCount))
				for _, name := range []string{"http_request_counts", "http_requests_total"} {
					counter := tt.want + "_" + name
					assert.Contains(t, body, "# HELP "+counter+" Counter of HTTP requests.\n")
					assert.Contains(t, body, "# TYPE "+counter+" counter\n")
					assert.Contains(t, body, fmt.Sprintf("%s{method=\"POST\",path=\"/sitecreds\",status_code=\"201\"} %d\n", counter, wantCount))
				}
				assert.NotContains(t, body, `path="/unknown"`, "unmatched routes are not counted")
				if tt.envNamespace != "" {
					assert.NotContains(t, body, tt.metricsNamespace)
				}
			}
		})
	}
}
