// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sitemgr

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// certManagerRequest is what a Cert Manager stub received.
type certManagerRequest struct {
	method, path, body string
}

// newCertManagerStub serves status and body for every request and reports
// each request it receives on the returned channel.
func newCertManagerStub(t *testing.T, status int, body string) (*httptest.Server, <-chan certManagerRequest) {
	received := make(chan certManagerRequest, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestBody, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		received <- certManagerRequest{method: r.Method, path: r.URL.Path, body: string(requestBody)}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, received
}

func TestNewCertManagerClient(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	servingCAPath, err := writeCAFile(srv.Certificate())
	require.NoError(t, err)
	defer os.Remove(servingCAPath)

	// A well-formed CA that simply did not sign the endpoint being dialled.
	// Every httptest server shares one built-in certificate, so a second
	// server would not be a distinct trust anchor.
	unrelatedCAPath := filepath.Join(t.TempDir(), "unrelated-ca.pem")
	require.NoError(t, os.WriteFile(unrelatedCAPath, []byte(testCACert), 0600))

	emptyPath := filepath.Join(t.TempDir(), "empty.pem")
	require.NoError(t, os.WriteFile(emptyPath, []byte("not a certificate"), 0600))

	tests := []struct {
		name string
		// caPath is the bundle handed to the client under test.
		caPath string
		// wantBuildErr means the client cannot be constructed at all, so the
		// process fails at startup rather than running unverified.
		wantBuildErr bool
		// wantRequestErr means the client is built but refuses the connection.
		wantRequestErr bool
	}{
		{
			name:   "CA that signed the endpoint is accepted",
			caPath: servingCAPath,
		},
		{
			name:           "unrelated CA is refused",
			caPath:         unrelatedCAPath,
			wantRequestErr: true,
		},
		{
			name:         "missing bundle fails at construction",
			caPath:       filepath.Join(t.TempDir(), "absent.pem"),
			wantBuildErr: true,
		},
		{
			name:         "bundle with no certificates fails at construction",
			caPath:       emptyPath,
			wantBuildErr: true,
		},
		{
			name:         "unset bundle fails at construction",
			caPath:       "",
			wantBuildErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := newCertManagerClient(tt.caPath)
			if tt.wantBuildErr {
				assert.Error(t, err)
				assert.Nil(t, client)
				return
			}
			require.NoError(t, err)

			resp, err := client.Get(srv.URL)
			if tt.wantRequestErr {
				assert.Error(t, err, "request should fail certificate verification")
				return
			}
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

func TestSiteMgr_getCertificate(t *testing.T) {
	tests := []struct {
		name string
		// status and body are the Cert Manager stub's answer.
		status int
		body   string
		// certManagerURL replaces the stub's URL when set.
		certManagerURL string
		want           *certificateResponse
		wantErr        string
	}{
		{
			name:   "posts name, app and ttl and decodes the issued pair",
			status: http.StatusOK,
			body:   `{"key":"KEY PEM","certificate":"CERT PEM"}`,
			want:   &certificateResponse{Key: "KEY PEM", Certificate: "CERT PEM"},
		},
		{
			name:    "a status outside 2xx is an error carrying the status",
			status:  http.StatusInternalServerError,
			body:    "{}",
			wantErr: "500 Internal Server Error",
		},
		{
			name:    "204 is an empty response",
			status:  http.StatusNoContent,
			wantErr: "empty response",
		},
		{
			name:           "a malformed Cert Manager URL fails before sending",
			certManagerURL: "https://[::1",
			wantErr:        "http.NewRequestWithContext",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, received := newCertManagerStub(t, tt.status, tt.body)
			certManagerURL := srv.URL
			if tt.certManagerURL != "" {
				certManagerURL = tt.certManagerURL
			}
			s := &SiteMgr{
				Options:           Options{certManagerURL: certManagerURL},
				certManagerClient: srv.Client(),
			}

			got, err := s.getCertificate(context.Background(), "client", "site-uuid", clientTTL)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, certManagerRequest{
				method: http.MethodPost,
				path:   "/v1/pki/cloud-cert",
				body:   `{"name":"client","app":"site-uuid","ttl":2160}` + "\n",
			}, <-received)
		})
	}
}

func TestSiteMgr_getCA(t *testing.T) {
	const caPEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

	tests := []struct {
		name string
		// certManagerURL replaces the stub's URL when set.
		certManagerURL string
		want           string
		wantErr        string
	}{
		{
			name: "returns the CA PEM as served",
			want: caPEM,
		},
		{
			name:           "a malformed Cert Manager URL fails before sending",
			certManagerURL: "https://[::1",
			wantErr:        "http.NewRequestWithContext",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, received := newCertManagerStub(t, http.StatusOK, caPEM)
			certManagerURL := srv.URL
			if tt.certManagerURL != "" {
				certManagerURL = tt.certManagerURL
			}
			s := &SiteMgr{
				Options:           Options{certManagerURL: certManagerURL},
				certManagerClient: srv.Client(),
			}

			got, err := s.getCA(context.Background())
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, certManagerRequest{method: http.MethodGet, path: "/v1/pki/ca/pem", body: ""}, <-received)
		})
	}
}
