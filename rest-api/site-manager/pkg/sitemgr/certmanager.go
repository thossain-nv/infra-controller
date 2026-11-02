// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sitemgr

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	// certManagerTimeout bounds each request to nico-rest-cert-manager,
	// including reading the response body.
	certManagerTimeout = 20 * time.Second
	// certManagerClientName is the span name of every Cert Manager request.
	certManagerClientName = "cert-manager-client"
)

// certificateRequest is the body of Cert Manager's POST /v1/pki/cloud-cert.
// Cert Manager derives the certificate's DNS name from Name and App, and its
// validity in hours from TTL.
type certificateRequest struct {
	Name string `json:"name,omitempty"`
	App  string `json:"app,omitempty"`
	TTL  int    `json:"ttl,omitempty"`
}

// certificateResponse is Cert Manager's reply to a certificateRequest: the
// PEM private key and the PEM certificate issued for it.
type certificateResponse struct {
	Key         string `json:"key,omitempty"`
	Certificate string `json:"certificate,omitempty"`
}

// newCertManagerClient builds the HTTP client used to reach
// nico-rest-cert-manager. The CA bundle at caPath is the only trust anchor, so
// an unreadable or malformed file is a startup failure rather than a silent
// downgrade to an unverified connection.
func newCertManagerClient(caPath string) (*http.Client, error) {
	if caPath == "" {
		return nil, fmt.Errorf("a CA bundle path is required to verify the cert manager endpoint")
	}

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, errors.Wrapf(err, "read cert manager CA bundle %q", caPath)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("cert manager CA bundle %q contains no certificates", caPath)
	}

	return &http.Client{
		Timeout: certManagerTimeout,
		// wrap transport with otel
		Transport: otelhttp.NewTransport(&http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			},
		}, otelhttp.WithSpanNameFormatter(func(_ string, _ *http.Request) string {
			return certManagerClientName
		})),
	}, nil
}

// getCertificate asks Cert Manager to issue a certificate for name and app,
// valid for ttl hours.
func (s *SiteMgr) getCertificate(ctx context.Context, name, app string, ttl int) (*certificateResponse, error) {
	body := &certificateRequest{
		Name: name,
		App:  app,
		TTL:  ttl,
	}

	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(body)
	if err != nil {
		return nil, errors.Wrap(err, "json encode payload")
	}
	url := s.certManagerURL + "/v1/pki/cloud-cert"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, payloadBuf)
	if err != nil {
		return nil, errors.Wrap(err, "http.NewRequestWithContext")
	}
	content, err := s.roundTrip(req)
	if err != nil {
		return nil, errors.Wrap(err, "s.roundTrip(req)")
	}

	if content == nil {
		return nil, fmt.Errorf("empty response")
	}

	creds := &certificateResponse{}
	err = json.Unmarshal(content, creds)
	if err != nil {
		return nil, errors.Wrap(err, "s.json.Unmarshal")
	}
	return creds, nil
}

// getCA returns Cert Manager's CA certificate file in PEM, as served.
func (s *SiteMgr) getCA(ctx context.Context) (string, error) {
	url := s.certManagerURL + "/v1/pki/ca/pem"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", errors.Wrap(err, "http.NewRequestWithContext")
	}
	content, err := s.roundTrip(req)
	if err != nil {
		return "", errors.Wrap(err, "s.roundTrip(req)")
	}

	if content == nil {
		return "", fmt.Errorf("empty response")
	}

	return string(content), nil
}

// roundTrip sends req to Cert Manager and returns the response body. A status
// outside 200-226 is an error carrying the status and body; 204 returns nil.
func (s *SiteMgr) roundTrip(req *http.Request) ([]byte, error) {
	resp, err := s.certManagerClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusIMUsed {
		content, _ := io.ReadAll(resp.Body)
		err = fmt.Errorf("%s, %s", resp.Status, content)
		return nil, err
	}

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}

	return io.ReadAll(resp.Body)
}
