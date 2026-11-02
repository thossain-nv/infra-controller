// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sitemgr

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"k8s.io/client-go/rest"

	"github.com/NVIDIA/infra-controller/rest-api/site-manager/internal/logger"
	"github.com/NVIDIA/infra-controller/rest-api/site-manager/internal/middleware"
	"github.com/NVIDIA/infra-controller/rest-api/site-manager/internal/server"
	crdclient "github.com/NVIDIA/infra-controller/rest-api/site-manager/pkg/client/clientset/versioned"
	"github.com/NVIDIA/infra-controller/rest-api/site-manager/pkg/metadata"
)

const (
	oneYrHours    = 365 * 24
	mgrCertFile   = "/tmp/mgr.cert"
	mgrKeyFile    = "/tmp/mgr.key"
	crdClientName = "site-crd-client"
)

// Options are args passed to the site manager at boot
type Options struct {
	certManagerURL string
	// certManagerCAPath is the CA bundle used to verify certManagerURL. It is
	// the ca.crt of the same CA that signs the Cert Manager's listener, so the
	// certificate chain and the hostname both have to check out.
	certManagerCAPath string
	ingressHost       string
	listenPort        string
	tlsKeyPath        string
	tlsCertPath       string
	namespace         string
}

// SiteMgr defines an instance of site manager
type SiteMgr struct {
	Options
	crdClient         crdclient.Interface
	appService        *server.HTTPService
	certManagerClient *http.Client
	log               *logrus.Entry
	l                 net.Listener
}

// NewSiteManager creates an instance of SiteMgr
func NewSiteManager(ctx context.Context, o Options) (*SiteMgr, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, errors.Wrap(err, "rest.InClusterConfig()")
	}

	// wrap the transport with otel
	otelWrapper := func(rt http.RoundTripper) http.RoundTripper {
		return otelhttp.NewTransport(rt, otelhttp.WithSpanNameFormatter(func(string, *http.Request) string {
			return crdClientName
		}))
	}

	cfg.WrapTransport = otelWrapper
	c, err := crdclient.NewForConfig(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "crdclient.NewForConfig(cfg)")
	}

	return newSiteManager(ctx, o, c)
}

func newSiteManager(ctx context.Context, o Options, c crdclient.Interface) (*SiteMgr, error) {
	certManagerClient, err := newCertManagerClient(o.certManagerCAPath)
	if err != nil {
		return nil, errors.Wrap(err, "newCertManagerClient")
	}

	s := &SiteMgr{
		Options:           o,
		certManagerClient: certManagerClient,
		log:               logger.FromContext(ctx),
	}

	s.crdClient = c

	err = s.tlsSetup(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "tlsSetup")
	}
	addr := fmt.Sprintf(":%s", s.listenPort)
	appService := server.NewTLSService(addr, s.tlsCertPath, s.tlsKeyPath)
	appService.AddHealthRoute()
	appService.AddVersionRoute(metadata.Version)
	appService.AddMetricsRoute()
	appService.Use(middleware.New(s.log, "nico_rest_site_manager")...)
	appService.Path("/v1/site").Handler(s.siteCreateHandler()).Methods("POST")
	appService.Path("/v1/site/{uuid}").Handler(s.siteGetHandler()).Methods("GET")
	appService.Path("/v1/site/roll/{uuid}").Handler(s.siteRollHandler()).Methods("POST")
	appService.Path("/v1/site/register/{uuid}").Handler(s.siteRegisterHandler()).Methods("POST")
	appService.Path("/v1/site/{uuid}").Handler(s.siteDeleteHandler()).Methods("DELETE")
	appService.Path("/v1/sitecreds").Handler(s.siteCredsHandler()).Methods("POST")
	s.appService = appService
	return s, nil
}

// Start starts the manager
func (s *SiteMgr) Start(ctx context.Context) {
	l, err := s.appService.Start(ctx)
	if err != nil {
		log.Fatalf("failed to start appService: %v", err)
	}
	s.l = l
}

func (s *SiteMgr) tlsSetup(ctx context.Context) error {
	log := s.log
	if s.tlsCertPath != "" && s.tlsKeyPath != "" {
		log.Infof("Using %s/%s passed via command line", s.tlsCertPath, s.tlsKeyPath)
		return nil
	}

	log.Infof("Setting up TLS Config using Cert Manager")

	var (
		resp *certificateResponse
		err  error
	)

	for {
		resp, err = s.getCertificate(ctx, s.ingressHost, "", oneYrHours)
		if err == nil {
			break
		}
		log.Infof("getCertificate: %v, retry in 10s", err)
		time.Sleep(10 * time.Second)
	}
	err = os.WriteFile(mgrCertFile, []byte(resp.Certificate), 0644)
	if err != nil {
		return err
	}

	err = os.WriteFile(mgrKeyFile, []byte(resp.Key), 0644)
	if err != nil {
		return err
	}

	s.tlsCertPath = mgrCertFile
	s.tlsKeyPath = mgrKeyFile
	return nil
}

func (s *SiteMgr) siteCreateHandler() http.Handler {
	h := &createHandler{manager: s}
	return otelhttp.NewHandler(h, "csm-site-create")
}

func (s *SiteMgr) siteDeleteHandler() http.Handler {
	h := &deleteHandler{manager: s}
	return otelhttp.NewHandler(h, "csm-site-delete")
}

func (s *SiteMgr) siteGetHandler() http.Handler {
	h := &getHandler{manager: s}
	return otelhttp.NewHandler(h, "csm-site-get")
}

func (s *SiteMgr) siteRegisterHandler() http.Handler {
	h := &registerHandler{manager: s}
	return otelhttp.NewHandler(h, "csm-site-register")
}
func (s *SiteMgr) siteRollHandler() http.Handler {
	h := &rollHandler{manager: s}
	return otelhttp.NewHandler(h, "csm-site-roll")
}

func (s *SiteMgr) siteCredsHandler() http.Handler {
	h := &credsHandler{manager: s}
	return otelhttp.NewHandler(h, "csm-site-bootstrap")
}

func (s *SiteMgr) writeJSONResp(w http.ResponseWriter, resp interface{}) {
	log := s.log
	c, err := json.Marshal(resp)
	if err != nil {
		log.Errorf("writeJSONResp Marshal %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(c)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
