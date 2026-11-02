// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sitemgr

import (
	"time"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	"github.com/NVIDIA/infra-controller/rest-api/site-manager/internal/logger"
)

const (
	defOTPDuration = 24
)

var (
	otpDuration = defOTPDuration * time.Hour
)

// NewCommand creates a new cli command
func NewCommand() *cli.Command {
	return &cli.Command{
		Name:  "Forge Site Manager Service",
		Usage: "Forge Site Manager Service",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "debug",
				Usage: "Log debug message to stderr",
				Value: false,
			},
			&cli.StringFlag{
				Name:  "listen-port",
				Value: "8100",
				Usage: "TLS port to listen to",
			},
			&cli.StringFlag{
				Name:  "ingress-host",
				Value: "sitemgr.forge.nvidia.com",
				Usage: "Ingress host name for self signed certs",
			},
			// The creds-manager flag names and the credsmgr-ca default path
			// are kept for existing Helm values and manifests.
			&cli.StringFlag{
				Name:  "creds-manager-url",
				Value: "https://localhost:8000",
				Usage: "Cert Manager service endpoint used by backend",
			},
			&cli.StringFlag{
				Name:  "creds-manager-ca-path",
				Value: "/etc/credsmgr-ca/ca.crt",
				Usage: "CA that signed the Cert Manager endpoint's listener. That " +
					"endpoint's host name must appear in its --dns-name SANs",
			},
			&cli.StringFlag{
				Name:  "tls-key-path",
				Value: "",
				Usage: "File path for server tls key",
			},
			&cli.StringFlag{
				Name:  "tls-cert-path",
				Value: "",
				Usage: "File path for server tls cert",
			},
			&cli.StringFlag{
				Name:    "namespace",
				Value:   "nico-rest",
				EnvVars: []string{"SITE_MANAGER_NS"},
				Usage:   "Namespace where service is deployed",
			},
			&cli.IntFlag{
				Name:  "otp-duration",
				Value: defOTPDuration,
				Usage: "OTP duration in hours",
			},
			// Accepted for compatibility with existing invocations; Site
			// Manager does not report to Sentry.
			&cli.StringFlag{
				Name:    "sentry-dsn",
				Value:   "",
				EnvVars: []string{"SENTRY_DSN"},
				Usage:   "Deprecated and ignored",
			},
		},
		// TODO: cmd/sitemgr builds its cli.App without this Before, so --debug
		// has no effect. Wiring it would turn on debug logging in every
		// default deployment, because the Helm chart and the kustomize base
		// pass --debug.
		Before: func(c *cli.Context) error {
			if c.Bool("debug") {
				logger.FromContext(c.Context).Logger.SetLevel(logrus.DebugLevel)
			}
			return nil
		},
		Action: func(c *cli.Context) error {
			ctx := c.Context
			log := logger.FromContext(ctx)

			sentryDSN := c.String("sentry-dsn")
			if sentryDSN != "" {
				log.Warn("--sentry-dsn / SENTRY_DSN is deprecated and ignored")
			}

			o := Options{
				certManagerURL:    c.String("creds-manager-url"),
				certManagerCAPath: c.String("creds-manager-ca-path"),
				ingressHost:       c.String("ingress-host"),
				listenPort:        c.String("listen-port"),
				tlsKeyPath:        c.String("tls-key-path"),
				tlsCertPath:       c.String("tls-cert-path"),
				namespace:         c.String("namespace"),
			}

			otpHrs := c.Int("otp-duration")
			if otpHrs != defOTPDuration {
				log.Warnf("OTP duration overridden to %v hours", otpHrs)
			}
			otpDuration = time.Duration(otpHrs) * time.Hour
			log.Info("Configuring site manager server")
			s, err := NewSiteManager(ctx, o)
			if err != nil {
				return err
			}
			log.Info("Starting site manager server")
			s.Start(ctx)

			<-ctx.Done()

			gracePeriod := 5 * time.Second
			log.Infof("Shut down requested, wait for %v grace period ...", gracePeriod)
			time.Sleep(gracePeriod)
			log.Infof("Server terminated.")
			return nil
		},
	}
}
