// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package main is the command entry point
package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	cotel "github.com/NVIDIA/infra-controller/rest-api/common/pkg/otel"
	"github.com/NVIDIA/infra-controller/rest-api/site-manager/internal/logger"
	"github.com/NVIDIA/infra-controller/rest-api/site-manager/pkg/metadata"
	"github.com/NVIDIA/infra-controller/rest-api/site-manager/pkg/sitemgr"
)

func main() {
	cmd := sitemgr.NewCommand()
	app := &cli.App{
		Name:    cmd.Name,
		Usage:   cmd.Usage,
		Version: metadata.Version,
		Flags:   cmd.Flags,
		Action:  cmd.Action,
	}

	log := logger.New()
	ctx := withShutdownSignals(logger.NewContext(context.Background(), log), log)
	otelShutdown, err := cotel.Bootstrap(ctx, cotel.ExporterConfigured(), "nico-rest-site-manager")
	if err != nil {
		log.Errorf("failed to initialize tracing: %v", err)
	}

	appErr := app.RunContext(ctx, os.Args)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	shutdownErr := otelShutdown(shutdownCtx)
	cancel()
	if shutdownErr != nil {
		log.Errorf("failed to shut down tracer provider: %v", shutdownErr)
	}
	if appErr != nil && !errors.Is(appErr, context.Canceled) {
		log.Fatal(appErr)
	}
}

// withShutdownSignals returns a copy of parent that the first SIGINT or
// SIGTERM cancels, which starts a graceful shutdown. A second signal exits
// the process immediately with status 1.
func withShutdownSignals(parent context.Context, log *logrus.Entry) context.Context {
	ctx, cancel := context.WithCancel(parent)
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		s := <-signals
		log.Infof("Received os.Signal %v, shutting down ...", s)
		cancel()

		s = <-signals
		log.Infof("Received second os.Signal %v, exit immediately !", s)
		os.Exit(1)
	}()

	return ctx
}
