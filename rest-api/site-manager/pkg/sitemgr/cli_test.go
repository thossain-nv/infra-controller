// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sitemgr

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cli "github.com/urfave/cli/v2"
	"k8s.io/client-go/rest"

	"github.com/NVIDIA/infra-controller/rest-api/site-manager/internal/logger"
)

func TestNewCommand(t *testing.T) {
	const sentryDeprecationWarning = "--sentry-dsn / SENTRY_DSN is deprecated and ignored"
	const sentryDSN = "https://key@sentry.example/1"

	tests := []struct {
		name string
		// args follow the program name on the command line.
		args []string
		// sentryDSNEnv is the SENTRY_DSN value. It is set even when empty so
		// a DSN in the caller's environment cannot reach the command; the
		// flag treats an empty value the same as an unset one.
		sentryDSNEnv string
		// wantWarnings is how often the deprecation warning is logged: once
		// at startup for a non-empty DSN from either source, never otherwise.
		wantWarnings int
	}{
		{
			name:         "no DSN logs no warning",
			wantWarnings: 0,
		},
		{
			name:         "--sentry-dsn logs one warning",
			args:         []string{"--sentry-dsn", sentryDSN},
			wantWarnings: 1,
		},
		{
			name:         "SENTRY_DSN logs one warning",
			sentryDSNEnv: sentryDSN,
			wantWarnings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Outside a cluster the Action returns from NewSiteManager instead
			// of serving until its context is cancelled. Startup warnings are
			// logged before that point.
			t.Setenv("KUBERNETES_SERVICE_HOST", "")
			t.Setenv("SENTRY_DSN", tt.sentryDSNEnv)

			nullLogger, hook := logtest.NewNullLogger()
			ctx := logger.NewContext(context.Background(), logrus.NewEntry(nullLogger))

			// Run the command the way cmd/sitemgr does. Flags hold parsed
			// state, so each row builds its own command.
			cmd := NewCommand()
			app := &cli.App{Name: cmd.Name, Flags: cmd.Flags, Action: cmd.Action}
			err := app.RunContext(ctx, append([]string{"sitemgr"}, tt.args...))
			require.ErrorIs(t, err, rest.ErrNotInCluster)

			warnings := 0
			for _, entry := range hook.AllEntries() {
				if entry.Level == logrus.WarnLevel && entry.Message == sentryDeprecationWarning {
					warnings++
				}
			}
			assert.Equal(t, tt.wantWarnings, warnings)
		})
	}
}
