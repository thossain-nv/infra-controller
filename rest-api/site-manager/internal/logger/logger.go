// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package logger builds Site Manager's logrus logger and carries it in a
// context, so request middleware can hand handlers a request-scoped logger.
package logger

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/sirupsen/logrus"
)

type contextKey struct{}

// New returns the process logger: text format with full timestamps and the
// calling file:line, at info level, written to stderr.
func New() *logrus.Entry {
	l := logrus.New()
	l.SetLevel(logrus.InfoLevel)
	l.Out = os.Stderr
	l.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02T15:04:05.999Z07:00",
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			return "", fmt.Sprintf("%s:%d", filepath.Base(f.File), f.Line)
		},
	})
	l.SetReportCaller(true)
	return logrus.NewEntry(l)
}

// NewContext returns a copy of parent that carries entry.
func NewContext(parent context.Context, entry *logrus.Entry) context.Context {
	return context.WithValue(parent, contextKey{}, entry)
}

// FromContext returns the logger NewContext stored in ctx. A context without
// one gets a logger that discards everything, so callers never check for nil.
func FromContext(ctx context.Context) *logrus.Entry {
	entry, ok := ctx.Value(contextKey{}).(*logrus.Entry)
	if ok && entry != nil {
		return entry
	}
	discard := logrus.New()
	discard.Out = io.Discard
	return logrus.NewEntry(discard)
}
