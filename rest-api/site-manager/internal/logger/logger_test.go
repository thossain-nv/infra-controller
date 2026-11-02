// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"context"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromContext(t *testing.T) {
	stored := New().WithField("request", "1")

	tests := []struct {
		name        string
		ctx         context.Context
		want        *logrus.Entry
		wantDiscard bool
	}{
		{
			name: "returns the logger NewContext stored",
			ctx:  NewContext(context.Background(), stored),
			want: stored,
		},
		{
			name:        "a context without a logger gets one that discards",
			ctx:         context.Background(),
			wantDiscard: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromContext(tt.ctx)

			require.NotNil(t, got)
			if tt.wantDiscard {
				assert.Equal(t, io.Discard, got.Logger.Out)
				return
			}
			assert.Same(t, tt.want, got)
		})
	}
}
