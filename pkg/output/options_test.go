// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package output

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithWriter(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf))

	o.Info("test")
	assert.Contains(t, buf.String(), "test")
}

func TestWithErrorWriter(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithErrorWriter(buf), WithNoColor(true))

	o.Error("error test")
	assert.Contains(t, buf.String(), "error test")
}

func TestWithQuiet(t *testing.T) {
	tests := []struct {
		name    string
		quiet   bool
		wantOut bool
	}{
		{"quiet enabled", true, false},
		{"quiet disabled", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			o := New(WithWriter(buf), WithQuiet(tt.quiet), WithNoColor(true))

			o.Info("test")

			if tt.wantOut {
				assert.NotEmpty(t, buf.String())
			} else {
				assert.Empty(t, buf.String())
			}
		})
	}
}

func TestWithLogOnly(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithLogOnly(true), WithDataEnabled(true))

	// LogOnly should suppress data output
	assert.False(t, o.IsDataOutputEnabled())
}

func TestWithDebug(t *testing.T) {
	tests := []struct {
		name    string
		debug   bool
		wantOut bool
	}{
		{"debug enabled", true, true},
		{"debug disabled", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			o := New(WithWriter(buf), WithDebug(tt.debug), WithNoColor(true))

			o.Debug("debug message")

			if tt.wantOut {
				assert.NotEmpty(t, buf.String())
			} else {
				assert.Empty(t, buf.String())
			}
		})
	}
}

func TestWithNoColor(t *testing.T) {
	tests := []struct {
		name     string
		noColor  bool
		wantANSI bool
	}{
		{"color enabled", false, true},
		{"color disabled", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			o := New(WithWriter(buf), WithNoColor(tt.noColor))

			o.Success("test")

			if tt.wantANSI {
				assert.Contains(t, buf.String(), ANSIGreen)
			} else {
				assert.NotContains(t, buf.String(), ANSIGreen)
			}
		})
	}
}

// TestWithPretty removed - pretty flag no longer supported

func TestWithFormat(t *testing.T) {
	formats := []string{LogFormatConsole, LogFormatVerbose, LogFormatJSON}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			o := New(WithFormat(format))
			assert.Equal(t, format, o.GetFormat())
		})
	}
}

func TestWithDataEnabled(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
	}{
		{"data enabled", true},
		{"data disabled", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := New(WithDataEnabled(tt.enabled))
			assert.Equal(t, tt.enabled, o.IsDataOutputEnabled())
		})
	}
}

func TestOptionsChaining(t *testing.T) {
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}

	o := New(
		WithWriter(buf),
		WithErrorWriter(errBuf),
		WithQuiet(false),
		WithDebug(true),
		WithNoColor(true),
		WithFormat(LogFormatConsole),
		WithDataEnabled(true),
	)

	require.NotNil(t, o)
	assert.False(t, o.IsQuiet())
	assert.True(t, o.IsDebug())
	assert.True(t, o.IsNoColor())
	assert.Equal(t, "json", o.GetDataFormat())
	assert.Equal(t, LogFormatConsole, o.GetFormat())
	assert.True(t, o.IsDataOutputEnabled())
}

func TestOptionOverride(t *testing.T) {
	// Later options should override earlier ones
	o := New(
		WithNoColor(false),
		WithNoColor(true), // This should take effect
	)

	assert.True(t, o.IsNoColor())
}
