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

package trust

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestLoggingTransport_RoundTrip(t *testing.T) {
	// Ensure requests pass through and responses are returned unchanged.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	defer ts.Close()

	client := &http.Client{Transport: &LoggingTransport{Log: logger.NewNoop()}}
	resp, err := client.Get(ts.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestLoggingTransport_TransportError(t *testing.T) {
	// Use a cancelled context so RoundTrip returns an error path.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:1", nil)
	require.NoError(t, err)

	tr := &LoggingTransport{Log: logger.NewNoop()}
	_, err = tr.RoundTrip(req)
	require.Error(t, err)
}

func TestRedactHeaders(t *testing.T) {
	tests := []struct {
		name         string
		header       string
		value        string
		wantRedacted bool
	}{
		{"authorization redacted", "Authorization", "Bearer secret", true},
		{"authorization redacted lowercase key", "authorization", "Bearer x", true},
		{"cookie redacted", "Cookie", "sid=abc", true},
		{"set-cookie redacted", "Set-Cookie", "sid=abc; Path=/", true},
		{"proxy-authorization redacted", "Proxy-Authorization", "Basic xyz", true},
		{"x-api-key redacted", "X-Api-Key", "k", true},
		{"content-type preserved", "Content-Type", "application/json", false},
		{"accept preserved", "Accept", "application/vnd.dev.sigstore.bundle.v0.3+json", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			h.Set(tt.header, tt.value)

			redacted := redactHeaders(h)
			got := redacted.Get(tt.header)
			if tt.wantRedacted {
				assert.Equal(t, "[REDACTED]", got)
			} else {
				assert.Equal(t, tt.value, got)
			}

			// Ensure original is untouched.
			assert.Equal(t, tt.value, h.Get(tt.header), "input header must not be mutated")
		})
	}
}

func TestNewHTTPClient(t *testing.T) {
	c := NewHTTPClient(logger.NewNoop(), false)
	require.NotNil(t, c)
	assert.Equal(t, defaultHTTPTimeout, c.Timeout)
	_, ok := c.Transport.(*LoggingTransport)
	assert.True(t, ok, "expected LoggingTransport, got %T", c.Transport)
}
