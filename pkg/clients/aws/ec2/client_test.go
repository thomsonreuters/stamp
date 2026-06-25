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

package ec2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestNew(t *testing.T) {
	t.Run("creates client successfully", func(t *testing.T) {
		client := New(&logger.Noop{})

		assert.NotNil(t, client)
		// Client successfully created with logger
	})
}

func TestIMDSOptions_Validate(t *testing.T) {
	t.Run("applies defaults for zero values", func(t *testing.T) {
		opts := &IMDSOptions{}
		err := opts.Validate()

		require.NoError(t, err)
		assert.Equal(t, DefaultIMDSEndpoint, opts.Endpoint)
		assert.Equal(t, IMDSVersionAuto, opts.Version)
		assert.Equal(t, DefaultIMDSTimeout, opts.Timeout)
		assert.Equal(t, DefaultIMDSMaxRetries, opts.MaxRetries)
		assert.Equal(t, DefaultIMDSRetryDelay, opts.RetryDelay)
		assert.Equal(t, DefaultIMDSv2TokenTTL, opts.TokenTTL)
	})

	t.Run("preserves non-zero values", func(t *testing.T) {
		opts := &IMDSOptions{
			Endpoint:   "http://custom",
			Version:    IMDSVersionV2,
			Timeout:    5 * time.Second,
			MaxRetries: 5,
			RetryDelay: 2 * time.Second,
			TokenTTL:   300,
		}
		err := opts.Validate()

		require.NoError(t, err)
		assert.Equal(t, "http://custom", opts.Endpoint)
		assert.Equal(t, IMDSVersionV2, opts.Version)
		assert.Equal(t, 5*time.Second, opts.Timeout)
		assert.Equal(t, 5, opts.MaxRetries)
		assert.Equal(t, 2*time.Second, opts.RetryDelay)
		assert.Equal(t, 300, opts.TokenTTL)
	})

	t.Run("rejects invalid version", func(t *testing.T) {
		opts := &IMDSOptions{
			Version: IMDSVersion("invalid"),
		}
		err := opts.Validate()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid IMDS version")
	})

	t.Run("rejects negative timeout", func(t *testing.T) {
		opts := &IMDSOptions{
			Timeout: -1 * time.Second,
		}
		err := opts.Validate()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid timeout")
	})

	t.Run("rejects negative max retries", func(t *testing.T) {
		opts := &IMDSOptions{
			MaxRetries: -1,
		}
		err := opts.Validate()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid max retries")
	})

	t.Run("rejects negative retry delay", func(t *testing.T) {
		opts := &IMDSOptions{
			RetryDelay: -1 * time.Second,
		}
		err := opts.Validate()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid retry delay")
	})

	t.Run("rejects token TTL too high", func(t *testing.T) {
		opts := &IMDSOptions{
			TokenTTL: 21601,
		}
		err := opts.Validate()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token TTL")
	})
}

func TestDefaultIMDSOptions(t *testing.T) {
	t.Run("returns correct defaults", func(t *testing.T) {
		opts := DefaultIMDSOptions()

		assert.Equal(t, DefaultIMDSEndpoint, opts.Endpoint)
		assert.Equal(t, IMDSVersionAuto, opts.Version)
		assert.Equal(t, DefaultIMDSTimeout, opts.Timeout)
		assert.Equal(t, DefaultIMDSMaxRetries, opts.MaxRetries)
		assert.Equal(t, DefaultIMDSRetryDelay, opts.RetryDelay)
		assert.Equal(t, DefaultIMDSv2TokenTTL, opts.TokenTTL)
	})
}

func TestClient_CheckIMDSAccessibility(t *testing.T) {
	t.Run("returns nil when IMDS is accessible", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodHead, r.Method)
			assert.Equal(t, "/latest/meta-data/instance-id", r.URL.Path)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := New(&logger.Noop{})
		opts := &IMDSOptions{
			Endpoint: server.URL,
		}

		err := client.CheckIMDSAccessibility(t.Context(), opts)

		assert.NoError(t, err)
	})

	t.Run("returns error when IMDS is not accessible", func(t *testing.T) {
		client := New(&logger.Noop{})
		opts := &IMDSOptions{
			Endpoint: "http://invalid-endpoint:12345",
		}

		err := client.CheckIMDSAccessibility(t.Context(), opts)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "IMDS endpoint not accessible")
	})

	t.Run("uses default options when nil", func(t *testing.T) {
		client := New(&logger.Noop{})

		// Verify that passing nil opts doesn't panic (actual network behavior varies by environment)
		assert.NotPanics(t, func() {
			_ = client.CheckIMDSAccessibility(t.Context(), nil)
		})
	})
}

func TestClient_GetIMDSMetadata_V1(t *testing.T) {
	t.Run("successfully retrieves metadata", func(t *testing.T) {
		expectedValue := "i-1234567890abcdef0"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/latest/meta-data/instance-id", r.URL.Path)
			_, _ = w.Write([]byte(expectedValue))
		}))
		defer server.Close()

		client := New(&logger.Noop{})
		opts := &IMDSOptions{
			Endpoint: server.URL,
			Version:  IMDSVersionV1,
		}

		result, err := client.GetIMDSMetadata(t.Context(), "instance-id", opts)

		require.NoError(t, err)
		assert.Equal(t, expectedValue, result)
	})

	t.Run("handles whitespace in response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("  i-1234567890abcdef0  \n"))
		}))
		defer server.Close()

		client := New(&logger.Noop{})
		opts := &IMDSOptions{
			Endpoint: server.URL,
			Version:  IMDSVersionV1,
		}

		result, err := client.GetIMDSMetadata(t.Context(), "instance-id", opts)

		require.NoError(t, err)
		assert.Equal(t, "i-1234567890abcdef0", result)
	})

	t.Run("returns error on HTTP error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		}))
		defer server.Close()

		client := New(&logger.Noop{})
		opts := &IMDSOptions{
			Endpoint:   server.URL,
			Version:    IMDSVersionV1,
			MaxRetries: 1,
		}

		result, err := client.GetIMDSMetadata(t.Context(), "invalid-path", opts)

		require.Error(t, err)
		assert.Empty(t, result)
		assert.Contains(t, err.Error(), "404")
	})

	t.Run("retries on failure", func(t *testing.T) {
		attempts := 0
		expectedValue := "i-1234567890abcdef0"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			if attempts < 3 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(expectedValue))
		}))
		defer server.Close()

		client := New(&logger.Noop{})
		opts := &IMDSOptions{
			Endpoint:   server.URL,
			Version:    IMDSVersionV1,
			MaxRetries: 3,
			RetryDelay: 10 * time.Millisecond,
		}

		result, err := client.GetIMDSMetadata(t.Context(), "instance-id", opts)

		require.NoError(t, err)
		assert.Equal(t, expectedValue, result)
		assert.Equal(t, 3, attempts)
	})
}

func TestClient_GetIMDSMetadata_V2(t *testing.T) {
	t.Run("successfully retrieves metadata with token", func(t *testing.T) {
		expectedToken := "test-token-12345"
		expectedValue := "i-1234567890abcdef0"
		tokenRequested := false
		metadataRequested := false

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/api/token"):
				tokenRequested = true
				assert.Equal(t, "60", r.Header.Get(IMDSv2TokenTTLHeader)) //nolint:canonicalheader // AWS-defined header name
				_, _ = w.Write([]byte(expectedToken))

			case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/instance-id"):
				metadataRequested = true
				assert.Equal(t, expectedToken, r.Header.Get(IMDSv2TokenHeader)) //nolint:canonicalheader // AWS-defined header name
				_, _ = w.Write([]byte(expectedValue))

			default:
				assert.Failf(t, "unexpected request", "method: %s, path: %s", r.Method, r.URL.Path)
			}
		}))
		defer server.Close()

		client := New(&logger.Noop{})
		opts := &IMDSOptions{
			Endpoint: server.URL,
			Version:  IMDSVersionV2,
		}

		result, err := client.GetIMDSMetadata(t.Context(), "instance-id", opts)

		require.NoError(t, err)
		assert.Equal(t, expectedValue, result)
		assert.True(t, tokenRequested)
		assert.True(t, metadataRequested)
	})

	t.Run("caches token for subsequent requests", func(t *testing.T) {
		tokenRequests := 0
		metadataRequests := 0

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/api/token"):
				tokenRequests++
				_, _ = w.Write([]byte("test-token"))

			case r.Method == http.MethodGet:
				metadataRequests++
				_, _ = w.Write([]byte("test-value"))
			}
		}))
		defer server.Close()

		client := New(&logger.Noop{})
		opts := &IMDSOptions{
			Endpoint: server.URL,
			Version:  IMDSVersionV2,
		}

		_, err := client.GetIMDSMetadata(t.Context(), "instance-id", opts)
		require.NoError(t, err)

		_, err = client.GetIMDSMetadata(t.Context(), "instance-type", opts)
		require.NoError(t, err)

		assert.Equal(t, 1, tokenRequests)
		assert.Equal(t, 2, metadataRequests)
	})

	t.Run("falls back to V1 when auto mode and token fails", func(t *testing.T) {
		tokenFailed := false
		v1Success := false

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPut:
				tokenFailed = true
				w.WriteHeader(http.StatusForbidden)

			case http.MethodGet:
				v1Success = true
				_, _ = w.Write([]byte("i-1234567890abcdef0"))
			}
		}))
		defer server.Close()

		client := New(&logger.Noop{})
		opts := &IMDSOptions{
			Endpoint: server.URL,
			Version:  IMDSVersionAuto,
		}

		result, err := client.GetIMDSMetadata(t.Context(), "instance-id", opts)

		require.NoError(t, err)
		assert.Equal(t, "i-1234567890abcdef0", result)
		assert.True(t, tokenFailed)
		assert.True(t, v1Success)
	})

	t.Run("uses custom token TTL", func(t *testing.T) {
		customTTL := 300

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut {
				assert.Equal(t, "300", r.Header.Get(IMDSv2TokenTTLHeader)) //nolint:canonicalheader // AWS-defined header name
				_, _ = w.Write([]byte("test-token"))
			} else {
				_, _ = w.Write([]byte("test-value"))
			}
		}))
		defer server.Close()

		client := New(&logger.Noop{})
		opts := &IMDSOptions{
			Endpoint: server.URL,
			Version:  IMDSVersionV2,
			TokenTTL: customTTL,
		}

		_, err := client.GetIMDSMetadata(t.Context(), "instance-id", opts)
		assert.NoError(t, err)
	})
}

func TestClient_GetInstanceIdentityDocument(t *testing.T) {
	t.Run("successfully retrieves and parses document", func(t *testing.T) {
		identityDoc := map[string]any{
			"instanceId":       "i-1234567890abcdef0",
			"instanceType":     "t3.micro",
			"region":           "us-east-1",
			"availabilityZone": "us-east-1a",
			"accountId":        "123456789012",
		}

		docJSON, err := json.Marshal(identityDoc)
		require.NoError(t, err)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/api/token") {
				_, _ = w.Write([]byte("test-token"))
			} else {
				_, _ = w.Write(docJSON)
			}
		}))
		defer server.Close()

		client := New(&logger.Noop{})
		opts := &IMDSOptions{
			Endpoint: server.URL,
			Version:  IMDSVersionV2,
		}

		doc, err := client.GetInstanceIdentityDocument(t.Context(), opts)

		require.NoError(t, err)
		assert.Equal(t, "i-1234567890abcdef0", doc.InstanceID)
		assert.Equal(t, "t3.micro", doc.InstanceType)
		assert.Equal(t, "us-east-1", doc.Region)
		assert.Equal(t, "us-east-1a", doc.AvailabilityZone)
		assert.Equal(t, "123456789012", doc.AccountID)
	})

	t.Run("uses default options when nil", func(t *testing.T) {
		client := New(&logger.Noop{})

		// Verify that passing nil opts doesn't panic (actual network behavior varies by environment)
		assert.NotPanics(t, func() {
			_, _ = client.GetInstanceIdentityDocument(t.Context(), nil)
		})
	})
}

func TestClient_ContextCancellation(t *testing.T) {
	t.Run("respects context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			_, _ = w.Write([]byte("value"))
		}))
		defer server.Close()

		client := New(&logger.Noop{})
		opts := &IMDSOptions{
			Endpoint: server.URL,
			Version:  IMDSVersionV1,
		}

		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()

		result, err := client.GetIMDSMetadata(ctx, "instance-id", opts)

		require.Error(t, err)
		assert.Empty(t, result)
	})
}

//nolint:dupl // Test scenarios have similar structure but test different behaviors
func TestClient_RealWorldScenarios(t *testing.T) {
	t.Run("retrieves multiline security groups", func(t *testing.T) {
		sgList := "sg-12345\nsg-67890\nsg-abcdef"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/api/token") {
				_, _ = w.Write([]byte("test-token"))
			} else {
				_, _ = w.Write([]byte(sgList))
			}
		}))
		defer server.Close()

		client := New(&logger.Noop{})
		opts := &IMDSOptions{
			Endpoint: server.URL,
			Version:  IMDSVersionV2,
		}

		result, err := client.GetIMDSMetadata(t.Context(), "network/interfaces/macs/00:00:00:00:00:00/security-group-ids", opts)

		require.NoError(t, err)
		assert.Contains(t, result, "sg-12345")
		assert.Contains(t, result, "sg-67890")
		assert.Contains(t, result, "sg-abcdef")
	})

	t.Run("handles tag collection", func(t *testing.T) {
		tagKeys := "Name\nEnvironment\nOwner"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/api/token") {
				_, _ = w.Write([]byte("test-token"))
			} else {
				_, _ = w.Write([]byte(tagKeys))
			}
		}))
		defer server.Close()

		client := New(&logger.Noop{})
		opts := &IMDSOptions{
			Endpoint: server.URL,
			Version:  IMDSVersionV2,
		}

		result, err := client.GetIMDSMetadata(t.Context(), "tags/instance", opts)

		require.NoError(t, err)
		assert.Contains(t, result, "Name")
		assert.Contains(t, result, "Environment")
		assert.Contains(t, result, "Owner")
	})
}
