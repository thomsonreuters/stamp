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
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestFetchRootFromURL_ChecksumMatch(t *testing.T) {
	body := []byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`)
	sum := sha256.Sum256(body)
	checksum := hex.EncodeToString(sum[:])

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	got, err := fetchRootFromURL(context.TODO(), ts.URL+"/root.json", checksum, NewHTTPClient(logger.NewNoop(), false))
	require.NoError(t, err)
	assert.Equal(t, body, got)
}

func TestFetchRootFromURL_ChecksumMismatch(t *testing.T) {
	body := []byte(`{"mediaType":"x"}`)
	badChecksum := "0000000000000000000000000000000000000000000000000000000000000000"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	_, err := fetchRootFromURL(context.TODO(), ts.URL+"/root.json", badChecksum, NewHTTPClient(logger.NewNoop(), false))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")
}

func TestFetchRootFromURL_NoChecksum_Rejected(t *testing.T) {
	_, err := fetchRootFromURL(context.TODO(), "https://example.com/root.json", "", NewHTTPClient(logger.NewNoop(), false))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires --tuf-root-checksum")
}

func TestFetchRootFromURL_NonOKStatus(t *testing.T) {
	body := []byte(`ignored`)
	sum := sha256.Sum256(body)
	checksum := hex.EncodeToString(sum[:])

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer ts.Close()

	_, err := fetchRootFromURL(context.TODO(), ts.URL+"/missing.json", checksum, NewHTTPClient(logger.NewNoop(), false))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status")
}

func TestFetchRootFromURL_RedactsUserinfoOnError(t *testing.T) {
	// Empty checksum triggers the required-checksum error, which echoes the URL
	// via safeURL. The password must be redacted in that error.
	_, err := fetchRootFromURL(
		context.TODO(),
		"https://user:supersecret@127.0.0.1:1/root.json",
		"",
		NewHTTPClient(logger.NewNoop(), false),
	)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "supersecret", "password must not leak into error message")
	assert.Contains(t, err.Error(), "xxxxx", "userinfo password should be redacted")
}

func TestResolveTUFRootBytes_BytesPreferredOverPath(t *testing.T) {
	bytes := []byte(`bytes-content`)
	got, err := resolveTUFRootBytes(
		context.TODO(),
		Options{TUFRootBytes: bytes, TUFRootPath: "/should/not/be/read"},
		NewHTTPClient(logger.NewNoop(), false),
	)
	require.NoError(t, err)
	assert.Equal(t, bytes, got)
}

func TestResolveTUFRootBytes_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "root.json")
	body := []byte(`file-content`)
	require.NoError(t, os.WriteFile(path, body, 0o600))

	got, err := resolveTUFRootBytes(
		context.TODO(),
		Options{TUFRootPath: path},
		NewHTTPClient(logger.NewNoop(), false),
	)
	require.NoError(t, err)
	assert.Equal(t, body, got)
}

func TestResolveTUFRootBytes_EmptyReturnsNil(t *testing.T) {
	got, err := resolveTUFRootBytes(
		context.TODO(),
		Options{},
		NewHTTPClient(logger.NewNoop(), false),
	)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestResolveTUFRootBytes_ChecksumWithoutSourceErrors(t *testing.T) {
	_, err := resolveTUFRootBytes(
		context.TODO(),
		Options{TUFRootChecksum: "abc123"},
		NewHTTPClient(logger.NewNoop(), false),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--tuf-root-checksum has no effect without --tuf-root")
}

func TestResolveTUFRootBytes_HTTPURLRequiresInsecure(t *testing.T) {
	_, err := resolveTUFRootBytes(
		context.TODO(),
		Options{TUFRootPath: "http://plaintext.example.com/root.json"},
		NewHTTPClient(logger.NewNoop(), false),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires --insecure")
}

func TestResolveTUFRootBytes_HTTPURLWithInsecureFetches(t *testing.T) {
	body := []byte(`{"mediaType":"x"}`)
	sum := sha256.Sum256(body)
	checksum := hex.EncodeToString(sum[:])

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	got, err := resolveTUFRootBytes(
		context.TODO(),
		Options{TUFRootPath: ts.URL + "/root.json", TUFRootChecksum: checksum, Insecure: true},
		NewHTTPClient(logger.NewNoop(), true),
	)
	require.NoError(t, err)
	assert.Equal(t, body, got)
}

func TestResolveTUFRootBytes_URLWithoutChecksumRejected(t *testing.T) {
	_, err := resolveTUFRootBytes(
		context.TODO(),
		Options{TUFRootPath: "https://example.com/root.json"},
		NewHTTPClient(logger.NewNoop(), false),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires --tuf-root-checksum")
}

func TestFetchRootFromURL_ExceedsMaxSize(t *testing.T) {
	// Serve exactly 1 byte over the cap.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		buf := make([]byte, maxTUFRootSize+1)
		_, _ = w.Write(buf)
	}))
	defer ts.Close()

	_, err := fetchRootFromURL(context.TODO(), ts.URL+"/root.json", "deadbeef", NewHTTPClient(logger.NewNoop(), false))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestIsHTTPURL(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"https://example.com/x", true},
		{"http://example.com/x", true},
		{"/etc/stamp/tr-root.json", false},
		{"./relative/path.json", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, isHTTPURL(tt.in))
		})
	}
}
