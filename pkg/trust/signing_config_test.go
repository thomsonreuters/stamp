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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

const minimalSigningConfigJSON = `{
  "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
  "caUrls": [
    { "url": "https://fulcio.example.com", "majorApiVersion": 1,
      "validFor": { "start": "2020-01-01T00:00:00Z" },
      "operator": "example.com" }
  ],
  "oidcUrls": [
    { "url": "https://oidc.example.com", "majorApiVersion": 1,
      "validFor": { "start": "2020-01-01T00:00:00Z" },
      "operator": "example.com" }
  ],
  "rekorTlogUrls": [
    { "url": "https://rekor.example.com", "majorApiVersion": 1,
      "validFor": { "start": "2020-01-01T00:00:00Z" },
      "operator": "example.com" }
  ],
  "tsaUrls": [
    { "url": "https://tsa.example.com", "majorApiVersion": 1,
      "validFor": { "start": "2020-01-01T00:00:00Z" },
      "operator": "example.com" }
  ],
  "rekorTlogConfig": { "selector": "ANY" },
  "tsaConfig":       { "selector": "ANY" }
}`

func TestNewSigningConfigResolver_Dispatch(t *testing.T) {
	tests := []struct {
		name     string
		opts     Options
		wantKind string // "nil", "file", "tuf"
	}{
		{
			name:     "no source → nil resolver",
			opts:     Options{},
			wantKind: "nil",
		},
		{
			name:     "path source → file resolver",
			opts:     Options{SigningConfigPath: "/some/path.json"},
			wantKind: "file",
		},
		{
			name:     "bytes source → file resolver",
			opts:     Options{SigningConfigBytes: []byte(minimalSigningConfigJSON)},
			wantKind: "file",
		},
		{
			name:     "use-signing-config → tuf resolver",
			opts:     Options{UseSigningConfig: true},
			wantKind: "tuf",
		},
		// Precedence: explicit sources win over the default TUF fetch.
		{
			name:     "path + use-signing-config → path wins",
			opts:     Options{SigningConfigPath: "/some/path.json", UseSigningConfig: true},
			wantKind: "file",
		},
		{
			name:     "bytes + use-signing-config → bytes win",
			opts:     Options{SigningConfigBytes: []byte("x"), UseSigningConfig: true},
			wantKind: "file",
		},
		{
			name:     "bytes + path → bytes win",
			opts:     Options{SigningConfigBytes: []byte("x"), SigningConfigPath: "/y"},
			wantKind: "file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewSigningConfigResolver(tt.opts, logger.NewNoop())
			require.NoError(t, err)
			require.NotNil(t, r)
			switch tt.wantKind {
			case "nil":
				_, ok := r.(nilSigningConfigResolver)
				assert.True(t, ok, "expected nilSigningConfigResolver, got %T", r)
			case "file":
				_, ok := r.(*fileSigningConfigResolver)
				assert.True(t, ok, "expected *fileSigningConfigResolver, got %T", r)
			case "tuf":
				_, ok := r.(*tufSigningConfigResolver)
				assert.True(t, ok, "expected *tufSigningConfigResolver, got %T", r)
			}
		})
	}
}

// Precedence: bytes must take precedence over path in file mode.
func TestNewSigningConfigResolver_BytesPreferredOverPath(t *testing.T) {
	r, err := NewSigningConfigResolver(Options{
		SigningConfigBytes: []byte(minimalSigningConfigJSON),
		SigningConfigPath:  "/does/not/exist.json",
	}, logger.NewNoop())
	require.NoError(t, err)
	fr, ok := r.(*fileSigningConfigResolver)
	require.True(t, ok)
	// If bytes did not win, Resolve would try the bogus path and fail.
	sc, err := fr.Resolve(context.Background())
	require.NoError(t, err)
	require.NotNil(t, sc)
}

func TestNilSigningConfigResolver_ReturnsNil(t *testing.T) {
	r := nilSigningConfigResolver{}
	sc, err := r.Resolve(context.Background())
	require.NoError(t, err)
	assert.Nil(t, sc)
}

func TestFileSigningConfigResolver_Bytes(t *testing.T) {
	r := &fileSigningConfigResolver{bytes: []byte(minimalSigningConfigJSON)}
	sc, err := r.Resolve(context.Background())
	require.NoError(t, err)
	require.NotNil(t, sc)
	assert.Equal(t, "https://fulcio.example.com", sc.FulcioCertificateAuthorityURLs()[0].URL)
	assert.Equal(t, "https://rekor.example.com", sc.RekorLogURLs()[0].URL)
	assert.Equal(t, "https://tsa.example.com", sc.TimestampAuthorityURLs()[0].URL)
}

func TestFileSigningConfigResolver_Path(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sc.json")
	require.NoError(t, os.WriteFile(path, []byte(minimalSigningConfigJSON), 0o600))

	r := &fileSigningConfigResolver{path: path}
	sc, err := r.Resolve(context.Background())
	require.NoError(t, err)
	require.NotNil(t, sc)
}

func TestFileSigningConfigResolver_MissingPath(t *testing.T) {
	r := &fileSigningConfigResolver{path: "/does/not/exist.json"}
	_, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load signing config")
}

func TestFileSigningConfigResolver_MalformedBytes(t *testing.T) {
	r := &fileSigningConfigResolver{bytes: []byte(`{ not json`)}
	_, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse signing config bytes")
}
