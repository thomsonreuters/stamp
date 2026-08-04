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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestNewResolver_Dispatch(t *testing.T) {
	tests := []struct {
		name     string
		opts     Options
		wantKind string // "file", "explicit", "tuf"
		wantErr  error
	}{
		{
			name:     "file mode via TrustedRootPath",
			opts:     Options{TrustedRootPath: "/some/root.json"},
			wantKind: "file",
		},
		{
			name:     "file mode via TrustedRootBytes",
			opts:     Options{TrustedRootBytes: []byte(`{"mediaType":"x"}`)},
			wantKind: "file",
		},
		{
			name: "explicit mode when fulcio cert chain set",
			opts: Options{
				FulcioURL:           "https://fulcio.example.com",
				FulcioCertChainPath: "/tmp/chain.pem",
			},
			wantKind: "explicit",
		},
		{
			name: "explicit mode when rekor pubkey set",
			opts: Options{
				RekorURL:           "https://rekor.example.com",
				RekorPublicKeyPath: "/tmp/rekor.pub",
			},
			wantKind: "explicit",
		},
		{
			name: "explicit mode when tsa cert chain set",
			opts: Options{
				TSAURL:           "https://tsa.example.com",
				TSACertChainPath: "/tmp/tsa.pem",
			},
			wantKind: "explicit",
		},
		{
			name:     "tuf mode when nothing set (defaults to public sigstore)",
			opts:     Options{},
			wantKind: "tuf",
		},
		{
			name:     "tuf mode with explicit URL",
			opts:     Options{TUFURL: "https://tuf.example.com"},
			wantKind: "tuf",
		},
		{
			name: "explicit mode with fulcio URL but no cert chain returns ErrFulcioCertChainRequired",
			opts: Options{
				FulcioURL:          "https://fulcio.example.com",
				RekorPublicKeyPath: "/tmp/rekor.pub", // triggers explicit mode
			},
			wantErr: ErrFulcioCertChainRequired,
		},
		{
			name: "explicit mode with rekor URL but no public key returns ErrRekorKeyRequired",
			opts: Options{
				RekorURL:            "https://rekor.example.com",
				FulcioCertChainPath: "/tmp/chain.pem", // triggers explicit mode
			},
			wantErr: ErrRekorKeyRequired,
		},
		{
			name: "explicit mode with tsa URL but no cert chain returns ErrTSACertRequired",
			opts: Options{
				TSAURL:              "https://tsa.example.com",
				FulcioCertChainPath: "/tmp/chain.pem", // triggers explicit mode
			},
			wantErr: ErrTSACertRequired,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewResolver(tt.opts, logger.NewNoop())
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tt.wantErr), "expected %v, got %v", tt.wantErr, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, r)

			switch tt.wantKind {
			case "file":
				_, ok := r.(*fileResolver)
				assert.True(t, ok, "expected *fileResolver, got %T", r)
			case "explicit":
				_, ok := r.(*explicitResolver)
				assert.True(t, ok, "expected *explicitResolver, got %T", r)
			case "tuf":
				_, ok := r.(*tufResolver)
				assert.True(t, ok, "expected *tufResolver, got %T", r)
			default:
				t.Fatalf("unknown wantKind %q", tt.wantKind)
			}
		})
	}
}

// --trusted-root + --use-signing-config is a legitimate combination.
func TestNewResolver_HybridFileTrustWithTUFSigningConfig(t *testing.T) {
	opts := Options{
		TrustedRootPath:  "/tmp/local-root.json",
		UseSigningConfig: true,
	}
	r, err := NewResolver(opts, logger.NewNoop())
	require.NoError(t, err)
	_, ok := r.(*fileResolver)
	assert.True(t, ok, "trust resolver should be file mode")

	scR, err := NewSigningConfigResolver(opts, logger.NewNoop())
	require.NoError(t, err)
	_, ok = scR.(*tufSigningConfigResolver)
	assert.True(t, ok, "signing-config resolver should be TUF mode")
}

func TestNewResolver_Precedence(t *testing.T) {
	t.Run("file beats explicit when both set", func(t *testing.T) {
		opts := Options{
			TrustedRootPath:     "/tmp/root.json",
			FulcioURL:           "https://fulcio.example.com",
			FulcioCertChainPath: "/tmp/chain.pem",
		}
		r, err := NewResolver(opts, logger.NewNoop())
		require.NoError(t, err)
		_, ok := r.(*fileResolver)
		assert.True(t, ok)
	})

	t.Run("file beats TUF when both set", func(t *testing.T) {
		opts := Options{
			TrustedRootPath: "/tmp/root.json",
			TUFURL:          "https://tuf.example.com",
		}
		r, err := NewResolver(opts, logger.NewNoop())
		require.NoError(t, err)
		_, ok := r.(*fileResolver)
		assert.True(t, ok)
	})

	t.Run("explicit beats TUF when both set", func(t *testing.T) {
		opts := Options{
			FulcioURL:           "https://fulcio.example.com",
			FulcioCertChainPath: "/tmp/chain.pem",
			TUFURL:              "https://tuf.example.com",
		}
		r, err := NewResolver(opts, logger.NewNoop())
		require.NoError(t, err)
		_, ok := r.(*explicitResolver)
		assert.True(t, ok)
	})
}
