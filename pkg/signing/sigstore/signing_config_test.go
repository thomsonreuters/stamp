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

package sigstore

import (
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	"github.com/thomsonreuters/stamp/pkg/types"
)

const testSigningConfigJSON = `{
  "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
  "caUrls": [
    { "url": "https://fulcio.example.com", "majorApiVersion": 1,
      "validFor": { "start": "2020-01-01T00:00:00Z" }, "operator": "example.com" }
  ],
  "oidcUrls": [
    { "url": "https://oidc.example.com", "majorApiVersion": 1,
      "validFor": { "start": "2020-01-01T00:00:00Z" }, "operator": "example.com" }
  ],
  "rekorTlogUrls": [
    { "url": "https://rekor.example.com", "majorApiVersion": 1,
      "validFor": { "start": "2020-01-01T00:00:00Z" }, "operator": "example.com" }
  ],
  "tsaUrls": [
    { "url": "https://tsa.example.com", "majorApiVersion": 1,
      "validFor": { "start": "2020-01-01T00:00:00Z" }, "operator": "example.com" }
  ],
  "rekorTlogConfig": { "selector": "ANY" },
  "tsaConfig":       { "selector": "ANY" }
}`

func mustSC(t *testing.T) *root.SigningConfig {
	sc, err := root.NewSigningConfigFromJSON([]byte(testSigningConfigJSON))
	require.NoError(t, err)
	return sc
}

func TestHasExplicitServiceURL(t *testing.T) {
	tests := []struct {
		name         string
		signer       string
		fulcioURLSet bool
		transparency bool
		rekorURLSet  bool
		tsaURLSet    bool
		want         bool
	}{
		{"nothing set", "key", false, false, false, false, false},
		{"fulcio URL set with fulcio signer", "fulcio", true, false, false, false, true},
		{"fulcio URL set but signer=key", "key", true, false, false, false, false},
		{"rekor URL set with transparency on", "key", false, true, true, false, true},
		{"rekor URL set but transparency off", "key", false, false, true, false, false},
		{"tsa URL set", "key", false, false, false, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.NewMockConfiguration()
			cfg.On("GetString", flags.Signer).Return(tt.signer).Maybe()
			cfg.On("GetBool", flags.TransparencyEnable).Return(tt.transparency).Maybe()
			cfg.On("IsSet", flags.FulcioURL).Return(tt.fulcioURLSet).Maybe()
			cfg.On("IsSet", flags.RekorURL).Return(tt.rekorURLSet).Maybe()
			cfg.On("IsSet", flags.TSAURL).Return(tt.tsaURLSet).Maybe()

			assert.Equal(t, tt.want, hasExplicitServiceURL(cfg))
		})
	}
}

func TestResolveEffectiveURLs_NoSigningConfig(t *testing.T) {
	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.FulcioURL).Return("https://fulcio.example.com")
	cfg.On("GetString", flags.RekorURL).Return("https://rekor.example.com")
	cfg.On("GetString", flags.TSAURL).Return("https://timestamp.example.com")
	cfg.On("GetInt", flags.RekorVersion).Return(1)

	urls, err := resolveEffectiveURLs(cfg, nil)
	require.NoError(t, err)
	assert.Equal(t, "https://fulcio.example.com", urls.fulcio)
	assert.Equal(t, "https://rekor.example.com", urls.rekor)
	assert.Equal(t, "https://timestamp.example.com", urls.tsa)
	assert.Equal(t, uint32(1), urls.rekorVersion)
}

func TestResolveEffectiveURLs_WithSigningConfig(t *testing.T) {
	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.FulcioURL).Return(flags.DefaultFulcioURL)
	cfg.On("GetString", flags.RekorURL).Return(flags.DefaultRekorURL)
	cfg.On("GetString", flags.TSAURL).Return("")
	cfg.On("GetInt", flags.RekorVersion).Return(1)

	urls, err := resolveEffectiveURLs(cfg, mustSC(t))
	require.NoError(t, err)
	assert.Equal(t, "https://fulcio.example.com", urls.fulcio)
	assert.Equal(t, "https://rekor.example.com", urls.rekor)
}

func TestResolveEffectiveURLs_RekorV2_RequestedButSCOnlyV1(t *testing.T) {
	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.FulcioURL).Return(flags.DefaultFulcioURL)
	cfg.On("GetString", flags.RekorURL).Return(flags.DefaultRekorURL)
	cfg.On("GetString", flags.TSAURL).Return("")
	cfg.On("GetInt", flags.RekorVersion).Return(2)

	_, err := resolveEffectiveURLs(cfg, mustSC(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rekor URL (v2)")
}

func TestResolveEffectiveURLs_RekorV2_AutoTSAFromSC(t *testing.T) {
	scJSON := `{
  "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
  "caUrls":        [{"url":"https://fulcio.v2.example.com","majorApiVersion":1,"validFor":{"start":"2020-01-01T00:00:00Z"},"operator":"example.com"}],
  "oidcUrls":      [{"url":"https://oidc.v2.example.com","majorApiVersion":1,"validFor":{"start":"2020-01-01T00:00:00Z"},"operator":"example.com"}],
  "rekorTlogUrls": [{"url":"https://rekor.v2.example.com","majorApiVersion":2,"validFor":{"start":"2020-01-01T00:00:00Z"},"operator":"example.com"}],
  "tsaUrls":       [{"url":"https://tsa.v2.example.com","majorApiVersion":1,"validFor":{"start":"2020-01-01T00:00:00Z"},"operator":"example.com"}],
  "rekorTlogConfig": {"selector":"ANY"},
  "tsaConfig":       {"selector":"ANY"}
}`
	sc, err := root.NewSigningConfigFromJSON([]byte(scJSON))
	require.NoError(t, err)

	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.FulcioURL).Return(flags.DefaultFulcioURL)
	cfg.On("GetString", flags.RekorURL).Return(flags.DefaultRekorURL)
	cfg.On("GetString", flags.TSAURL).Return("")
	cfg.On("GetInt", flags.RekorVersion).Return(2)

	urls, err := resolveEffectiveURLs(cfg, sc)
	require.NoError(t, err)
	assert.Equal(t, "https://rekor.v2.example.com", urls.rekor)
	assert.Equal(t, uint32(2), urls.rekorVersion)
	assert.Equal(t, "https://tsa.v2.example.com", urls.tsa)
}

// Sanity: types package referenced only for its constants.
var _ = types.SignerFulcio
