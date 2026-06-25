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

package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	jwtclient "github.com/thomsonreuters/stamp/pkg/clients/jwt"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/logger"
	jwtpredicate "github.com/thomsonreuters/stamp/pkg/predicates/jwt/v1"
)

func TestID(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "jwt", attestor.ID())
}

func TestName(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "JWT Token Attestor", attestor.Name())
}

func TestDescription(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Contains(t, attestor.Description(), "JWT tokens")
}

func TestPredicateURI(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, jwtpredicate.PredicateURI, attestor.PredicateURI())
}

func TestConfigSchema(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	schema := attestor.ConfigSchema()

	require.NotEmpty(t, schema)

	fieldNames := make(map[string]bool)
	for _, field := range schema {
		fieldNames[field.Name] = true
	}

	expectedFields := []string{
		"jwt-token-file",
		"jwt-from-stdin",
		"jwt-from-env",
		"jwt-auto-discover-github",
		"jwt-auto-discover-aws",
		"jwt-auto-discover-kubernetes",
		"jwt-expected-audience",
		"jwt-jwks-url",
		"jwt-oidc-discovery-url",
		"jwt-public-key-file",
		"jwt-ca-cert",
		"jwt-allowed-algorithms",
		"jwt-denied-algorithms",
		"jwt-skip-verification",
		"jwt-include-all-claims",
		"jwt-claims-allowlist",
		"jwt-claims-denylist",
		"jwt-redact-claims",
	}

	for _, expected := range expectedFields {
		assert.True(t, fieldNames[expected], "Expected field %s to be in schema", expected)
	}
}

func TestConfigSchemaFieldTypes(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	schema := attestor.ConfigSchema()

	for _, field := range schema {
		assert.NotEmpty(t, field.Name)
		assert.NotEmpty(t, field.Type)
		assert.NotEmpty(t, field.Description)

		switch field.Name {
		case "jwt-token-file":
			assert.Equal(t, "string", field.Type)
		case "jwt-from-stdin":
			assert.Equal(t, "bool", field.Type)
		case "jwt-skip-verification":
			assert.Equal(t, "bool", field.Type)
		case "jwt-include-all-claims":
			assert.Equal(t, "bool", field.Type)
			assert.Equal(t, true, field.Default)
		case "jwt-allowed-algorithms":
			assert.Equal(t, "[]string", field.Type)
		}
	}
}

func TestSchema(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	schema := attestor.Schema()

	require.NotNil(t, schema)
	assert.Equal(t, "object", schema.Type)
	assert.NotNil(t, schema.Properties)
}

func TestPostAttest(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	err := attestor.PostAttest(t.Context(), core.Config{})
	assert.NoError(t, err)
}

func TestGeneratePredicate_NilPredicate(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	_, err := attestor.GeneratePredicate(core.Config{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Attest not called")
}

func TestGeneratePredicate_Success(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		predicate: &jwtpredicate.Predicate{
			Source:       "file:test.jwt",
			Verification: VerificationVerified,
		},
	}

	pred, err := attestor.GeneratePredicate(core.Config{})

	require.NoError(t, err)
	require.NotNil(t, pred)

	p, ok := pred.(*jwtpredicate.Predicate)
	require.True(t, ok)
	assert.Equal(t, "file:test.jwt", p.Source)
	assert.Equal(t, VerificationVerified, p.Verification)
}

func TestSubjects_EmptyToken(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	subjects := attestor.Subjects(core.Config{})
	assert.Empty(t, subjects)
}

func TestSubjects_WithToken(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		token:  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXN1YmplY3QifQ.sig",
		parsedClaims: jwtpredicate.JWTClaims{
			Subject: "test-subject",
		},
	}

	subjects := attestor.Subjects(core.Config{})

	require.Len(t, subjects, 1)
	assert.Equal(t, "test-subject", subjects[0].Name)
	assert.Contains(t, subjects[0].Digest, "sha256")
}

func TestSubjects_NoSubjectClaim(t *testing.T) {
	attestor := &Attestor{
		logger:       logger.NewNoop(),
		token:        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0In0.sig",
		parsedClaims: jwtpredicate.JWTClaims{},
	}

	subjects := attestor.Subjects(core.Config{})

	require.Len(t, subjects, 1)
	assert.Equal(t, "jwt:no-subject-claim", subjects[0].Name)
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   core.Config
		expected Config
	}{
		{
			name: "all fields",
			config: core.Config{
				"jwt-token-file":               "/path/to/token",
				"jwt-from-stdin":               true,
				"jwt-from-env":                 "JWT_TOKEN",
				"jwt-auto-discover-github":     true,
				"jwt-auto-discover-aws":        true,
				"jwt-auto-discover-kubernetes": true,
				"jwt-expected-audience":        []string{"https://example.com"},
				"jwt-jwks-url":                 "https://example.com/.well-known/jwks.json",
				"jwt-oidc-discovery-url":       "https://example.com/.well-known/openid-configuration",
				"jwt-public-key-file":          "/path/to/key.pem",
				"jwt-ca-cert":                  "/path/to/ca.pem",
				"jwt-skip-verification":        true,
				"jwt-allowed-algorithms":       []string{"RS256", "ES256"},
				"jwt-denied-algorithms":        []string{"none"},
				"jwt-include-all-claims":       false,
				"jwt-claims-allowlist":         []string{"custom1"},
				"jwt-claims-denylist":          []string{"internal"},
				"jwt-redact-claims":            []string{"email"},
			},
			expected: Config{
				TokenFile:          "/path/to/token",
				FromStdin:          true,
				FromEnv:            "JWT_TOKEN",
				AutoDiscoverGitHub: true,
				AutoDiscoverAWS:    true,
				AutoDiscoverK8s:    true,
				ExpectedAudience:   []string{"https://example.com"},
				JWKSURL:            "https://example.com/.well-known/jwks.json",
				OIDCDiscoveryURL:   "https://example.com/.well-known/openid-configuration",
				PublicKeyFile:      "/path/to/key.pem",
				CACert:             "/path/to/ca.pem",
				SkipVerification:   true,
				AllowedAlgorithms:  []string{"RS256", "ES256"},
				DeniedAlgorithms:   []string{"none"},
				IncludeAllClaims:   false,
				ClaimsAllowlist:    []string{"custom1"},
				ClaimsDenylist:     []string{"internal"},
				RedactClaims:       []string{"email"},
			},
		},
		{
			name:   "empty config uses defaults",
			config: core.Config{},
			expected: Config{
				IncludeAllClaims: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{logger: logger.NewNoop()}
			attestor.parseConfig(tt.config)

			assert.Equal(t, tt.expected.TokenFile, attestor.config.TokenFile)
			assert.Equal(t, tt.expected.FromStdin, attestor.config.FromStdin)
			assert.Equal(t, tt.expected.FromEnv, attestor.config.FromEnv)
			assert.Equal(t, tt.expected.AutoDiscoverGitHub, attestor.config.AutoDiscoverGitHub)
			assert.Equal(t, tt.expected.AutoDiscoverAWS, attestor.config.AutoDiscoverAWS)
			assert.Equal(t, tt.expected.AutoDiscoverK8s, attestor.config.AutoDiscoverK8s)
			assert.Equal(t, tt.expected.SkipVerification, attestor.config.SkipVerification)
			assert.Equal(t, tt.expected.IncludeAllClaims, attestor.config.IncludeAllClaims)
		})
	}
}

func TestBuildClientOptions(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			JWKSURL:           "https://example.com/jwks",
			OIDCDiscoveryURL:  "https://example.com/oidc",
			PublicKeyFile:     "/path/to/key.pem",
			CACert:            "/path/to/ca.pem",
			AllowedAlgorithms: []string{"RS256"},
			DeniedAlgorithms:  []string{"none"},
		},
	}

	opts := attestor.buildClientOptions()
	assert.NotEmpty(t, opts)
}

func TestBuildClientOptions_Empty(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		config: Config{},
	}

	opts := attestor.buildClientOptions()
	assert.NotEmpty(t, opts)
}

func TestAttestorInterfaceCompliance(t *testing.T) {
	var _ core.Attestor = (*Attestor)(nil)
}

func TestPreAttest(t *testing.T) {
	jwtclient.SetupMockClient(t)

	attestor := &Attestor{logger: logger.NewNoop()}
	config := core.Config{
		"jwt-token-file": "/path/to/token",
	}

	err := attestor.PreAttest(t.Context(), config)
	require.NoError(t, err)
	assert.NotNil(t, attestor.jwtClient)
}
