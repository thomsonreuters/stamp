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

// Package jwt provides comprehensive JWT token attestation for generating
// attestations about JWT tokens used in build and deployment processes within
// the software supply chain.

package jwt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/invopop/jsonschema"
	jwtclient "github.com/thomsonreuters/stamp/pkg/clients/jwt"
	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	jwtpredicate "github.com/thomsonreuters/stamp/pkg/predicates/jwt/v1"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

func init() {
	_ = core.RegisterAttestor(func(log logger.Logger) core.Attestor {
		return &Attestor{
			logger: log.With("attestor_id", attestorID),
		}
	})
}

// Config holds parsed configuration values for the JWT attestor.
type Config struct {
	// Token Sources
	TokenFile          string
	FromStdin          bool
	FromEnv            string
	AutoDiscoverGitHub bool
	AutoDiscoverAWS    bool
	AutoDiscoverK8s    bool
	ExpectedAudience   []string

	// Key Sources
	JWKSURL          string
	OIDCDiscoveryURL string
	PublicKeyFile    string
	CACert           string

	// Verification
	SkipVerification  bool
	AllowedAlgorithms []string
	DeniedAlgorithms  []string

	// Claims
	IncludeAllClaims bool
	ClaimsAllowlist  []string
	ClaimsDenylist   []string
	RedactClaims     []string
}

// Attestor implements the core.Attestor interface for JWT token attestation.
// It collects JWT token information, verifies signatures, and generates attestation
// predicates containing token metadata, claims, and verification results.
//
// The attestor maintains token data across the attestation lifecycle:
//   - token: The raw JWT token string
//   - tokenSource: How the token was obtained (file, stdin, env, etc.)
//   - parsedClaims: Parsed JWT claims for subject generation
//   - predicate: Generated attestation predicate with complete token information
//
// Token acquisition methods (priority order):
//  1. Static file (jwt-token-file)
//  2. Standard input (jwt-from-stdin)
//  3. Environment variable (jwt-from-env)
//  4. Auto-discovery (GitHub Actions, AWS IRSA, Kubernetes)
//
// Verification methods (priority order):
//  1. Static public key (jwt-public-key-file)
//  2. Explicit JWKS URL (jwt-jwks-url)
//  3. Explicit OIDC discovery (jwt-oidc-discovery-url)
//  4. Auto-discovery from token issuer (iss claim)
//  5. Skip verification (jwt-skip-verification)
type Attestor struct {
	logger    logger.Logger
	jwtClient jwtclient.ClientIface
	config    Config

	token string

	tokenSource string

	parsedClaims jwtpredicate.JWTClaims

	predicate *jwtpredicate.Predicate
}

func (a *Attestor) parseConfig(config core.Config) {
	a.config = Config{
		// Token Sources
		TokenFile:          config.GetString("jwt-token-file", ""),
		FromStdin:          config.GetBool("jwt-from-stdin", false),
		FromEnv:            config.GetString("jwt-from-env", ""),
		AutoDiscoverGitHub: config.GetBool("jwt-auto-discover-github", false),
		AutoDiscoverAWS:    config.GetBool("jwt-auto-discover-aws", false),
		AutoDiscoverK8s:    config.GetBool("jwt-auto-discover-kubernetes", false),
		ExpectedAudience:   config.GetStringSlice("jwt-expected-audience"),

		// Key Sources
		JWKSURL:          config.GetString("jwt-jwks-url", ""),
		OIDCDiscoveryURL: config.GetString("jwt-oidc-discovery-url", ""),
		PublicKeyFile:    config.GetString("jwt-public-key-file", ""),
		CACert:           config.GetString("jwt-ca-cert", ""),

		// Verification
		SkipVerification:  config.GetBool("jwt-skip-verification", false),
		AllowedAlgorithms: config.GetStringSlice("jwt-allowed-algorithms"),
		DeniedAlgorithms:  config.GetStringSlice("jwt-denied-algorithms"),

		// Claims
		IncludeAllClaims: config.GetBool("jwt-include-all-claims", true),
		ClaimsAllowlist:  config.GetStringSlice("jwt-claims-allowlist"),
		ClaimsDenylist:   config.GetStringSlice("jwt-claims-denylist"),
		RedactClaims:     config.GetStringSlice("jwt-redact-claims"),
	}
}

func (a *Attestor) buildClientOptions() []jwtclient.Option {
	opts := []jwtclient.Option{
		jwtclient.WithLogger(a.logger),
	}

	if a.config.JWKSURL != "" {
		opts = append(opts, jwtclient.WithJWKSURL(a.config.JWKSURL))
	}
	if a.config.OIDCDiscoveryURL != "" {
		opts = append(opts, jwtclient.WithOIDCDiscoveryURL(a.config.OIDCDiscoveryURL))
	}
	if a.config.PublicKeyFile != "" {
		opts = append(opts, jwtclient.WithPublicKeyFile(a.config.PublicKeyFile))
	}
	if a.config.CACert != "" {
		opts = append(opts, jwtclient.WithCACertFile(a.config.CACert))
	}
	if len(a.config.AllowedAlgorithms) > 0 {
		opts = append(opts, jwtclient.WithAllowedAlgorithms(a.config.AllowedAlgorithms))
	}
	if len(a.config.DeniedAlgorithms) > 0 {
		opts = append(opts, jwtclient.WithDeniedAlgorithms(a.config.DeniedAlgorithms))
	}

	return opts
}

// ID returns the unique identifier for this attestor ("jwt").
func (a *Attestor) ID() string { return attestorID }

// PredicateURI returns the custom JWT predicate type URI.
func (a *Attestor) PredicateURI() string { return jwtpredicate.PredicateURI }

// Name returns the human-readable name of this attestor.
func (a *Attestor) Name() string { return attestorName }

// Description returns a brief description of what this attestor does.
func (a *Attestor) Description() string { return attestorDesc }

// ConfigSchema returns the configuration schema for this attestor.
func (a *Attestor) ConfigSchema() []core.ConfigField {
	return []core.ConfigField{
		// Token Sources (mutually exclusive)
		{
			Name:        "jwt-token-file",
			Type:        "string",
			Default:     "",
			Required:    false,
			Description: "Path to file containing JWT token",
			Example:     "/var/run/secrets/token",
		},
		{
			Name:        "jwt-from-stdin",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Read JWT token from stdin",
			Example:     true,
		},
		{
			Name:        "jwt-from-env",
			Type:        "string",
			Default:     "",
			Required:    false,
			Description: "Environment variable name containing JWT token",
			Example:     "BUILD_TOKEN",
		},
		{
			Name:        "jwt-auto-discover-github",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Auto-discover GitHub Actions OIDC token",
			Example:     true,
		},
		{
			Name:        "jwt-auto-discover-aws",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Auto-discover AWS IRSA/EKS token",
			Example:     true,
		},
		{
			Name:        "jwt-auto-discover-kubernetes",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Auto-discover Kubernetes service account token",
			Example:     true,
		},
		{
			Name:        "jwt-expected-audience",
			Type:        "[]string",
			Default:     []string{},
			Required:    false,
			Description: "Expected audience for OIDC token requests (used with auto-discovery)",
			Example:     []string{"https://github.com"},
		},

		// JWKS Configuration
		{
			Name:        "jwt-jwks-url",
			Type:        "string",
			Default:     "",
			Required:    false,
			Description: "JWKS endpoint URL (overrides auto-discovery)",
			Example:     "https://auth.company.com/.well-known/jwks.json",
		},
		{
			Name:        "jwt-oidc-discovery-url",
			Type:        "string",
			Default:     "",
			Required:    false,
			Description: "OIDC discovery endpoint URL",
			Example:     "https://auth.company.com/.well-known/openid-configuration",
		},
		{
			Name:        "jwt-public-key-file",
			Type:        "string",
			Default:     "",
			Required:    false,
			Description: "Static public key file in PEM format",
			Example:     "/etc/certs/public-key.pem",
		},
		{
			Name:        "jwt-ca-cert",
			Type:        "string",
			Default:     "",
			Required:    false,
			Description: "CA certificate for JWKS endpoint TLS verification",
			Example:     "/etc/ssl/certs/ca.pem",
		},

		// Algorithm Filtering (optional - policy enforcement typically done at verification time)
		{
			Name:        "jwt-allowed-algorithms",
			Type:        "[]string",
			Default:     []string{},
			Required:    false,
			Description: "Optional: Allowed JWT signing algorithms (empty = allow all). Policy enforcement typically done at verification time.",
			Example:     []string{"RS256", "ES256"},
		},
		{
			Name:        "jwt-denied-algorithms",
			Type:        "[]string",
			Default:     []string{},
			Required:    false,
			Description: "Optional: Explicitly denied algorithms (overrides allowlist). Policy enforcement typically done at verification time.",
			Example:     []string{"none", "HS256"},
		},

		// Signature Verification
		{
			Name:        "jwt-skip-verification",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Skip JWT signature verification entirely (verification='skipped')",
			Example:     true,
		},

		// Output Configuration
		{
			Name:        "jwt-include-all-claims",
			Type:        "bool",
			Default:     true,
			Required:    false,
			Description: "Include all JWT claims in predicate",
			Example:     false,
		},
		{
			Name:        "jwt-claims-allowlist",
			Type:        "[]string",
			Default:     []string{},
			Required:    false,
			Description: "Only include these custom claims (standard claims always included)",
			Example:     []string{"groups", "roles", "permissions"},
		},
		{
			Name:        "jwt-claims-denylist",
			Type:        "[]string",
			Default:     []string{},
			Required:    false,
			Description: "Exclude these custom claims from output (standard claims always included)",
			Example:     []string{"internal_id", "debug_info"},
		},
		{
			Name:        "jwt-redact-claims",
			Type:        "[]string",
			Default:     []string{},
			Required:    false,
			Description: "Custom claims to redact (replaced with [REDACTED])",
			Example:     []string{"email", "phone", "address"},
		},
	}
}

// ValidateConfig validates the configuration for the JWT attestor.
func (a *Attestor) ValidateConfig(config core.Config) error {
	if err := config.Validate(a.ConfigSchema()); err != nil {
		return err
	}
	a.parseConfig(config)

	if err := a.validateTokenSource(); err != nil {
		return err
	}
	if err := a.validateFilePaths(); err != nil {
		return err
	}
	if err := a.validateAlgorithms(); err != nil {
		return err
	}
	if err := a.validateClaimsFiltering(); err != nil {
		return err
	}

	return nil
}

// PreAttest performs pre-attestation setup and initialization.
func (a *Attestor) PreAttest(ctx context.Context, config core.Config) error {
	a.parseConfig(config)

	client, err := jwtclient.New(ctx, a.buildClientOptions()...)
	if err != nil {
		return pkgerrors.WrapWithContext(err, attestorID, "init", "failed to create JWT client")
	}
	a.jwtClient = client

	return nil
}

// Attest performs the main attestation logic by acquiring and validating the JWT token.
func (a *Attestor) Attest(ctx context.Context, config core.Config) error {
	predicate, err := a.collectData(ctx, config)
	if err != nil {
		return pkgerrors.WrapWithContext(err, attestorID, "attest", "JWT attestation failed")
	}
	a.predicate = predicate

	return nil
}

// PostAttest performs post-attestation cleanup and finalization.
func (a *Attestor) PostAttest(ctx context.Context, config core.Config) error {
	return nil
}

// GeneratePredicate generates the JWT attestation predicate with dynamic configuration-based filtering.

func (a *Attestor) GeneratePredicate(config core.Config) (any, error) {
	if a.predicate == nil {
		return nil, pkgerrors.NewWithContext(attestorID, "predicate", "predicate not generated (Attest not called)")
	}
	return a.predicate, nil
}

// Subjects returns the subjects for this attestation following in-toto specification.

func (a *Attestor) Subjects(config core.Config) []intoto.Subject {
	if a.token == "" {
		return []intoto.Subject{}
	}

	tokenHash := sha256.Sum256([]byte(a.token))
	subjectName := a.parsedClaims.Subject
	if subjectName == "" {
		subjectName = "jwt:no-subject-claim"
	}

	return []intoto.Subject{{
		Name:   subjectName,
		Digest: map[string]string{"sha256": hex.EncodeToString(tokenHash[:])},
	}}
}

// Schema returns the JSON schema for this attestor's configuration.

func (a *Attestor) Schema() *jsonschema.Schema {
	schema := &jsonschema.Schema{
		Type:       "object",
		Properties: jsonschema.NewProperties(),
		Required:   []string{},
	}

	for _, field := range a.ConfigSchema() {
		var fieldSchema *jsonschema.Schema

		switch field.Type {
		case "string":
			fieldSchema = &jsonschema.Schema{Type: "string", Description: field.Description, Default: field.Default}
		case "bool", "boolean":
			fieldSchema = &jsonschema.Schema{Type: "boolean", Description: field.Description, Default: field.Default}
		case "int":
			fieldSchema = &jsonschema.Schema{Type: "integer", Description: field.Description, Default: field.Default}
		case "[]string":
			fieldSchema = &jsonschema.Schema{
				Type:        "array",
				Description: field.Description,
				Items:       &jsonschema.Schema{Type: "string"},
				Default:     field.Default,
			}
			if field.Name == "jwt-allowed-algorithms" || field.Name == "jwt-denied-algorithms" {
				fieldSchema.Items.Enum = utils.ToAnySlice(SupportedAlgorithms)
			}
		}

		if fieldSchema != nil {
			schema.Properties.Set(field.Name, fieldSchema)
		}
		if field.Required {
			schema.Required = append(schema.Required, field.Name)
		}
	}

	return schema
}
