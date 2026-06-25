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

// Package sbom provides SBOM (Software Bill of Materials) attestation for
// CycloneDX and SPDX documents. It supports automatic format detection,
// optional schema validation, and generates attestations with SHA-256 digests.
package sbom

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/crypto/hash"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	sbompredicate "github.com/thomsonreuters/stamp/pkg/predicates/sbom/v1"
)

const (
	id          = "sbom"
	name        = "SBOM Attestor"
	description = "Generates attestations for Software Bill of Materials (CycloneDX and SPDX)"
)

func init() {
	_ = core.RegisterAttestor(func(logger logger.Logger) core.Attestor {
		return &Attestor{
			logger: logger.With("attestor_id", id),
			hasher: hash.New(hash.Config{
				Algorithms: []string{hash.AlgorithmSHA256},
			}),
		}
	})
}

type Config struct {
	SBOMPath           string             `json:"sbom-path"`
	ValidateSchema     bool               `json:"validate-schema"`
	ValidationBehavior ValidationBehavior `json:"validation-behavior"`
}

// Attestor implements the core.Attestor interface for SBOM attestation.
type Attestor struct {
	logger logger.Logger
	hasher hash.Hasher
	config Config

	sbomPath   string
	sbomDigest string
	predicate  sbompredicate.Predicate
}

func (a *Attestor) ID() string           { return id }
func (a *Attestor) PredicateURI() string { return sbompredicate.PredicateURI }
func (a *Attestor) Name() string         { return name }
func (a *Attestor) Description() string  { return description }
func (a *Attestor) ConfigSchema() []core.ConfigField {
	return []core.ConfigField{
		{
			Name:        "sbom-path",
			Type:        "string",
			Default:     "",
			Required:    true,
			Description: "Path to the SBOM file (CycloneDX or SPDX JSON format)",
			Example:     "/path/to/sbom.json",
		},
		{
			Name:        "validate-schema",
			Type:        "bool",
			Default:     true,
			Required:    false,
			Description: "Validate SBOM against its specification schema before attestation",
			Example:     false,
		},
		{
			Name:        "validation-behavior",
			Type:        "string",
			Default:     "warn",
			Required:    false,
			Description: "How to handle schema validation failures: 'allow' (include invalid SBOM), 'warn' (include with warning log), 'fail' (error and abort)",
			Example:     "fail",
		},
	}
}

func (a *Attestor) parseConfig(config core.Config) {
	a.config = Config{
		SBOMPath:           config.GetString("sbom-path", ""),
		ValidateSchema:     config.GetBool("validate-schema", true),
		ValidationBehavior: ValidationBehavior(config.GetString("validation-behavior", "warn")),
	}
}

// PreAttest resolves and stores the SBOM file path.
func (a *Attestor) PreAttest(ctx context.Context, config core.Config) error {
	start := time.Now()
	a.logger.InfoContext(ctx, "starting SBOM attestor pre-attestation setup")

	a.parseConfig(config)

	absPath, err := filepath.Abs(a.config.SBOMPath)
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "pre-attest",
			"failed to resolve SBOM path to absolute path")
	}
	a.sbomPath = absPath

	a.logger.InfoContext(ctx, "SBOM attestor pre-attestation setup completed",
		"sbom_path", a.sbomPath,
		"duration_ms", time.Since(start).Milliseconds())

	return nil
}

// Attest collects SBOM information including format detection, parsing, and digest calculation.
func (a *Attestor) Attest(ctx context.Context, config core.Config) error {
	start := time.Now()
	a.logger.InfoContext(ctx, "starting SBOM attestation collection")

	if err := a.collectSBOMInformation(ctx, config); err != nil {
		a.logger.ErrorContext(ctx, "SBOM information collection failed", "error", err.Error())
		return err
	}

	a.logger.InfoContext(ctx, "SBOM attestation collection completed",
		"format", a.predicate.Format,
		"version", a.predicate.Version,
		"duration_ms", time.Since(start).Milliseconds())
	return nil
}

// PostAttest performs post-attestation cleanup (no-op for SBOM attestor).
func (a *Attestor) PostAttest(ctx context.Context, config core.Config) error {
	return nil
}

// GeneratePredicate returns the SBOM attestation predicate with format, version, and content.
func (a *Attestor) GeneratePredicate(config core.Config) (any, error) {
	start := time.Now()

	a.logger.Info("generating SBOM attestation predicate")

	if len(a.predicate.Content) == 0 {
		err := errors.New("predicate content is empty - attestation data not collected")
		return nil, pkgerrors.WrapWithContext(err, id, "generate",
			"cannot generate predicate without collected SBOM data")
	}

	if !a.predicate.Format.IsValid() {
		err := fmt.Errorf("invalid SBOM format: %s", a.predicate.Format)
		return nil, pkgerrors.WrapWithContext(err, id, "generate",
			fmt.Sprintf("SBOM format not recognized: %s", a.predicate.Format))
	}

	a.logger.Info("SBOM attestation predicate generated successfully",
		"predicate_uri", sbompredicate.PredicateURI,
		"format", a.predicate.Format,
		"version", a.predicate.Version,
		"content_fields", len(a.predicate.Content),
		"duration_ms", time.Since(start).Milliseconds())

	return a.predicate, nil
}

// Subjects returns the SBOM file as a subject with name "sbom+<filename>" and SHA-256 digest.
func (a *Attestor) Subjects(config core.Config) []intoto.Subject {
	fileName := filepath.Base(a.sbomPath)
	subjectName := fmt.Sprintf("sbom+%s", fileName)

	return []intoto.Subject{{
		Name: subjectName,
		Digest: map[string]string{
			"sha256": a.sbomDigest,
		},
	}}
}

// Schema returns the JSON schema for the SBOM predicate.
func (a *Attestor) Schema() *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		AllowAdditionalProperties:  false,
		RequiredFromJSONSchemaTags: true,
	}

	schema := reflector.Reflect(&sbompredicate.Predicate{})
	schema.Title = "SBOM Attestation"
	schema.Description = "Software Bill of Materials attestation predicate (CycloneDX or SPDX)"

	return schema
}
