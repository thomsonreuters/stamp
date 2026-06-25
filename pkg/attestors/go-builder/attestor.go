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

// Package gobuilder provides a Go builder attestor that generates provenance
// attestations for Go binary builds in GitHub Actions/EC2 environments. It collects
// build configuration, environment context, and resolved dependencies to produce
// a provenance predicate for the built artifact.
package gobuilder

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/thomsonreuters/stamp/pkg/buildenv"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/executor"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	gobuilderpredicate "github.com/thomsonreuters/stamp/pkg/predicates/go-builder/v1"
)

func init() {
	_ = core.RegisterAttestor(func(log logger.Logger) core.Attestor {
		return &Attestor{
			logger:   log.With("attestor_id", id),
			executor: executor.NewOSCommandExecutor(),
		}
	})
}

type Config struct {
	ConfigFile    string
	ConfigVersion int
	BinaryPath    string
	BinaryName    string
	GoCommand     []string
	GoEnv         []string
	WorkingDir    string
	CaptureEvent  bool
}

type Attestor struct {
	logger         logger.Logger
	executor       executor.CommandExecutor
	config         Config
	buildEnv       buildenv.BuildEnvironment
	binaryDigest   string
	sourceURI      string
	builderID      string
	internalParams map[string]any
	resolvedDeps   []gobuilderpredicate.ResourceDescriptor
	workflowInputs any
	metadata       gobuilderpredicate.Metadata
	configDigest   string
	byproducts     []gobuilderpredicate.ResourceDescriptor
	// buildEnvDetector allows injecting a custom build environment detector for testing
	buildEnvDetector func(ctx context.Context, log logger.Logger, opts buildenv.DetectOptions) (buildenv.BuildEnvironment, error)
}

func (a *Attestor) ID() string           { return id }
func (a *Attestor) PredicateURI() string { return gobuilderpredicate.PredicateURI }
func (a *Attestor) Name() string         { return name }
func (a *Attestor) Description() string  { return description }

func (a *Attestor) ConfigSchema() []core.ConfigField {
	return []core.ConfigField{
		{
			Name:        "build-config",
			Type:        "string",
			Default:     "",
			Required:    true,
			Description: "Path to .slsa-goreleaser.yml build config file (required - defines the build specification)",
			Example:     ".slsa-goreleaser.yml",
		},

		{
			Name:        "capture-event-payload",
			Type:        "bool",
			Default:     true,
			Required:    false,
			Description: "Include CI event payload in internal parameters (GitHub Actions only)",
			Example:     false,
		},
	}
}

func (a *Attestor) ValidateConfig(config core.Config) error {
	if config.IsEmpty("build-config") {
		return errors.New("build-config is required")
	}
	return nil
}

func (a *Attestor) PreAttest(ctx context.Context, config core.Config) error {
	start := time.Now()
	a.logger.InfoContext(ctx, "starting Go Builder attestor pre-attestation setup")

	if err := a.parseConfig(config); err != nil {
		return fmt.Errorf("parsing configuration: %w", err)
	}

	a.logger.InfoContext(ctx, "Go Builder attestor pre-attestation setup completed",
		"duration_ms", time.Since(start).Milliseconds())
	return nil
}

func (a *Attestor) Attest(ctx context.Context, config core.Config) error {
	start := time.Now()
	a.logger.InfoContext(ctx, "starting Go Builder attestation collection")

	if err := a.collectAllData(ctx); err != nil {
		a.logger.ErrorContext(ctx, "Go Builder information collection failed", "error", err.Error())
		return err
	}

	a.metadata.FinishedOn = time.Now().UTC().Format(time.RFC3339)

	a.logger.InfoContext(ctx, "Go Builder attestation collection completed",
		"binary", a.config.BinaryName,
		"digest", a.binaryDigest,
		"environment", a.buildEnv.Type(),
		"duration_ms", time.Since(start).Milliseconds())
	return nil
}

func (a *Attestor) PostAttest(_ context.Context, _ core.Config) error {
	return nil
}

func (a *Attestor) GeneratePredicate(_ core.Config) (any, error) {
	start := time.Now()
	a.logger.Info("generating Go Builder provenance predicate",
		"binary", a.config.BinaryName,
		"environment", a.buildEnv.Type())

	byproducts := a.byproducts
	if byproducts == nil {
		byproducts = []gobuilderpredicate.ResourceDescriptor{}
	}

	predicate := gobuilderpredicate.Predicate{
		BuildDefinition: gobuilderpredicate.BuildDefinition{
			BuildType: BuildTypeGolang,
			ExternalParameters: gobuilderpredicate.ExternalParameters{
				Source:            a.sourceURI,
				BuildConfigSource: a.config.ConfigFile,
				Inputs:            a.workflowInputs,
			},
			InternalParameters:   a.internalParams,
			ResolvedDependencies: a.resolvedDeps,
		},
		RunDetails: gobuilderpredicate.RunDetails{
			Builder: gobuilderpredicate.Builder{
				ID:                  a.builderID,
				BuilderDependencies: []gobuilderpredicate.ResourceDescriptor{},
				Version:             map[string]string{},
			},
			Metadata:   a.metadata,
			Byproducts: byproducts,
		},
	}

	a.logger.Info("Go Builder provenance predicate generated successfully",
		"predicate_uri", gobuilderpredicate.PredicateURI,
		"environment", a.buildEnv.Type(),
		"duration_ms", time.Since(start).Milliseconds())
	return predicate, nil
}

func (a *Attestor) Subjects(_ core.Config) []intoto.Subject {
	return []intoto.Subject{
		{
			Name: a.config.BinaryName,
			Digest: map[string]string{
				"sha256": a.binaryDigest,
			},
		},
	}
}

func (a *Attestor) Schema() *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		AllowAdditionalProperties:  false,
		RequiredFromJSONSchemaTags: true,
	}
	schema := reflector.Reflect(&gobuilderpredicate.Predicate{})
	schema.Title = "Go Builder Provenance"
	schema.Description = "Provenance predicate for Go binary builds"
	return schema
}
