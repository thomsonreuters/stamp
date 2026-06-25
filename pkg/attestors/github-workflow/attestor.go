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

// Package githubworkflow provides comprehensive GitHub Actions workflow attestation for generating
// GitHub Actions-specific environment predicates. It collects workflow identification, runner
// environment details, trigger context, and repository state for CI/CD attestation purposes.
package githubworkflow

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/thomsonreuters/stamp/pkg/clients/github"
	jwtclient "github.com/thomsonreuters/stamp/pkg/clients/jwt"
	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	ghworkflowpredicate "github.com/thomsonreuters/stamp/pkg/predicates/github-workflow/v1"
)

const (
	id          = "github-workflow"
	name        = "GitHub Workflow Attestor"
	description = "Generates GitHub Actions workflow attestation with CI/CD environment metadata"
)

func init() {
	_ = core.RegisterAttestor(func(log logger.Logger) core.Attestor {
		return &Attestor{
			logger: log.With("attestor_id", id),
		}
	})
}

// Config holds parsed configuration values for the GitHub Workflow attestor.
type Config struct {
	CaptureEnvironment bool
	EnvIncludePatterns []string
	EnvExcludePatterns []string

	CaptureEventPayload  bool
	RedactEventPayload   bool
	MissingEventBehavior string

	RedactPatterns  []string
	RedactActor     bool
	SensitiveFields []string

	SubjectWorkflowFile bool

	// OIDC token configuration
	OIDCAudience string
}

// Attestor implements core.Attestor for GitHub Actions workflow attestation.
type Attestor struct {
	logger logger.Logger
	config Config

	githubClient github.ClientIface
	jwtClient    jwtclient.ClientIface

	workflowInfo   ghworkflowpredicate.WorkflowInfo
	runnerInfo     ghworkflowpredicate.RunnerInfo
	triggerInfo    ghworkflowpredicate.TriggerInfo
	repositoryInfo ghworkflowpredicate.RepositoryInfo
	metadataInfo   ghworkflowpredicate.MetadataInfo
	oidcInfo       *ghworkflowpredicate.OIDCInfo
	allClaims      map[string]any

	workflowFileSHA  map[string]string
	workflowFilePath string
}

func (a *Attestor) ID() string           { return id }
func (a *Attestor) PredicateURI() string { return ghworkflowpredicate.PredicateURI }
func (a *Attestor) Name() string         { return name }
func (a *Attestor) Description() string  { return description }

// ConfigSchema returns the configuration schema defining all available options.
func (a *Attestor) ConfigSchema() []core.ConfigField {
	return []core.ConfigField{
		{
			Name:        "capture-environment",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Capture environment variables (controlled by include/exclude patterns)",
			Example:     true,
		},
		{
			Name:        "env-include-patterns",
			Type:        "[]string",
			Default:     []string{"GITHUB_*", "RUNNER_*", "CI", "ACTIONS_*"},
			Required:    false,
			Description: "Glob patterns for environment variables to include",
			Example:     []string{"GITHUB_*", "RUNNER_*", "NPM_*"},
		},
		{
			Name:        "env-exclude-patterns",
			Type:        "[]string",
			Default:     []string{"*TOKEN*", "*SECRET*", "*PASSWORD*", "*KEY*", "*CREDENTIAL*", "GITHUB_TOKEN", "GH_TOKEN"},
			Required:    false,
			Description: "Glob patterns for environment variables to exclude (takes precedence over include)",
			Example:     []string{"*TOKEN*", "*SECRET*"},
		},
		{
			Name:        "capture-event-payload",
			Type:        "bool",
			Default:     true,
			Required:    false,
			Description: "Read and include webhook event payload from $GITHUB_EVENT_PATH",
			Example:     false,
		},

		{
			Name:        "redact-event-payload",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Apply built-in and custom redaction patterns to sanitize sensitive values in the event payload while preserving its structure",
			Example:     true,
		},
		{
			Name:        "missing-event-behavior",
			Type:        "string",
			Default:     "warn",
			Required:    false,
			Description: "How to handle missing event payload: 'allow' (continue without), 'warn' (log warning), 'fail' (error out)",
			Example:     "allow",
		},
		{
			Name:        "redact-patterns",
			Type:        "[]string",
			Default:     []string{},
			Required:    false,
			Description: "Additional regex patterns for sanitizing event payload (beyond built-in patterns)",
			Example:     []string{`(?i)internal-token-.*`, `(?i)corp-secret-.*`},
		},
		{
			Name:        "redact-actor",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Redact actor information (user/app that triggered workflow)",
			Example:     true,
		},
		{
			Name:        "sensitive-fields",
			Type:        "[]string",
			Default:     []string{},
			Required:    false,
			Description: "Predicate fields to redact (e.g., 'actor', 'repository.owner', 'trigger.event_payload')",
			Example:     []string{"actor", "repository.owner"},
		},
		{
			Name:        "subject-workflow-file",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Include workflow YAML file as subject (with SHA256 digest from checked-out repo)",
			Example:     true,
		},
		{
			Name:        "oidc-audience",
			Type:        "string",
			Default:     "https://github.com",
			Required:    false,
			Description: "Audience for OIDC token request",
			Example:     "https://your-service.example.com",
		},
	}
}

// parseConfig extracts and normalizes configuration values from core.Config.
func (a *Attestor) parseConfig(config core.Config) {
	a.config = Config{
		CaptureEnvironment: config.GetBool("capture-environment", false),
		EnvIncludePatterns: config.GetStringSlice("env-include-patterns"),
		EnvExcludePatterns: config.GetStringSlice("env-exclude-patterns"),

		CaptureEventPayload:  config.GetBool("capture-event-payload", true),
		RedactEventPayload:   config.GetBool("redact-event-payload", false),
		MissingEventBehavior: config.GetString("missing-event-behavior", MissingEventBehaviorWarn),

		RedactPatterns:  config.GetStringSlice("redact-patterns"),
		RedactActor:     config.GetBool("redact-actor", false),
		SensitiveFields: config.GetStringSlice("sensitive-fields"),

		SubjectWorkflowFile: config.GetBool("subject-workflow-file", false),

		// OIDC configuration
		OIDCAudience: config.GetString("oidc-audience", "https://github.com"),
	}

	if len(a.config.EnvIncludePatterns) == 0 {
		a.config.EnvIncludePatterns = EnvIncludePatterns
	}
	if len(a.config.EnvExcludePatterns) == 0 {
		a.config.EnvExcludePatterns = EnvExcludePatterns
	}
}

// PreAttest performs pre-attestation setup and environment validation.
func (a *Attestor) PreAttest(ctx context.Context, config core.Config) error {
	start := time.Now()
	a.logger.InfoContext(ctx, "starting GitHub Workflow attestor pre-attestation setup")

	a.parseConfig(config)

	ghClient, err := github.New(ctx, github.Options{Logger: a.logger})
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "pre_attest", "failed to initialize GitHub client")
	}
	a.githubClient = ghClient

	jwtClient, err := jwtclient.New(ctx, jwtclient.WithLogger(a.logger))
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "pre_attest", "failed to initialize JWT client")
	}
	a.jwtClient = jwtClient

	a.logger.InfoContext(ctx, "GitHub Workflow attestor pre-attestation setup completed",
		"duration_ms", time.Since(start).Milliseconds())
	return nil
}

// Attest collects all GitHub Actions workflow information.
func (a *Attestor) Attest(ctx context.Context, config core.Config) error {
	start := time.Now()
	a.logger.InfoContext(ctx, "starting GitHub Workflow attestation collection")

	err := a.collectAllData(ctx, config)
	if err != nil {
		a.logger.ErrorContext(ctx, "GitHub Workflow information collection failed", "error", err.Error())
		return err
	}

	a.logger.InfoContext(ctx, "GitHub Workflow attestation collection completed",
		"workflow_run_id", a.getStringClaim("run_id"),
		"repository", a.getStringClaim("repository"),
		"event_name", a.getStringClaim("event_name"),
		"runner_hosted_type", a.getStringClaim("runner_environment"),
		"duration_ms", time.Since(start).Milliseconds())
	return nil
}

// PostAttest performs post-attestation cleanup (no-op for this attestor).
func (a *Attestor) PostAttest(_ context.Context, _ core.Config) error {
	return nil
}

// GeneratePredicate generates the GitHub Workflow predicate with configured redaction.
func (a *Attestor) GeneratePredicate(_ core.Config) (any, error) {
	start := time.Now()
	a.logger.Info("generating GitHub Workflow custom predicate",
		"workflow_run_id", a.getStringClaim("run_id"),
		"repository", a.getStringClaim("repository"))

	predicate := ghworkflowpredicate.Predicate{
		Workflow:   a.workflowInfo,
		Runner:     a.runnerInfo,
		Trigger:    a.triggerInfo,
		Repository: a.repositoryInfo,
		Metadata:   a.metadataInfo,
		OIDC:       a.oidcInfo,
	}

	if a.config.RedactActor {
		predicate.Trigger.Actor = "[REDACTED]"
		predicate.Trigger.ActorID = "[REDACTED]"
	}

	if len(a.config.SensitiveFields) > 0 {
		predicate = a.redactSensitiveFields(predicate, a.config.SensitiveFields)
	}

	a.logger.Info("GitHub Workflow custom predicate generated successfully",
		"predicate_uri", ghworkflowpredicate.PredicateURI,
		"duration_ms", time.Since(start).Milliseconds())
	return predicate, nil
}

// Subjects returns the attestation subjects including the workflow run and optional workflow file.
func (a *Attestor) Subjects(_ core.Config) []intoto.Subject {
	subjects := []intoto.Subject{}

	repository := a.getStringClaim("repository")
	runID := a.getStringClaim("run_id")

	runURI := fmt.Sprintf("github-workflow://%s/runs/%s", repository, runID)

	subjects = append(subjects, intoto.Subject{
		Name: runURI,
		Digest: map[string]string{
			"run_id":      runID,
			"run_attempt": a.getStringClaim("run_attempt"),
			"sha1":        a.getStringClaim("sha"),
		},
	})

	if a.workflowFilePath != "" && len(a.workflowFileSHA) > 0 {
		subjects = append(subjects, intoto.Subject{
			Name: fmt.Sprintf("github-workflow-file://%s/%s",
				repository,
				a.workflowFilePath),
			Digest: a.workflowFileSHA,
		})
	}

	return subjects
}

// Schema returns the JSON schema for the predicate.
func (a *Attestor) Schema() *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		AllowAdditionalProperties:  false,
		RequiredFromJSONSchemaTags: true,
	}
	schema := reflector.Reflect(&ghworkflowpredicate.Predicate{})
	schema.Title = "GitHub Workflow Attestation"
	schema.Description = "Evidence of GitHub Actions workflow execution and metadata"
	return schema
}

// getStringClaim safely retrieves a string value from OIDC claims.
// Returns empty string if the claim doesn't exist or OIDC info is nil.
func (a *Attestor) getStringClaim(key string) string {
	if a.allClaims == nil {
		return ""
	}
	val, ok := a.allClaims[key]
	if !ok {
		return ""
	}
	// Handle different types that might be returned
	switch v := val.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}
