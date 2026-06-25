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

package githubworkflow

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	ghworkflowpredicate "github.com/thomsonreuters/stamp/pkg/predicates/github-workflow/v1"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

// ValidateConfig validates the attestor configuration against the schema and
// performs additional custom validation including event payload size limits,
// redaction pattern validity, logical constraints, and security requirements.
func (a *Attestor) ValidateConfig(config core.Config) error {
	a.logger.Debug("validating GitHub Workflow attestor configuration")

	a.parseConfig(config)

	if err := config.Validate(a.ConfigSchema()); err != nil {
		a.logger.Error("configuration schema validation failed", "error", err.Error())
		return err
	}

	if a.config.MissingEventBehavior != "" && !slices.Contains(validMissingEventBehaviors, a.config.MissingEventBehavior) {
		err := fmt.Errorf("invalid missing-event-behavior '%s': must be one of %v", a.config.MissingEventBehavior, validMissingEventBehaviors)
		return pkgerrors.WrapWithContext(err, id, "validate", "invalid missing-event-behavior value")
	}

	if len(a.config.RedactPatterns) > 0 {
		if err := validateRegexPatterns(a.config.RedactPatterns); err != nil {
			return pkgerrors.WrapWithContext(
				fmt.Errorf("%w", err),
				id,
				"validate",
				"redaction pattern would remove all event payload content",
			)
		}
	} else {
		a.logger.Info("no custom redaction patterns configured, only built-in patterns will be applied",
			"message", "Consider adding custom redaction patterns for organization-specific sensitive data")
	}

	if !a.config.CaptureEnvironment && !a.config.CaptureEventPayload {
		a.logger.Warn("minimal attestation mode: both capture-environment and capture-event-payload are disabled",
			"capture_environment", a.config.CaptureEnvironment,
			"capture_event_payload", a.config.CaptureEventPayload,
			"message", "Attestation will contain minimal workflow metadata only")
	}

	if len(a.config.SensitiveFields) > 0 {
		for _, field := range a.config.SensitiveFields {
			if slices.Contains(criticalFields, field) {
				err := fmt.Errorf("sensitive-fields contains critical field '%s' that must not be redacted", field)
				return pkgerrors.WrapWithContext(err, id, "validate",
					"critical fields cannot be redacted as they ensure attestation integrity")
			}
		}
	}

	if err := utils.ValidateGlobPatterns(a.config.EnvIncludePatterns, "env-include-patterns"); err != nil {
		return pkgerrors.WrapWithContext(err, id, "validate", "invalid env-include pattern")
	}
	if err := utils.ValidateGlobPatterns(a.config.EnvExcludePatterns, "env-exclude-patterns"); err != nil {
		return pkgerrors.WrapWithContext(err, id, "validate", "invalid env-exclude pattern")
	}

	return nil
}

// redactSensitiveFields removes or masks sensitive information from the GitHub Workflow predicate.
// Typed struct fields are handled via a direct field map. Dynamic JSON paths inside
// event_payload are handled separately via redactEventPayloadPaths.
func (a *Attestor) redactSensitiveFields(predicate ghworkflowpredicate.Predicate, fields []string) ghworkflowpredicate.Predicate {
	var payloadPaths [][]string

	for _, fieldStr := range fields {
		if after, ok := strings.CutPrefix(fieldStr, "trigger.event_payload."); ok {
			payloadPaths = append(payloadPaths, strings.Split(after, "."))
			continue
		}

		predicate = a.redactStructField(predicate, fieldStr)
	}

	if len(payloadPaths) > 0 && predicate.Trigger.EventPayload != nil {
		predicate.Trigger.EventPayload = redactEventPayloadPaths(predicate.Trigger.EventPayload, payloadPaths)
	}

	return predicate
}

// redactStructField applies redaction to a single typed predicate field.
//
//nolint:gocyclo,cyclop // Flat switch mapping field names to redaction actions; splitting would reduce readability.
func (a *Attestor) redactStructField(predicate ghworkflowpredicate.Predicate, field string) ghworkflowpredicate.Predicate {
	switch field {
	// Workflow fields
	case "workflow.name", "workflow_name":
		predicate.Workflow.Name = "[REDACTED]"
	case "workflow.ref", "workflow_ref":
		predicate.Workflow.Ref = "[REDACTED]"
	case "workflow.sha", "workflow_sha":
		predicate.Workflow.SHA = "[REDACTED]"
	case "workflow.job_workflow_ref", "job_workflow_ref":
		predicate.Workflow.JobWorkflowRef = "[REDACTED]"
	case "workflow.run_id", "run_id":
		predicate.Workflow.RunID = "[REDACTED]"
	case "workflow.job", "job":
		predicate.Workflow.Job = "[REDACTED]"
	case "workflow.action", "action":
		predicate.Workflow.Action = "[REDACTED]"
	case "workflow.action_path", "action_path":
		predicate.Workflow.ActionPath = "[REDACTED]"

	// Runner fields
	case "runner.name", "runner_name":
		predicate.Runner.Name = "[REDACTED]"
	case "runner.hosted_type", "hosted_type":
		predicate.Runner.HostedType = "[REDACTED]"
	case "runner.environment", "environment":
		predicate.Runner.Environment = nil

	// Trigger fields
	case "trigger.event_name", "event_name":
		predicate.Trigger.EventName = "[REDACTED]"
	case "trigger.actor", "actor":
		predicate.Trigger.Actor = "[REDACTED]"
		predicate.Trigger.ActorID = "[REDACTED]"
	case "trigger.actor_id", "actor_id":
		predicate.Trigger.ActorID = "[REDACTED]"
	case "trigger.event_payload", "event_payload":
		if predicate.Trigger.EventPayload != nil {
			predicate.Trigger.EventPayload = json.RawMessage(`{"_redacted": true}`)
		}
	case "trigger.event_payload_size", "event_payload_size":
		predicate.Trigger.EventPayloadSize = 0
	case "trigger.head_ref", "head_ref":
		predicate.Trigger.HeadRef = "[REDACTED]"
	case "trigger.base_ref", "base_ref":
		predicate.Trigger.BaseRef = "[REDACTED]"

	// Repository fields
	case "repository.full_name", "repository", "repo":
		predicate.Repository.FullName = "[REDACTED]"
	case "repository.owner", "owner":
		predicate.Repository.Owner = "[REDACTED]"
	case "repository.owner_id", "owner_id":
		predicate.Repository.OwnerID = "[REDACTED]"
	case "repository.id", "repository_id", "repo_id":
		predicate.Repository.ID = "[REDACTED]"
	case "repository.visibility", "visibility":
		predicate.Repository.Visibility = "[REDACTED]"
	case "repository.sha", "sha":
		predicate.Repository.SHA = "[REDACTED]"
	case "repository.ref", "ref":
		predicate.Repository.Ref = "[REDACTED]"
	case "repository.ref_type", "ref_type":
		predicate.Repository.RefType = "[REDACTED]"
	case "repository.ref_name", "ref_name":
		predicate.Repository.RefName = "[REDACTED]"

	// Metadata fields
	case "metadata.server_url", "server_url":
		predicate.Metadata.ServerURL = "[REDACTED]"

	// OIDC fields
	case "oidc.token_hash", "token_hash":
		if predicate.OIDC != nil {
			predicate.OIDC.TokenHash = "[REDACTED]"
		}
	case "oidc.issuer", "oidc_issuer":
		if predicate.OIDC != nil {
			predicate.OIDC.Issuer = "[REDACTED]"
		}
	case "oidc.subject", "oidc_subject":
		if predicate.OIDC != nil {
			predicate.OIDC.Subject = "[REDACTED]"
		}
	case "oidc.audience", "oidc_audience":
		if predicate.OIDC != nil {
			predicate.OIDC.Audience = "[REDACTED]"
		}
	case "oidc.jwt_id", "jwt_id":
		if predicate.OIDC != nil {
			predicate.OIDC.JWTID = "[REDACTED]"
		}
	}

	return predicate
}

// redactEventPayloadPaths applies multiple dot-notation path redactions to a JSON blob
// in a single parse/marshal cycle.
func redactEventPayloadPaths(raw json.RawMessage, paths [][]string) json.RawMessage {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw
	}

	for _, path := range paths {
		redactNestedField(obj, path)
	}

	result, err := json.Marshal(obj)
	if err != nil {
		return raw
	}
	return result
}

// redactNestedField traverses a parsed JSON object along the given path segments
// and replaces the leaf value with "[REDACTED]".
func redactNestedField(obj map[string]any, path []string) {
	if len(path) == 0 {
		return
	}

	key := path[0]
	val, exists := obj[key]
	if !exists {
		return
	}

	if len(path) == 1 {
		obj[key] = "[REDACTED]"
		return
	}

	nested, ok := val.(map[string]any)
	if !ok {
		return
	}
	redactNestedField(nested, path[1:])
}

// validateRegexPatterns validates that regex patterns compile and aren't overly broad.
func validateRegexPatterns(patterns []string) error {
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}

		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("%s is not valid regex", pattern)
		}

		if slices.Contains(dangerousRegexPatterns, pattern) {
			return fmt.Errorf("%s is too broad and would match everything", pattern)
		}
	}
	return nil
}
