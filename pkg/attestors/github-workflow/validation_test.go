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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/logger"
	ghworkflowpredicate "github.com/thomsonreuters/stamp/pkg/predicates/github-workflow/v1"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        core.Config
		expectError   bool
		errorContains string
	}{
		{
			name:        "empty config (all defaults)",
			config:      core.Config{},
			expectError: false,
		},
		{
			name: "valid missing-event-behavior: allow",
			config: core.Config{
				"missing-event-behavior": "allow",
			},
			expectError: false,
		},
		{
			name: "valid missing-event-behavior: warn",
			config: core.Config{
				"missing-event-behavior": "warn",
			},
			expectError: false,
		},
		{
			name: "valid missing-event-behavior: fail",
			config: core.Config{
				"missing-event-behavior": "fail",
			},
			expectError: false,
		},
		{
			name: "invalid missing-event-behavior",
			config: core.Config{
				"missing-event-behavior": "invalid",
			},
			expectError:   true,
			errorContains: "missing-event-behavior",
		},
		{
			name: "valid redaction patterns",
			config: core.Config{
				"redact-patterns": []string{
					`(?i)internal-token-.*`,
					`(?i)corp-secret-.*`,
					`[0-9]{3}-[0-9]{2}-[0-9]{4}`,
				},
			},
			expectError: false,
		},
		{
			name: "invalid regex pattern",
			config: core.Config{
				"redact-patterns": []string{
					"[invalid-regex(",
				},
			},
			expectError:   true,
			errorContains: "regex",
		},
		{
			name: "dangerous pattern - matches everything",
			config: core.Config{
				"redact-patterns": []string{
					".*",
				},
			},
			expectError:   true,
			errorContains: "too broad",
		},
		{
			name: "dangerous pattern - matches all lines",
			config: core.Config{
				"redact-patterns": []string{
					"^.*$",
				},
			},
			expectError:   true,
			errorContains: "too broad",
		},
		{
			name: "empty pattern in list (should be ignored)",
			config: core.Config{
				"redact-patterns": []string{
					`(?i)valid-pattern`,
					"",
					`(?i)another-pattern`,
				},
			},
			expectError: false,
		},
		{
			name: "valid sensitive-fields",
			config: core.Config{
				"sensitive-fields": []string{
					"actor",
					"repository.owner",
					"runner.name",
				},
			},
			expectError: false,
		},
		{
			name: "attempt to redact critical field - workflow.run_id",
			config: core.Config{
				"sensitive-fields": []string{
					"workflow.run_id",
				},
			},
			expectError:   true,
			errorContains: "critical field",
		},
		{
			name: "attempt to redact critical field - run_id",
			config: core.Config{
				"sensitive-fields": []string{
					"run_id",
				},
			},
			expectError:   true,
			errorContains: "critical field",
		},
		{
			name: "attempt to redact critical field - repository.sha",
			config: core.Config{
				"sensitive-fields": []string{
					"repository.sha",
				},
			},
			expectError:   true,
			errorContains: "critical field",
		},
		{
			name: "attempt to redact critical field - metadata.started_on",
			config: core.Config{
				"sensitive-fields": []string{
					"metadata.started_on",
				},
			},
			expectError:   true,
			errorContains: "critical field",
		},
		{
			name: "minimal attestation warning (both capture flags false)",
			config: core.Config{
				"capture-environment":   false,
				"capture-event-payload": false,
			},
			expectError: false,
		},
		{
			name: "comprehensive configuration",
			config: core.Config{
				"capture-environment":    true,
				"env-include-patterns":   []string{"GITHUB_*", "RUNNER_*", "CI"},
				"env-exclude-patterns":   []string{"*TOKEN*", "*SECRET*"},
				"capture-event-payload":  true,
				"redact-event-payload":   false,
				"missing-event-behavior": "warn",
				"redact-patterns":        []string{`(?i)internal-.*`},
				"redact-actor":           true,
				"sensitive-fields":       []string{"repository.owner"},
				"subject-workflow-file":  true,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{logger: logger.NewNoop()}
			err := attestor.ValidateConfig(tt.config)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateConfig_RedactPatternsAsInterface(t *testing.T) {
	config := core.Config{
		"redact-patterns": []any{
			"(?i)pattern1",
			"(?i)pattern2",
		},
	}

	attestor := &Attestor{logger: logger.NewNoop()}
	err := attestor.ValidateConfig(config)
	assert.NoError(t, err)
}

func TestValidateConfig_InvalidRedactPatternType(t *testing.T) {
	config := core.Config{
		"redact-patterns": []any{
			"valid-pattern",
			123,
		},
	}

	attestor := &Attestor{logger: logger.NewNoop()}
	err := attestor.ValidateConfig(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be a string")
}

// createTestPredicate creates a test predicate with sample data for redaction tests.
func createTestPredicate() ghworkflowpredicate.Predicate {
	return ghworkflowpredicate.Predicate{
		Workflow: ghworkflowpredicate.WorkflowInfo{
			Name:           "Test Workflow",
			Ref:            "owner/repo/.github/workflows/ci.yml@refs/heads/main",
			SHA:            "workflow123",
			JobWorkflowRef: "owner/repo/.github/workflows/ci.yml@refs/heads/main",
			RunID:          "123456789",
			RunNumber:      42,
			RunAttempt:     1,
			Job:            "build",
			Action:         "checkout",
			ActionPath:     "/actions/checkout",
		},
		Runner: ghworkflowpredicate.RunnerInfo{
			Name:       "GitHub Actions 2",
			OS:         "Linux",
			Arch:       "X64",
			HostedType: "github-hosted",
			Environment: map[string]string{
				"CI": "true",
			},
		},
		Trigger: ghworkflowpredicate.TriggerInfo{
			EventName:        "push",
			Actor:            "testuser",
			ActorID:          "12345",
			EventPayload:     json.RawMessage(`{"action": "opened"}`),
			EventPayloadSize: 100,
			HeadRef:          "feature-branch",
			BaseRef:          "main",
		},
		Repository: ghworkflowpredicate.RepositoryInfo{
			FullName:   "owner/repo",
			Owner:      "owner",
			OwnerID:    "67890",
			ID:         "11111",
			Visibility: "private",
			SHA:        "abc123def456",
			Ref:        "refs/heads/main",
			RefName:    "main",
			RefType:    "branch",
		},
		Metadata: ghworkflowpredicate.MetadataInfo{
			ServerURL: "https://github.com",
		},
		OIDC: &ghworkflowpredicate.OIDCInfo{
			TokenHash: "abc123hash",
			Issuer:    "https://token.actions.githubusercontent.com",
			Subject:   "repo:owner/repo:ref:refs/heads/main",
			Audience:  "https://github.com",
			JWTID:     "test-jwt-id",
		},
	}
}

// redactionTestCase represents a single test case for field redaction.
type redactionTestCase struct {
	name              string
	fields            []string
	validateRedacted  func(*testing.T, ghworkflowpredicate.Predicate)
	validatePreserved func(*testing.T, ghworkflowpredicate.Predicate)
}

// getRedactionTestCases returns all test cases for redaction testing.
func getRedactionTestCases() []redactionTestCase {
	return []redactionTestCase{
		{
			name:   "redact actor",
			fields: []string{"actor"},
			validateRedacted: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Trigger.Actor)
				assert.Equal(t, "[REDACTED]", p.Trigger.ActorID)
			},
			validatePreserved: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "push", p.Trigger.EventName)
			},
		},
		{
			name:   "redact repository owner",
			fields: []string{"repository.owner"},
			validateRedacted: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Repository.Owner)
			},
			validatePreserved: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "owner/repo", p.Repository.FullName)
			},
		},
		{
			name:   "redact runner name",
			fields: []string{"runner.name"},
			validateRedacted: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Runner.Name)
			},
			validatePreserved: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "Linux", p.Runner.OS)
			},
		},
		{
			name:   "redact environment",
			fields: []string{"runner.environment"},
			validateRedacted: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Nil(t, p.Runner.Environment)
			},
			validatePreserved: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "Linux", p.Runner.OS)
			},
		},
		{
			name:   "redact event payload",
			fields: []string{"trigger.event_payload"},
			validateRedacted: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Contains(t, string(p.Trigger.EventPayload), "_redacted")
			},
			validatePreserved: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "push", p.Trigger.EventName)
			},
		},
		{
			name:   "redact multiple fields",
			fields: []string{"actor", "repository.owner", "runner.name"},
			validateRedacted: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Trigger.Actor)
				assert.Equal(t, "[REDACTED]", p.Repository.Owner)
				assert.Equal(t, "[REDACTED]", p.Runner.Name)
			},
			validatePreserved: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "push", p.Trigger.EventName)
				assert.Equal(t, "owner/repo", p.Repository.FullName)
				assert.Equal(t, "Linux", p.Runner.OS)
			},
		},
		{
			name:   "alternative field names",
			fields: []string{"workflow_name", "repo", "owner"},
			validateRedacted: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Workflow.Name)
				assert.Equal(t, "[REDACTED]", p.Repository.FullName)
				assert.Equal(t, "[REDACTED]", p.Repository.Owner)
			},
			validatePreserved: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "123456789", p.Workflow.RunID)
			},
		},
		{
			name:   "redact head_ref and base_ref",
			fields: []string{"trigger.head_ref", "trigger.base_ref"},
			validateRedacted: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Trigger.HeadRef)
				assert.Equal(t, "[REDACTED]", p.Trigger.BaseRef)
			},
			validatePreserved: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "push", p.Trigger.EventName)
				assert.Equal(t, "testuser", p.Trigger.Actor)
			},
		},
		{
			name:   "redact job_workflow_ref",
			fields: []string{"workflow.job_workflow_ref"},
			validateRedacted: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Workflow.JobWorkflowRef)
			},
			validatePreserved: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "Test Workflow", p.Workflow.Name)
			},
		},
		{
			name:   "redact oidc token_hash",
			fields: []string{"oidc.token_hash"},
			validateRedacted: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				require.NotNil(t, p.OIDC)
				assert.Equal(t, "[REDACTED]", p.OIDC.TokenHash)
			},
			validatePreserved: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "https://token.actions.githubusercontent.com", p.OIDC.Issuer)
			},
		},
		{
			name:   "redact oidc subject",
			fields: []string{"oidc.subject"},
			validateRedacted: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				require.NotNil(t, p.OIDC)
				assert.Equal(t, "[REDACTED]", p.OIDC.Subject)
			},
			validatePreserved: func(t *testing.T, p ghworkflowpredicate.Predicate) {
				assert.Equal(t, "https://token.actions.githubusercontent.com", p.OIDC.Issuer)
			},
		},
	}
}

func TestRedactSensitiveFields(t *testing.T) {
	predicate := createTestPredicate()
	tests := getRedactionTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{logger: logger.NewNoop()}

			predicateCopy := predicate

			result := attestor.redactSensitiveFields(predicateCopy, tt.fields)

			if tt.validateRedacted != nil {
				tt.validateRedacted(t, result)
			}
			if tt.validatePreserved != nil {
				tt.validatePreserved(t, result)
			}
		})
	}
}

func TestRedactSensitiveFields_AllFieldVariations(t *testing.T) {
	fieldVariations := map[string][]string{
		"workflow": {
			"workflow.name", "workflow_name",
			"workflow.ref", "workflow_ref",
			"workflow.sha", "workflow_sha",
			"workflow.job_workflow_ref", "job_workflow_ref",
			"workflow.run_id", "run_id",
			"workflow.job", "job",
			"workflow.action", "action",
			"workflow.action_path", "action_path",
		},
		"runner": {
			"runner.name", "runner_name",
			"runner.hosted_type", "hosted_type",
			"runner.environment", "environment",
		},
		"trigger": {
			"trigger.event_name", "event_name",
			"trigger.actor", "actor",
			"trigger.actor_id", "actor_id",
			"trigger.event_payload", "event_payload",
			"trigger.event_payload_size", "event_payload_size",
			"trigger.head_ref", "head_ref",
			"trigger.base_ref", "base_ref",
		},
		"repository": {
			"repository.full_name", "repository", "repo",
			"repository.owner", "owner",
			"repository.owner_id", "owner_id",
			"repository.id", "repository_id", "repo_id",
			"repository.visibility", "visibility",
			"repository.sha", "sha",
			"repository.ref", "ref",
			"repository.ref_type", "ref_type",
			"repository.ref_name", "ref_name",
		},
		"metadata": {
			"metadata.server_url", "server_url",
		},
		"oidc": {
			"oidc.token_hash", "token_hash",
			"oidc.issuer", "oidc_issuer",
			"oidc.subject", "oidc_subject",
			"oidc.audience", "oidc_audience",
			"oidc.jwt_id", "jwt_id",
		},
	}

	predicate := ghworkflowpredicate.Predicate{
		Workflow: ghworkflowpredicate.WorkflowInfo{
			Name:       "Test",
			Ref:        "owner/repo/.github/workflows/ci.yml@refs/heads/main",
			SHA:        "workflow123",
			RunID:      "123456789",
			RunNumber:  42,
			RunAttempt: 1,
			Job:        "build",
		},
		Runner: ghworkflowpredicate.RunnerInfo{
			Name:       "Runner",
			HostedType: "github-hosted",
		},
		Trigger: ghworkflowpredicate.TriggerInfo{
			EventName:        "push",
			Actor:            "testuser",
			ActorID:          "12345",
			EventPayload:     json.RawMessage(`{"action": "opened"}`),
			EventPayloadSize: 100,
			HeadRef:          "feature-branch",
			BaseRef:          "main",
		},
		Repository: ghworkflowpredicate.RepositoryInfo{
			FullName:   "owner/repo",
			Owner:      "owner",
			OwnerID:    "67890",
			ID:         "11111",
			Visibility: "private",
			SHA:        "abc123def456",
			Ref:        "refs/heads/main",
			RefName:    "main",
			RefType:    "branch",
		},
		Metadata: ghworkflowpredicate.MetadataInfo{
			ServerURL: "https://github.com",
		},
		OIDC: &ghworkflowpredicate.OIDCInfo{
			Issuer:  "https://token.actions.githubusercontent.com",
			Subject: "repo:owner/repo:ref:refs/heads/main",
		},
	}

	attestor := &Attestor{logger: logger.NewNoop()}

	for category, fields := range fieldVariations {
		t.Run(category, func(t *testing.T) {
			for _, field := range fields {
				t.Run(field, func(t *testing.T) {
					predicateCopy := predicate
					result := attestor.redactSensitiveFields(predicateCopy, []string{field})

					assert.NotNil(t, result)
				})
			}
		})
	}
}

func TestRedactSensitiveFields_NilOIDC(t *testing.T) {
	predicate := ghworkflowpredicate.Predicate{
		Workflow: ghworkflowpredicate.WorkflowInfo{Name: "Test"},
	}
	attestor := &Attestor{logger: logger.NewNoop()}

	// Should not panic when OIDC is nil
	result := attestor.redactSensitiveFields(predicate, []string{"oidc.token_hash", "oidc.subject", "oidc.issuer", "oidc.audience", "oidc.jwt_id"})
	assert.Nil(t, result.OIDC)
}
