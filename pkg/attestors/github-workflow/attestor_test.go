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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/logger"
	ghworkflowpredicate "github.com/thomsonreuters/stamp/pkg/predicates/github-workflow/v1"
)

func TestID(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "github-workflow", attestor.ID())
}

func TestPredicateURI(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "https://github.com/thomsonreuters/stamp/github-workflow/v1", attestor.PredicateURI())
	assert.Equal(t, ghworkflowpredicate.PredicateURI, attestor.PredicateURI())
}

func TestName(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "GitHub Workflow Attestor", attestor.Name())
}

func TestDescription(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "Generates GitHub Actions workflow attestation with CI/CD environment metadata", attestor.Description())
}

func TestConfigSchema(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	schema := attestor.ConfigSchema()

	assert.NotEmpty(t, schema)

	fieldNames := make(map[string]bool)
	for _, field := range schema {
		fieldNames[field.Name] = true
	}

	expectedFields := []string{
		"capture-environment",
		"env-include-patterns",
		"env-exclude-patterns",
		"capture-event-payload",
		"redact-event-payload",
		"missing-event-behavior",
		"redact-patterns",
		"redact-actor",
		"sensitive-fields",
		"subject-workflow-file",
	}

	for _, expected := range expectedFields {
		assert.True(t, fieldNames[expected], "Expected field %s to be in schema", expected)
	}

	// Verify some field properties
	for _, field := range schema {
		assert.NotEmpty(t, field.Name)
		assert.NotEmpty(t, field.Type)
		assert.NotEmpty(t, field.Description)

		if field.Name == "capture-environment" {
			assert.Equal(t, "bool", field.Type)
			assert.Equal(t, false, field.Default)
		}

		if field.Name == "capture-event-payload" {
			assert.Equal(t, "bool", field.Type)
			assert.Equal(t, true, field.Default)
		}

		if field.Name == "event-max-size" {
			assert.Equal(t, "string", field.Type)
			assert.Equal(t, "1MB", field.Default)
		}

		if field.Name == "env-include-patterns" {
			assert.Equal(t, "[]string", field.Type)
			assert.NotNil(t, field.Default)
		}
	}
}

func TestSchema(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	schema := attestor.Schema()

	assert.NotNil(t, schema)
	assert.Equal(t, "GitHub Workflow Attestation", schema.Title)
	assert.Equal(t, "Evidence of GitHub Actions workflow execution and metadata", schema.Description)
	assert.Contains(t, schema.ID.String(), "github.com/thomsonreuters/stamp/pkg/predicates/github-workflow/v1")
}

func TestPreAttest(t *testing.T) {
	tests := []struct {
		name   string
		config core.Config
	}{
		{
			name:   "successful pre-attest with default config",
			config: core.Config{},
		},
		{
			name: "successful pre-attest with custom config",
			config: core.Config{
				"capture-environment":   true,
				"capture-event-payload": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{logger: logger.NewNoop()}
			err := attestor.PreAttest(t.Context(), tt.config)

			// PreAttest only parses config, doesn't collect data (that happens in Attest)
			require.NoError(t, err)
		})
	}
}

func TestAttest(t *testing.T) {
	setupGitHubEnv(t)

	config := core.Config{
		"capture-environment":   false,
		"capture-event-payload": false,
	}

	// Setup mock clients via package-level New replacement
	setupMockOIDCClients(t)

	attestor := &Attestor{
		logger: logger.NewNoop(),
	}
	err := attestor.PreAttest(t.Context(), config)
	require.NoError(t, err)

	err = attestor.Attest(t.Context(), config)

	require.NoError(t, err)

	// Fields populated from OIDC claims into predicate
	assert.NotEmpty(t, attestor.workflowInfo.Name)
	assert.NotEmpty(t, attestor.workflowInfo.RunID)
	assert.NotEmpty(t, attestor.triggerInfo.EventName)
	assert.NotEmpty(t, attestor.repositoryInfo.FullName)
	// Fields still in predicate
	assert.NotEmpty(t, attestor.runnerInfo.OS)
}

func TestPostAttest(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	err := attestor.PostAttest(t.Context(), core.Config{})

	// PostAttest is a no-op for this attestor
	assert.NoError(t, err)
}

func TestGeneratePredicate(t *testing.T) {
	// Setup complete attestor with test data
	attestor := &Attestor{
		logger: logger.NewNoop(),
		workflowInfo: ghworkflowpredicate.WorkflowInfo{
			Name:       "Test Workflow",
			Ref:        "owner/repo/.github/workflows/ci.yml@refs/heads/main",
			SHA:        "workflow123",
			RunID:      "123456789",
			RunNumber:  42,
			RunAttempt: 1,
			Job:        "build",
			Action:     "test",
			ActionPath: "/path/to/action",
		},
		runnerInfo: ghworkflowpredicate.RunnerInfo{
			Name:       "GitHub Actions 2",
			OS:         "Linux",
			Arch:       "X64",
			HostedType: "github-hosted",
		},
		triggerInfo: ghworkflowpredicate.TriggerInfo{
			EventName: "push",
			Actor:     "testuser",
			ActorID:   "12345",
		},
		repositoryInfo: ghworkflowpredicate.RepositoryInfo{
			FullName: "owner/repo",
			Owner:    "owner",
			SHA:      "abc123def456",
			Ref:      "refs/heads/main",
			RefName:  "main",
			RefType:  "branch",
		},
		metadataInfo: ghworkflowpredicate.MetadataInfo{
			ServerURL: "https://github.com",
		},
		oidcInfo: &ghworkflowpredicate.OIDCInfo{},
	}

	tests := []struct {
		name     string
		config   core.Config
		validate func(*testing.T, any)
	}{
		{
			name:   "basic predicate without redaction",
			config: core.Config{},
			validate: func(t *testing.T, pred any) {
				p, ok := pred.(ghworkflowpredicate.Predicate)
				require.True(t, ok)

				assert.Equal(t, "Test Workflow", p.Workflow.Name)
				assert.Equal(t, "123456789", p.Workflow.RunID)
				assert.Equal(t, "testuser", p.Trigger.Actor)
				assert.Equal(t, "owner/repo", p.Repository.FullName)
				assert.Equal(t, "Linux", p.Runner.OS)
			},
		},
		{
			name: "with actor redaction",
			config: core.Config{
				"redact-actor": true,
			},
			validate: func(t *testing.T, pred any) {
				p, ok := pred.(ghworkflowpredicate.Predicate)
				require.True(t, ok)

				assert.Equal(t, "[REDACTED]", p.Trigger.Actor)
				assert.Equal(t, "[REDACTED]", p.Trigger.ActorID)
				// Other fields preserved
				assert.Equal(t, "push", p.Trigger.EventName)
			},
		},
		{
			name: "with sensitive fields redaction",
			config: core.Config{
				"sensitive-fields": []string{"actor", "repository.owner"},
			},
			validate: func(t *testing.T, pred any) {
				p, ok := pred.(ghworkflowpredicate.Predicate)
				require.True(t, ok)

				assert.Equal(t, "[REDACTED]", p.Trigger.Actor)
				assert.Equal(t, "[REDACTED]", p.Repository.Owner)
				assert.Equal(t, "owner/repo", p.Repository.FullName)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor.parseConfig(tt.config)

			predicate, err := attestor.GeneratePredicate(tt.config)

			require.NoError(t, err)
			assert.NotNil(t, predicate)

			if tt.validate != nil {
				tt.validate(t, predicate)
			}
		})
	}
}

func TestSubjects(t *testing.T) {
	claims := map[string]any{
		"run_id":      "123456789",
		"run_attempt": "1",
		"repository":  "owner/repo",
		"sha":         "abc123def456",
	}
	attestor := &Attestor{
		workflowInfo:   ghworkflowpredicate.WorkflowInfo{},
		repositoryInfo: ghworkflowpredicate.RepositoryInfo{},
		allClaims:      claims,
		oidcInfo:       &ghworkflowpredicate.OIDCInfo{},
	}

	subjects := attestor.Subjects(core.Config{})

	require.Len(t, subjects, 1)

	subject := subjects[0]
	assert.Equal(t, "github-workflow://owner/repo/runs/123456789", subject.Name)
	assert.Contains(t, subject.Digest, "run_id")
	assert.Equal(t, "123456789", subject.Digest["run_id"])
	assert.Contains(t, subject.Digest, "run_attempt")
	assert.Equal(t, "1", subject.Digest["run_attempt"])
	assert.Contains(t, subject.Digest, "sha1")
	assert.Equal(t, "abc123def456", subject.Digest["sha1"])
}

func TestSubjectsWithConfig(t *testing.T) {
	tests := []struct {
		name             string
		setupAttesor     func() *Attestor
		config           core.Config
		expectedCount    int
		validateSubjects func(*testing.T, []any)
	}{
		{
			name: "basic subjects without workflow file",
			setupAttesor: func() *Attestor {
				claims := map[string]any{
					"workflow_ref": "owner/repo/.github/workflows/ci.yml@refs/heads/main",
					"run_id":       "123456789",
					"run_attempt":  "1",
					"repository":   "owner/repo",
					"sha":          "abc123",
				}
				return &Attestor{
					workflowInfo:   ghworkflowpredicate.WorkflowInfo{},
					repositoryInfo: ghworkflowpredicate.RepositoryInfo{},
					allClaims:      claims,
					oidcInfo:       &ghworkflowpredicate.OIDCInfo{},
				}
			},
			config:        core.Config{},
			expectedCount: 1,
			validateSubjects: func(t *testing.T, subjects []any) {
				assert.Len(t, subjects, 1)
			},
		},
		{
			name: "with workflow file subject",
			setupAttesor: func() *Attestor {
				claims := map[string]any{
					"workflow_ref": "owner/repo/.github/workflows/ci.yml@refs/heads/main",
					"run_id":       "123456789",
					"run_attempt":  "1",
					"repository":   "owner/repo",
					"sha":          "abc123",
				}
				return &Attestor{
					workflowInfo:   ghworkflowpredicate.WorkflowInfo{},
					repositoryInfo: ghworkflowpredicate.RepositoryInfo{},
					// These fields are populated by Attest() when subject-workflow-file is true
					workflowFilePath: ".github/workflows/ci.yml",
					workflowFileSHA:  map[string]string{"sha256": "abc123def456"},
					allClaims:        claims,
					oidcInfo:         &ghworkflowpredicate.OIDCInfo{},
				}
			},
			config: core.Config{
				"subject-workflow-file": true,
			},
			expectedCount: 2,
			validateSubjects: func(t *testing.T, subjects []any) {
				assert.Len(t, subjects, 2)

				hasWorkflowFile := false
				for _, s := range subjects {
					if s != nil {
						hasWorkflowFile = true
					}
				}
				assert.True(t, hasWorkflowFile)
			},
		},
		{
			name: "workflow file disabled",
			setupAttesor: func() *Attestor {
				claims := map[string]any{
					"workflow_ref": "owner/repo/.github/workflows/ci.yml@refs/heads/main",
					"run_id":       "123456789",
					"run_attempt":  "1",
					"repository":   "owner/repo",
					"sha":          "abc123",
				}
				return &Attestor{
					workflowInfo:   ghworkflowpredicate.WorkflowInfo{},
					repositoryInfo: ghworkflowpredicate.RepositoryInfo{},
					// workflowFilePath and workflowFileSHA are empty when subject-workflow-file is false
					allClaims: claims,
					oidcInfo:  &ghworkflowpredicate.OIDCInfo{},
				}
			},
			config: core.Config{
				"subject-workflow-file": false,
			},
			expectedCount: 1,
			validateSubjects: func(t *testing.T, subjects []any) {
				assert.Len(t, subjects, 1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := tt.setupAttesor()

			subjects := attestor.Subjects(tt.config)

			assert.Len(t, subjects, tt.expectedCount)

			subjectsInterface := make([]any, len(subjects))
			for i, s := range subjects {
				subjectsInterface[i] = s
			}

			if tt.validateSubjects != nil {
				tt.validateSubjects(t, subjectsInterface)
			}
		})
	}
}

func TestFullAttestationLifecycle(t *testing.T) {
	setupGitHubEnv(t)

	tempDir := t.TempDir()
	workflowDir := filepath.Join(tempDir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(workflowDir, 0755))

	workflowContent := `name: Test CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
`
	workflowFile := filepath.Join(workflowDir, "test.yml")
	require.NoError(t, os.WriteFile(workflowFile, []byte(workflowContent), 0644))

	t.Setenv("GITHUB_WORKSPACE", tempDir)
	t.Setenv("GITHUB_WORKFLOW_REF", "owner/repo/.github/workflows/test.yml@refs/heads/main")
	defer func() {
	}()

	config := core.Config{
		"capture-environment":   false,
		"capture-event-payload": false,
		"subject-workflow-file": true,
	}

	// Setup mock clients via package-level New replacement
	setupMockOIDCClients(t)

	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	err := attestor.ValidateConfig(config)
	require.NoError(t, err, "ValidateConfig should succeed")

	err = attestor.PreAttest(t.Context(), config)
	require.NoError(t, err, "PreAttest should succeed")

	err = attestor.Attest(t.Context(), config)
	require.NoError(t, err, "Attest should succeed")

	predicate, err := attestor.GeneratePredicate(config)
	require.NoError(t, err, "GeneratePredicate should succeed")
	assert.NotNil(t, predicate)

	p, ok := predicate.(ghworkflowpredicate.Predicate)
	require.True(t, ok, "Predicate should be correct type")

	// Check predicate fields populated from OIDC claims
	assert.Equal(t, "Test Workflow", p.Workflow.Name)
	assert.Equal(t, "123456789", p.Workflow.RunID)
	assert.Equal(t, 42, p.Workflow.RunNumber)
	assert.Equal(t, "github-hosted", p.Runner.HostedType)
	assert.Equal(t, "push", p.Trigger.EventName)
	assert.Equal(t, "testuser", p.Trigger.Actor)
	assert.Equal(t, "owner/repo", p.Repository.FullName)
	assert.Equal(t, "abc123def456", p.Repository.SHA)
	// Check fields from env vars
	assert.Equal(t, "Linux", p.Runner.OS)
	assert.Equal(t, "https://github.com", p.Metadata.ServerURL)

	subjects := attestor.Subjects(config)
	assert.Len(t, subjects, 2, "Should have workflow run and workflow file subjects")

	err = attestor.PostAttest(t.Context(), config)
	require.NoError(t, err, "PostAttest should succeed")
}

func TestAttestorInterfaceCompliance(t *testing.T) {
	var _ core.Attestor = (*Attestor)(nil)
}

func TestGetStringClaim(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		key    string
		want   string
	}{
		{"nil claims returns empty", nil, "workflow", ""},
		{"missing key returns empty", map[string]any{"other": "val"}, "workflow", ""},
		{"string value", map[string]any{"workflow": "CI"}, "workflow", "CI"},
		{"float64 value", map[string]any{"run_number": float64(42)}, "run_number", "42"},
		{"int value", map[string]any{"count": 7}, "count", "7"},
		{"other type uses Sprintf", map[string]any{"flag": true}, "flag", "true"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Attestor{
				allClaims: tt.claims,
				logger:    logger.NewNoop(),
			}
			assert.Equal(t, tt.want, a.getStringClaim(tt.key))
		})
	}
}
