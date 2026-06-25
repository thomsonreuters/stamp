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
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestFilterEnvironmentVariables(t *testing.T) {
	t.Setenv("GITHUB_WORKFLOW", "test-workflow")
	t.Setenv("GITHUB_TOKEN", "secret-token")
	t.Setenv("RUNNER_OS", "Linux")
	t.Setenv("NPM_TOKEN", "npm-secret")
	t.Setenv("CI", "true")
	t.Setenv("MY_PASSWORD", "secret")
	t.Setenv("CUSTOM_VAR", "should-not-match")

	tests := []struct {
		name             string
		includePatterns  []string
		excludePatterns  []string
		expectedIncluded []string
		expectedExcluded []string
	}{
		{
			name:             "default patterns",
			includePatterns:  []string{"GITHUB_*", "RUNNER_*", "CI"},
			excludePatterns:  []string{"*TOKEN*", "*SECRET*", "*PASSWORD*"},
			expectedIncluded: []string{"GITHUB_WORKFLOW", "RUNNER_OS", "CI"},
			expectedExcluded: []string{"GITHUB_TOKEN", "NPM_TOKEN", "MY_PASSWORD", "CUSTOM_VAR"},
		},
		{
			name:             "include NPM vars",
			includePatterns:  []string{"GITHUB_*", "RUNNER_*", "NPM_*"},
			excludePatterns:  []string{"*TOKEN*"},
			expectedIncluded: []string{"GITHUB_WORKFLOW", "RUNNER_OS"},
			expectedExcluded: []string{"GITHUB_TOKEN", "NPM_TOKEN", "CI"},
		},
		{
			name:             "exclude takes precedence",
			includePatterns:  []string{"*"},
			excludePatterns:  []string{"*TOKEN*", "*PASSWORD*"},
			expectedIncluded: []string{"GITHUB_WORKFLOW", "RUNNER_OS", "CI", "CUSTOM_VAR"},
			expectedExcluded: []string{"GITHUB_TOKEN", "NPM_TOKEN", "MY_PASSWORD"},
		},
		{
			name:             "no includes matches nothing",
			includePatterns:  []string{},
			excludePatterns:  []string{"*TOKEN*"},
			expectedIncluded: []string{},
			expectedExcluded: []string{"GITHUB_WORKFLOW", "GITHUB_TOKEN", "RUNNER_OS", "NPM_TOKEN", "CI"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ghInfo := GitHubActionInfo{}
			result := ghInfo.CaptureEnvironmentVariables(
				t.Context(),
				logger.NewNoop(),
				tt.includePatterns,
				tt.excludePatterns,
			)

			// Check expected inclusions
			for _, key := range tt.expectedIncluded {
				assert.Contains(t, result, key, "Expected %s to be included", key)
			}

			// Check expected exclusions
			for _, key := range tt.expectedExcluded {
				assert.NotContains(t, result, key, "Expected %s to be excluded", key)
			}
		})
	}
}

func TestParseWorkflowFile(t *testing.T) {
	tests := []struct {
		name         string
		workflowRef  string
		expectedFile string
		expectError  bool
	}{
		{
			name:         "valid workflow ref",
			workflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
			expectedFile: ".github/workflows/ci.yml",
			expectError:  false,
		},
		{
			name:         "nested workflow path",
			workflowRef:  "owner/repo/.github/workflows/deploy/production.yml@refs/tags/v1.0",
			expectedFile: ".github/workflows/deploy/production.yml",
			expectError:  false,
		},
		{
			name:         "empty ref",
			workflowRef:  "",
			expectedFile: "",
			expectError:  true,
		},
		{
			name:         "malformed ref - no @",
			workflowRef:  "owner/repo/.github/workflows/ci.yml",
			expectedFile: "",
			expectError:  true,
		},
		{
			name:         "malformed ref - incomplete path",
			workflowRef:  "owner@refs/heads/main",
			expectedFile: "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ghInfo := &GitHubActionInfo{
				WorkflowRef: tt.workflowRef,
			}

			err := ghInfo.parseWorkflowFile(t.Context())

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedFile, ghInfo.WorkflowFilePath)
			}
		})
	}
}

func TestGetWorkflowFileDigest(t *testing.T) {
	// Create temporary workspace
	tempDir := t.TempDir()
	workflowDir := filepath.Join(tempDir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(workflowDir, 0755))

	workflowContent := `name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
`
	workflowFile := filepath.Join(workflowDir, "ci.yml")
	require.NoError(t, os.WriteFile(workflowFile, []byte(workflowContent), 0644))

	tests := []struct {
		name        string
		workspace   string
		workflowRef string
		expectError bool
	}{
		{
			name:        "valid workflow file",
			workspace:   tempDir,
			workflowRef: "owner/repo/.github/workflows/ci.yml@refs/heads/main",
			expectError: false,
		},
		{
			name:        "missing workspace",
			workspace:   "",
			workflowRef: "owner/repo/.github/workflows/ci.yml@refs/heads/main",
			expectError: true,
		},
		{
			name:        "non-existent file",
			workspace:   tempDir,
			workflowRef: "owner/repo/.github/workflows/nonexistent.yml@refs/heads/main",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ghInfo := &GitHubActionInfo{
				WorkflowRef:     tt.workflowRef,
				GithubWorkspace: tt.workspace,
			}

			result, err := ghInfo.GetWorkflowFileDigest(t.Context())

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Contains(t, result, "sha256")
				assert.NotEmpty(t, result["sha256"])
				// Verify it's a valid hex string
				assert.Len(t, result["sha256"], 64) // SHA256 produces 64 hex characters
			}
		})
	}
}

func TestHandleMissingEventPayload(t *testing.T) {
	tests := []struct {
		name        string
		behavior    string
		expectError bool
		expectNil   bool
	}{
		{
			name:        "allow behavior",
			behavior:    "allow",
			expectError: false,
			expectNil:   true,
		},
		{
			name:        "warn behavior",
			behavior:    "warn",
			expectError: false,
			expectNil:   true,
		},
		{
			name:        "fail behavior",
			behavior:    "fail",
			expectError: true,
			expectNil:   false,
		},
		{
			name:        "invalid behavior defaults to warn",
			behavior:    "invalid",
			expectError: false,
			expectNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
				config: Config{
					MissingEventBehavior: tt.behavior,
				},
			}

			err := attestor.handleEventPayloadError("test event payload missing")

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReadEventPayload(t *testing.T) {
	// Create temporary event files
	tempDir := t.TempDir()

	validEventFile := filepath.Join(tempDir, "valid-event.json")
	validEventContent := `{"action": "opened", "number": 42}`
	require.NoError(t, os.WriteFile(validEventFile, []byte(validEventContent), 0644))

	eventWithEmail := filepath.Join(tempDir, "event-with-email.json")
	emailEventContent := `{"user": {"email": "test@example.com"}, "action": "opened"}`
	require.NoError(t, os.WriteFile(eventWithEmail, []byte(emailEventContent), 0644))

	invalidJSONFile := filepath.Join(tempDir, "invalid-event.json")
	require.NoError(t, os.WriteFile(invalidJSONFile, []byte("invalid json {{{"), 0644))

	tests := []struct {
		name           string
		eventPath      string
		redact         bool
		redactPatterns []string
		expectError    bool
		checkRedacted  bool
	}{
		{
			name:          "valid event payload",
			eventPath:     validEventFile,
			redact:        false,
			expectError:   false,
			checkRedacted: false,
		},
		{
			name:        "missing event path",
			eventPath:   "",
			redact:      false,
			expectError: true,
		},
		{
			name:        "non-existent file",
			eventPath:   filepath.Join(tempDir, "nonexistent.json"),
			redact:      false,
			expectError: true,
		},
		{
			name:        "invalid JSON - no error without redaction",
			eventPath:   invalidJSONFile,
			redact:      false,
			expectError: false, // ReadEventPayload doesn't validate JSON when redact is false
		},
		{
			name:        "invalid JSON with redaction fails",
			eventPath:   invalidJSONFile,
			redact:      true,
			expectError: true, // SanitizeJSON validates JSON
		},
		{
			name:          "with redaction",
			eventPath:     eventWithEmail,
			redact:        true,
			expectError:   false,
			checkRedacted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ghInfo := &GitHubActionInfo{
				GithubEventPath: tt.eventPath,
			}

			result, size, err := ghInfo.ReadEventPayload(
				t.Context(),
				tt.redact,
				tt.redactPatterns,
			)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Positive(t, size)

				if tt.checkRedacted {
					// Check that email was redacted
					assert.Contains(t, string(result), "[REDACTED_EMAIL]")
					assert.NotContains(t, string(result), "test@example.com")
				}
			}
		})
	}
}

func TestGitHubActionInfoValidate(t *testing.T) {
	tests := []struct {
		name        string
		info        GitHubActionInfo
		expectError bool
		errorMsg    string
	}{
		{
			name: "all required fields present",
			info: GitHubActionInfo{
				WorkflowName:     "CI",
				WorkflowRunID:    "123456",
				GithubRepository: "owner/repo",
				GithubSHA:        "abc123",
			},
			expectError: false,
		},
		{
			name: "missing WorkflowName",
			info: GitHubActionInfo{
				WorkflowRunID:    "123456",
				GithubRepository: "owner/repo",
				GithubSHA:        "abc123",
			},
			expectError: true,
			errorMsg:    "WorkflowName (GITHUB_WORKFLOW)",
		},
		{
			name: "missing WorkflowRunID",
			info: GitHubActionInfo{
				WorkflowName:     "CI",
				GithubRepository: "owner/repo",
				GithubSHA:        "abc123",
			},
			expectError: true,
			errorMsg:    "WorkflowRunID (GITHUB_RUN_ID)",
		},
		{
			name: "missing GithubRepository",
			info: GitHubActionInfo{
				WorkflowName:  "CI",
				WorkflowRunID: "123456",
				GithubSHA:     "abc123",
			},
			expectError: true,
			errorMsg:    "GithubRepository (GITHUB_REPOSITORY)",
		},
		{
			name: "missing GithubSHA",
			info: GitHubActionInfo{
				WorkflowName:     "CI",
				WorkflowRunID:    "123456",
				GithubRepository: "owner/repo",
			},
			expectError: true,
			errorMsg:    "GithubSHA (GITHUB_SHA)",
		},
		{
			name: "multiple missing fields",
			info: GitHubActionInfo{
				WorkflowName: "CI",
			},
			expectError: true,
			errorMsg:    "missing required environment variables",
		},
		{
			name:        "all fields empty",
			info:        GitHubActionInfo{},
			expectError: true,
			errorMsg:    "missing required environment variables",
		},
		{
			name: "optional fields can be empty",
			info: GitHubActionInfo{
				WorkflowName:     "CI",
				WorkflowRunID:    "123456",
				GithubRepository: "owner/repo",
				GithubSHA:        "abc123",
				// WorkflowRef, WorkflowJob, etc. are optional
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.info.Validate()

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestParseAttestorTag(t *testing.T) {
	tests := []struct {
		name     string
		tag      string
		expected map[string]string
	}{
		{
			name:     "single option - required",
			tag:      "required",
			expected: map[string]string{"required": "true"},
		},
		{
			name:     "single option - computed",
			tag:      "computed",
			expected: map[string]string{"computed": "true"},
		},
		{
			name:     "multiple options",
			tag:      "required;computed",
			expected: map[string]string{"required": "true", "computed": "true"},
		},
		{
			name:     "empty tag",
			tag:      "",
			expected: nil,
		},
		{
			name:     "with whitespace",
			tag:      " required ; computed ",
			expected: map[string]string{"required": "true", "computed": "true"},
		},
		{
			name:     "key-value pair - env",
			tag:      "env:GITHUB_WORKFLOW",
			expected: map[string]string{"env": "GITHUB_WORKFLOW"},
		},
		{
			name:     "key-value pair - default",
			tag:      "default:1",
			expected: map[string]string{"default": "1"},
		},
		{
			name:     "combined - env and required",
			tag:      "env:GITHUB_WORKFLOW;required",
			expected: map[string]string{"env": "GITHUB_WORKFLOW", "required": "true"},
		},
		{
			name:     "combined - env, required, default",
			tag:      "env:GITHUB_RUN_ATTEMPT;default:1",
			expected: map[string]string{"env": "GITHUB_RUN_ATTEMPT", "default": "1"},
		},
		{
			name:     "with whitespace in key-value",
			tag:      " env:GITHUB_WORKFLOW ; required ; default:1 ",
			expected: map[string]string{"env": "GITHUB_WORKFLOW", "required": "true", "default": "1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseAttestorTag(tt.tag)
			assert.Equal(t, tt.expected, result)
		})
	}
}
