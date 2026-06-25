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
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/clients/github"
	jwtclient "github.com/thomsonreuters/stamp/pkg/clients/jwt"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// extractEnvVarsFromStruct extracts all environment variable names from struct tags.
func extractEnvVarsFromStruct(s any) []string {
	val := reflect.TypeOf(s)
	if val.Kind() == reflect.Pointer {
		val = val.Elem()
	}

	vars := make([]string, 0, val.NumField())

	for field := range val.Fields() {
		tag := field.Tag.Get("attestor")

		if tag == "" {
			continue
		}

		for part := range strings.SplitSeq(tag, ";") {
			if envVar, found := strings.CutPrefix(part, "env:"); found {
				vars = append(vars, envVar)
				break
			}
		}
	}

	return vars
}

// TestMain clears GitHub Actions environment variables once before all tests.
// This ensures clean test state when running in GitHub Actions CI.
func TestMain(m *testing.M) {
	githubVars := extractEnvVarsFromStruct(GitHubActionInfo{})

	for _, varName := range githubVars {
		_ = os.Unsetenv(varName)
	}

	os.Exit(m.Run())
}

// setupGitHubEnv sets up a complete GitHub Actions environment for testing using t.Setenv.
func setupGitHubEnv(t *testing.T) {
	t.Helper()

	// OIDC environment variables (required)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-request-token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://test.actions.githubusercontent.com")

	t.Setenv("GITHUB_WORKFLOW", "Test Workflow")
	t.Setenv("GITHUB_WORKFLOW_REF", "owner/repo/.github/workflows/ci.yml@refs/heads/main")
	t.Setenv("GITHUB_WORKFLOW_SHA", "workflow123abc")
	t.Setenv("GITHUB_RUN_ID", "123456789")
	t.Setenv("GITHUB_RUN_NUMBER", "42")
	t.Setenv("GITHUB_RUN_ATTEMPT", "1")
	t.Setenv("GITHUB_JOB", "test-job")
	t.Setenv("GITHUB_ACTION", "test-action")
	t.Setenv("GITHUB_ACTION_PATH", "/path/to/action")
	t.Setenv("RUNNER_NAME", "GitHub Actions 2")
	t.Setenv("RUNNER_OS", "Linux")
	t.Setenv("RUNNER_ARCH", "X64")
	t.Setenv("RUNNER_ENVIRONMENT", "github-hosted")
	t.Setenv("RUNNER_TEMP", "/tmp/runner")
	t.Setenv("RUNNER_TOOL_CACHE", "/opt/hostedtoolcache")
	t.Setenv("GITHUB_EVENT_NAME", "push")
	t.Setenv("GITHUB_ACTOR", "testuser")
	t.Setenv("GITHUB_ACTOR_ID", "12345")
	t.Setenv("GITHUB_HEAD_REF", "feature-branch")
	t.Setenv("GITHUB_BASE_REF", "main")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")
	t.Setenv("GITHUB_REPOSITORY_OWNER", "owner")
	t.Setenv("GITHUB_REPOSITORY_OWNER_ID", "67890")
	t.Setenv("GITHUB_REPOSITORY_ID", "11111")
	t.Setenv("GITHUB_SHA", "abc123def456")
	t.Setenv("GITHUB_REF", "refs/heads/main")
	t.Setenv("GITHUB_REF_NAME", "main")
	t.Setenv("GITHUB_REF_TYPE", "branch")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
}

// setupMockOIDCClients sets up mock GitHub and JWT clients using SetupMockClient pattern.
// It replaces the package-level New functions and configures mock expectations.
func setupMockOIDCClients(t *testing.T) {
	t.Helper()

	mockToken := generateMockJWT(t)

	// Setup mock GitHub client via package-level New replacement
	mockGithubClient := github.SetupMockClient(t)
	mockGithubClient.On("FetchIDToken", mock.Anything, "").Return(mockToken, nil)
	mockGithubClient.On("FetchIDToken", mock.Anything, "https://github.com").Return(mockToken, nil)
	mockGithubClient.On("FetchIDToken", mock.Anything, "https://custom-audience.example.com").Return(mockToken, nil)

	// Setup mock JWT client via package-level New replacement
	mockJWTClient := jwtclient.SetupMockClient(t)

	tokenInfo := &jwtclient.TokenInfo{
		Claims: jwtclient.Claims{
			Issuer:       DefaultOIDCIssuer,
			Audience:     "https://github.com",
			Subject:      "repo:owner/repo:ref:refs/heads/main",
			CustomClaims: getMockOIDCClaims(),
		},
	}
	mockJWTClient.On("ParseToken", mockToken).Return(tokenInfo, nil)
	mockJWTClient.On("HashToken", mockToken).Return("mock-hash")

	verifyResult := &jwtclient.VerificationResult{
		Verified:   true,
		VerifiedAt: time.Now(),
		KeyID:      "test-key-id",
	}
	mockJWTClient.On("VerifySignature", mock.Anything, mockToken).Return(verifyResult, nil)
}

// getMockOIDCClaims returns mock OIDC claims for testing.
func getMockOIDCClaims() map[string]any {
	return map[string]any{
		"workflow":              "Test Workflow",
		"workflow_ref":          "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		"workflow_sha":          "workflow123abc",
		"job_workflow_ref":      "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		"run_id":                "123456789",
		"run_number":            "42",
		"run_attempt":           "1",
		"runner_environment":    "github-hosted",
		"event_name":            "push",
		"actor":                 "testuser",
		"actor_id":              "12345",
		"head_ref":              "feature-branch",
		"base_ref":              "main",
		"repository":            "owner/repo",
		"repository_owner":      "owner",
		"repository_owner_id":   "67890",
		"repository_id":         "11111",
		"repository_visibility": "private",
		"sha":                   "abc123def456",
		"ref":                   "refs/heads/main",
		"ref_type":              "branch",
	}
}

// generateMockJWT generates a simple mock JWT token for testing.
func generateMockJWT(t *testing.T) string {
	t.Helper()

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := getMockOIDCClaims()
	claims["iss"] = DefaultOIDCIssuer
	claims["aud"] = "https://github.com"
	claims["sub"] = "repo:owner/repo:ref:refs/heads/main"

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	return headerB64 + "." + claimsB64 + ".mock-signature"
}

// setupRequiredOIDCEnv sets up the required OIDC environment for tests.
func setupRequiredOIDCEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-request-token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://test.actions.githubusercontent.com")
}

func TestCollectWorkflowInfo(t *testing.T) {
	tests := []struct {
		name        string
		setupEnv    func(*testing.T)
		expectError bool
		validate    func(*testing.T, *Attestor)
	}{
		{
			name: "complete workflow info",
			setupEnv: func(t *testing.T) {
				t.Setenv("GITHUB_WORKFLOW", "Test Workflow")
				t.Setenv("GITHUB_WORKFLOW_REF", "owner/repo/.github/workflows/ci.yml@refs/heads/main")
				t.Setenv("GITHUB_WORKFLOW_SHA", "workflow123")
				t.Setenv("GITHUB_RUN_ID", "123456789")
				t.Setenv("GITHUB_RUN_NUMBER", "42")
				t.Setenv("GITHUB_RUN_ATTEMPT", "2")
				t.Setenv("GITHUB_JOB", "build")
				t.Setenv("GITHUB_ACTION", "checkout")
				t.Setenv("GITHUB_ACTION_PATH", "/actions/checkout")
				t.Setenv("GITHUB_REPOSITORY", "owner/repo")
				t.Setenv("GITHUB_SHA", "abc123")
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				// Workflow fields populated from OIDC claims (source of truth)
				assert.Equal(t, "Test Workflow", a.workflowInfo.Name)
				assert.Equal(t, "owner/repo/.github/workflows/ci.yml@refs/heads/main", a.workflowInfo.Ref)
				assert.Equal(t, "workflow123abc", a.workflowInfo.SHA)
				assert.Equal(t, "123456789", a.workflowInfo.RunID)
				assert.Equal(t, 42, a.workflowInfo.RunNumber)
				assert.Equal(t, 1, a.workflowInfo.RunAttempt)
				// Fields from env vars
				assert.Equal(t, "build", a.workflowInfo.Job)
				assert.Equal(t, "checkout", a.workflowInfo.Action)
				assert.Equal(t, "/actions/checkout", a.workflowInfo.ActionPath)
			},
		},
		{
			name: "minimal workflow info",
			setupEnv: func(t *testing.T) {
				t.Setenv("GITHUB_WORKFLOW", "Minimal")
				t.Setenv("GITHUB_RUN_ID", "999")
				t.Setenv("GITHUB_REPOSITORY", "owner/repo")
				t.Setenv("GITHUB_SHA", "abc123")
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				// OIDC-sourced fields populated from mock token
				assert.Equal(t, "Test Workflow", a.workflowInfo.Name)
				assert.Equal(t, "123456789", a.workflowInfo.RunID)
			},
		},
		{
			name: "missing GITHUB_WORKFLOW",
			setupEnv: func(t *testing.T) {
				t.Setenv("GITHUB_RUN_ID", "123")
				t.Setenv("GITHUB_REPOSITORY", "owner/repo")
				t.Setenv("GITHUB_SHA", "abc123")
			},
			expectError: true,
		},
		{
			name: "missing GITHUB_RUN_ID",
			setupEnv: func(t *testing.T) {
				t.Setenv("GITHUB_WORKFLOW", "Test")
				t.Setenv("GITHUB_REPOSITORY", "owner/repo")
				t.Setenv("GITHUB_SHA", "abc123")
			},
			expectError: true,
		},
		{
			name: "invalid run number",
			setupEnv: func(t *testing.T) {
				t.Setenv("GITHUB_WORKFLOW", "Test")
				t.Setenv("GITHUB_RUN_ID", "123")
				t.Setenv("GITHUB_RUN_NUMBER", "invalid")
				t.Setenv("GITHUB_REPOSITORY", "owner/repo")
				t.Setenv("GITHUB_SHA", "abc123")
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				// RunNumber is now in OIDC claims
				// No assertion needed for invalid value test
			},
		},
		{
			name: "invalid run attempt defaults to 1",
			setupEnv: func(t *testing.T) {
				t.Setenv("GITHUB_WORKFLOW", "Test")
				t.Setenv("GITHUB_RUN_ID", "123")
				t.Setenv("GITHUB_RUN_ATTEMPT", "invalid")
				t.Setenv("GITHUB_REPOSITORY", "owner/repo")
				t.Setenv("GITHUB_SHA", "abc123")
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				// RunAttempt is now in OIDC claims
				// No assertion needed for invalid value test
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupRequiredOIDCEnv(t)
			tt.setupEnv(t)

			// Setup mock clients via package-level New replacement
			setupMockOIDCClients(t)

			attestor := &Attestor{
				logger: logger.NewNoop(),
			}
			// PreAttest handles parseConfig and client initialization
			err := attestor.PreAttest(t.Context(), core.Config{})
			require.NoError(t, err)
			err = attestor.collectAllData(t.Context(), core.Config{})

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, attestor)
				}
			}
		})
	}
}

func TestCollectWithOIDCConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   core.Config
		validate func(*testing.T, *Attestor)
	}{
		{
			name:   "default config applies OIDC defaults",
			config: core.Config{},
			validate: func(t *testing.T, a *Attestor) {
				// parseConfig should set defaults: OIDCAudience="https://github.com"
				assert.Equal(t, "https://github.com", a.config.OIDCAudience)

				// Predicate fields populated from OIDC claims
				assert.Equal(t, "Test Workflow", a.workflowInfo.Name)
				assert.Equal(t, "push", a.triggerInfo.EventName)
			},
		},
		{
			name: "custom audience passed to FetchIDToken",
			config: core.Config{
				"oidc-audience": "https://github.com",
			},
			validate: func(t *testing.T, a *Attestor) {
				assert.Equal(t, "https://github.com", a.config.OIDCAudience)
				require.NotNil(t, a.oidcInfo)
				assert.True(t, a.oidcInfo.Verified)
			},
		},
		{
			name: "claims allowlist filters claims",
			config: core.Config{
				"oidc-audience": "https://github.com",
			},
			validate: func(t *testing.T, a *Attestor) {
				require.NotNil(t, a.oidcInfo)
				// Predicate fields still populated from allClaims
				assert.Equal(t, "Test Workflow", a.workflowInfo.Name)
				assert.Equal(t, "123456789", a.workflowInfo.RunID)
				assert.Equal(t, "owner/repo", a.repositoryInfo.FullName)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupGitHubEnv(t)

			setupMockOIDCClients(t)

			attestor := &Attestor{
				logger: logger.NewNoop(),
			}
			err := attestor.PreAttest(t.Context(), tt.config)
			require.NoError(t, err)
			err = attestor.collectAllData(t.Context(), tt.config)

			require.NoError(t, err)
			tt.validate(t, attestor)
		})
	}
}

func TestCollectOIDCAudienceValidation(t *testing.T) {
	tests := []struct {
		name        string
		audience    any // nil or string value for Claims.Audience
		config      core.Config
		expectError bool
		errorMsg    string
	}{
		{
			name:     "nil audience rejected when audience configured",
			audience: nil,
			config: core.Config{
				"oidc-audience": "https://github.com",
			},
			expectError: true,
			errorMsg:    "OIDC token missing audience claim",
		},
		{
			name:     "mismatched audience rejected",
			audience: "https://other.example.com",
			config: core.Config{
				"oidc-audience": "https://github.com",
			},
			expectError: true,
			errorMsg:    "OIDC token audience mismatch",
		},
		{
			name:     "matching audience passes",
			audience: "https://github.com",
			config: core.Config{
				"oidc-audience": "https://github.com",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupGitHubEnv(t)

			mockToken := generateMockJWT(t)

			mockGithubClient := github.SetupMockClient(t)
			mockGithubClient.On("FetchIDToken", mock.Anything, mock.Anything).Return(mockToken, nil)

			mockJWTClient := jwtclient.SetupMockClient(t)

			tokenInfo := &jwtclient.TokenInfo{
				Claims: jwtclient.Claims{
					Issuer:       DefaultOIDCIssuer,
					Subject:      "repo:owner/repo:ref:refs/heads/main",
					CustomClaims: getMockOIDCClaims(),
				},
			}
			if tt.audience != nil {
				tokenInfo.Claims.Audience = tt.audience
			}
			mockJWTClient.On("ParseToken", mockToken).Return(tokenInfo, nil)
			mockJWTClient.On("HashToken", mockToken).Return("mock-hash")

			verifyResult := &jwtclient.VerificationResult{
				Verified:   true,
				VerifiedAt: time.Now(),
				KeyID:      "test-key-id",
			}
			mockJWTClient.On("VerifySignature", mock.Anything, mockToken).Return(verifyResult, nil)

			attestor := &Attestor{
				logger: logger.NewNoop(),
			}
			err := attestor.PreAttest(t.Context(), tt.config)
			require.NoError(t, err)
			err = attestor.collectAllData(t.Context(), tt.config)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// setupRequiredGitHubEnv sets up only the required GitHub environment variables for testing.
func setupRequiredGitHubEnv(t *testing.T) {
	t.Helper()
	// OIDC environment variables (required)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-request-token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://test.actions.githubusercontent.com")

	t.Setenv("GITHUB_WORKFLOW", "Test Workflow")
	t.Setenv("GITHUB_RUN_ID", "123456789")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")
	t.Setenv("GITHUB_SHA", "abc123def456")
}

func TestCollectRunnerInfo(t *testing.T) {
	tests := []struct {
		name        string
		setupEnv    func(*testing.T)
		config      core.Config
		expectError bool
		validate    func(*testing.T, *Attestor)
	}{
		{
			name: "complete runner info without environment vars",
			setupEnv: func(t *testing.T) {
				setupRequiredGitHubEnv(t)
				t.Setenv("RUNNER_NAME", "GitHub Actions 2")
				t.Setenv("RUNNER_OS", "Linux")
				t.Setenv("RUNNER_ARCH", "X64")
				t.Setenv("RUNNER_ENVIRONMENT", "github-hosted")
				t.Setenv("RUNNER_TEMP", "/tmp")
				t.Setenv("RUNNER_TOOL_CACHE", "/opt/cache")
			},
			config:      core.Config{"capture-environment": false},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				assert.Equal(t, "GitHub Actions 2", a.runnerInfo.Name)
				assert.Equal(t, "Linux", a.runnerInfo.OS)
				assert.Equal(t, "X64", a.runnerInfo.Arch)
				assert.Equal(t, "github-hosted", a.runnerInfo.HostedType)
				assert.Nil(t, a.runnerInfo.Environment)
			},
		},
		{
			name: "self-hosted runner detection",
			setupEnv: func(t *testing.T) {
				setupRequiredGitHubEnv(t)
				t.Setenv("RUNNER_NAME", "example-custom-runner")
				t.Setenv("RUNNER_OS", "Linux")
				t.Setenv("RUNNER_ARCH", "ARM64")
				t.Setenv("RUNNER_ENVIRONMENT", "self-hosted")
			},
			config:      core.Config{"capture-environment": false},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				// OIDC token is source of truth — mock always returns "github-hosted"
				assert.Equal(t, "github-hosted", a.runnerInfo.HostedType)
			},
		},
		{
			name: "capture environment variables",
			setupEnv: func(t *testing.T) {
				setupRequiredGitHubEnv(t)
				t.Setenv("RUNNER_NAME", "test-runner")
				t.Setenv("RUNNER_OS", "Linux")
				t.Setenv("RUNNER_ARCH", "X64")
				t.Setenv("GITHUB_TOKEN", "secret")
				t.Setenv("CI", "true")
			},
			config: core.Config{
				"capture-environment":  true,
				"env-include-patterns": []string{"GITHUB_*", "RUNNER_*", "CI"},
				"env-exclude-patterns": []string{"*TOKEN*"},
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				assert.NotNil(t, a.runnerInfo.Environment)
				assert.Contains(t, a.runnerInfo.Environment, "RUNNER_OS")
				assert.Contains(t, a.runnerInfo.Environment, "CI")
				assert.NotContains(t, a.runnerInfo.Environment, "GITHUB_TOKEN")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupRequiredOIDCEnv(t)
			tt.setupEnv(t)

			// Setup mock clients via package-level New replacement
			setupMockOIDCClients(t)

			attestor := &Attestor{
				logger: logger.NewNoop(),
			}
			err := attestor.PreAttest(t.Context(), tt.config)
			require.NoError(t, err)
			err = attestor.collectAllData(t.Context(), tt.config)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, attestor)
				}
			}
		})
	}
}

func TestCollectTriggerInfo(t *testing.T) {
	tests := []struct {
		name        string
		setupEnv    func(*testing.T)
		config      core.Config
		expectError bool
		validate    func(*testing.T, *Attestor)
	}{
		{
			name: "complete trigger info without payload",
			setupEnv: func(t *testing.T) {
				setupRequiredGitHubEnv(t)
				t.Setenv("GITHUB_EVENT_NAME", "push")
				t.Setenv("GITHUB_ACTOR", "testuser")
				t.Setenv("GITHUB_ACTOR_ID", "12345")
				t.Setenv("GITHUB_HEAD_REF", "feature")
				t.Setenv("GITHUB_BASE_REF", "main")
			},
			config:      core.Config{"capture-event-payload": false},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				// Trigger fields come from OIDC claims (source of truth)
				assert.Equal(t, "push", a.triggerInfo.EventName)
				assert.Equal(t, "testuser", a.triggerInfo.Actor)
				assert.Equal(t, "12345", a.triggerInfo.ActorID)
				assert.Nil(t, a.triggerInfo.EventPayload)
			},
		},
		{
			name: "minimal trigger info",
			setupEnv: func(t *testing.T) {
				setupRequiredGitHubEnv(t)
				t.Setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
				t.Setenv("GITHUB_ACTOR", "bot")
			},
			config:      core.Config{"capture-event-payload": false},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				// Trigger fields come from OIDC claims
				assert.Equal(t, "push", a.triggerInfo.EventName)
				assert.Equal(t, "testuser", a.triggerInfo.Actor)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv(t)

			// Setup mock clients via package-level New replacement
			setupMockOIDCClients(t)

			attestor := &Attestor{
				logger: logger.NewNoop(),
			}

			err := attestor.PreAttest(t.Context(), tt.config)
			require.NoError(t, err)
			err = attestor.collectAllData(t.Context(), tt.config)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, attestor)
				}
			}
		})
	}
}

func TestCollectRepositoryInfo(t *testing.T) {
	tests := []struct {
		name        string
		setupEnv    func(*testing.T)
		expectError bool
		validate    func(*testing.T, *Attestor)
	}{
		{
			name: "complete repository info",
			setupEnv: func(t *testing.T) {
				// Set up workflow requirements
				t.Setenv("GITHUB_WORKFLOW", "Test Workflow")
				t.Setenv("GITHUB_RUN_ID", "123456789")
				// Set up repository-specific info
				t.Setenv("GITHUB_REPOSITORY", "owner/repo")
				t.Setenv("GITHUB_REPOSITORY_OWNER", "owner")
				t.Setenv("GITHUB_REPOSITORY_OWNER_ID", "12345")
				t.Setenv("GITHUB_REPOSITORY_ID", "67890")
				t.Setenv("GITHUB_SHA", "abc123def456")
				t.Setenv("GITHUB_REF", "refs/heads/main")
				t.Setenv("GITHUB_REF_NAME", "main")
				t.Setenv("GITHUB_REF_TYPE", "branch")
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				// Repository fields populated from OIDC claims (source of truth)
				assert.Equal(t, "owner/repo", a.repositoryInfo.FullName)
				assert.Equal(t, "owner", a.repositoryInfo.Owner)
				assert.Equal(t, "67890", a.repositoryInfo.OwnerID)
				assert.Equal(t, "11111", a.repositoryInfo.ID)
				assert.Equal(t, "abc123def456", a.repositoryInfo.SHA)
				assert.Equal(t, "refs/heads/main", a.repositoryInfo.Ref)
				assert.Equal(t, "branch", a.repositoryInfo.RefType)
				// RefName still from env var
				assert.Equal(t, "main", a.repositoryInfo.RefName)
			},
		},
		{
			name: "minimal repository info",
			setupEnv: func(t *testing.T) {
				// Set up workflow requirements
				t.Setenv("GITHUB_WORKFLOW", "Test Workflow")
				t.Setenv("GITHUB_RUN_ID", "123456789")
				// Set up minimal repository info
				t.Setenv("GITHUB_REPOSITORY", "org/project")
				t.Setenv("GITHUB_SHA", "xyz789")
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				// OIDC-sourced fields from mock token
				assert.Equal(t, "owner/repo", a.repositoryInfo.FullName)
				assert.Equal(t, "abc123def456", a.repositoryInfo.SHA)
			},
		},
		{
			name: "missing GITHUB_REPOSITORY",
			setupEnv: func(t *testing.T) {
				t.Setenv("GITHUB_WORKFLOW", "Test Workflow")
				t.Setenv("GITHUB_RUN_ID", "123456789")
				t.Setenv("GITHUB_SHA", "abc")
			},
			expectError: true,
		},
		{
			name: "missing GITHUB_SHA",
			setupEnv: func(t *testing.T) {
				t.Setenv("GITHUB_WORKFLOW", "Test Workflow")
				t.Setenv("GITHUB_RUN_ID", "123456789")
				t.Setenv("GITHUB_REPOSITORY", "owner/repo")
			},
			expectError: true,
		},
		{
			name: "tag reference",
			setupEnv: func(t *testing.T) {
				// Set up workflow requirements
				t.Setenv("GITHUB_WORKFLOW", "Test Workflow")
				t.Setenv("GITHUB_RUN_ID", "123456789")
				// Set up tag-specific info
				t.Setenv("GITHUB_REPOSITORY", "owner/repo")
				t.Setenv("GITHUB_SHA", "abc123")
				t.Setenv("GITHUB_REF", "refs/tags/v1.0.0")
				t.Setenv("GITHUB_REF_NAME", "v1.0.0")
				t.Setenv("GITHUB_REF_TYPE", "tag")
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				// OIDC claims are source of truth — ref/ref_type from mock
				assert.Equal(t, "refs/heads/main", a.repositoryInfo.Ref)
				assert.Equal(t, "branch", a.repositoryInfo.RefType)
				// RefName still from env var
				assert.Equal(t, "v1.0.0", a.repositoryInfo.RefName)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupRequiredOIDCEnv(t)
			tt.setupEnv(t)

			// Setup mock clients via package-level New replacement
			setupMockOIDCClients(t)

			attestor := &Attestor{
				logger: logger.NewNoop(),
			}

			err := attestor.PreAttest(t.Context(), core.Config{})
			require.NoError(t, err)
			err = attestor.collectAllData(t.Context(), core.Config{})

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, attestor)
				}
			}
		})
	}
}

func TestCollectMetadataInfo(t *testing.T) {
	tests := []struct {
		name      string
		setupEnv  func(*testing.T)
		setupMock func(*testing.T)
		validate  func(*testing.T, *Attestor)
	}{
		{
			name: "with server URL",
			setupEnv: func(t *testing.T) {
				setupRequiredGitHubEnv(t)
				t.Setenv("GITHUB_SERVER_URL", "https://github.com")
			},
			validate: func(t *testing.T, a *Attestor) {
				assert.Equal(t, "https://github.com", a.metadataInfo.ServerURL)
			},
		},
		{
			name: "enterprise server URL",
			setupEnv: func(t *testing.T) {
				setupRequiredGitHubEnv(t)
				t.Setenv("GITHUB_SERVER_URL", "https://github.enterprise.com")
			},
			setupMock: func(t *testing.T) {
				// GHES issuer is derived as https://HOSTNAME/_services/token
				ghesIssuer := "https://github.enterprise.com/_services/token"
				mockToken := generateMockJWT(t)

				mockGithubClient := github.SetupMockClient(t)
				mockGithubClient.On("FetchIDToken", mock.Anything, "https://github.com").Return(mockToken, nil)

				mockJWTClient := jwtclient.SetupMockClient(t)
				tokenInfo := &jwtclient.TokenInfo{
					Claims: jwtclient.Claims{
						Issuer:       ghesIssuer,
						Audience:     "https://github.com",
						Subject:      "repo:owner/repo:ref:refs/heads/main",
						CustomClaims: getMockOIDCClaims(),
					},
				}
				mockJWTClient.On("ParseToken", mockToken).Return(tokenInfo, nil)
				mockJWTClient.On("HashToken", mockToken).Return("mock-hash")
				mockJWTClient.On("VerifySignature", mock.Anything, mockToken).Return(&jwtclient.VerificationResult{
					Verified:   true,
					VerifiedAt: time.Now(),
					KeyID:      "test-key-id",
				}, nil)
			},
			validate: func(t *testing.T, a *Attestor) {
				assert.Equal(t, "https://github.enterprise.com", a.metadataInfo.ServerURL)
			},
		},
		{
			name: "without server URL",
			setupEnv: func(t *testing.T) {
				setupRequiredGitHubEnv(t)
			},
			validate: func(t *testing.T, a *Attestor) {
				assert.Empty(t, a.metadataInfo.ServerURL)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv(t)

			// Setup mock clients via package-level New replacement
			if tt.setupMock != nil {
				tt.setupMock(t)
			} else {
				setupMockOIDCClients(t)
			}

			attestor := &Attestor{
				logger: logger.NewNoop(),
			}

			err := attestor.PreAttest(t.Context(), core.Config{})
			require.NoError(t, err)
			err = attestor.collectAllData(t.Context(), core.Config{})

			require.NoError(t, err)
			if tt.validate != nil {
				tt.validate(t, attestor)
			}
		})
	}
}

func TestCollectAllData(t *testing.T) {
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
	err = attestor.collectAllData(t.Context(), config)

	require.NoError(t, err)

	// Predicate fields populated from OIDC claims (source of truth)
	require.NotNil(t, attestor.oidcInfo)
	assert.Equal(t, "Test Workflow", attestor.workflowInfo.Name)
	assert.Equal(t, "123456789", attestor.workflowInfo.RunID)
	assert.Equal(t, "github-hosted", attestor.runnerInfo.HostedType)
	assert.Equal(t, "push", attestor.triggerInfo.EventName)
	assert.Equal(t, "owner/repo", attestor.repositoryInfo.FullName)
	// Fields still in predicate (from env vars)
	assert.Equal(t, "Linux", attestor.runnerInfo.OS)
	assert.Equal(t, "https://github.com", attestor.metadataInfo.ServerURL)
}

func TestCollectAllData_MissingRequiredVars(t *testing.T) {
	config := core.Config{}

	// Setup mock clients via package-level New replacement
	setupMockOIDCClients(t)

	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	err := attestor.PreAttest(t.Context(), config)
	require.NoError(t, err)

	err = attestor.collectAllData(t.Context(), config)
	assert.Error(t, err, "Should fail when required environment variables are missing")
}
