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

package buildenv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	githubclient "github.com/thomsonreuters/stamp/pkg/clients/github"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// --- Tests for GitHubEnvironment methods (using pre-populated oidcClaims) ---

func newTestGitHubEnv(claims map[string]any, ghCtx *GitHubContext, opts DetectOptions) *GitHubEnvironment {
	if ghCtx == nil {
		ghCtx = &GitHubContext{}
	}
	return &GitHubEnvironment{
		logger:        logger.NewNoop(),
		opts:          opts,
		githubContext: ghCtx,
		oidcClaims:    claims,
	}
}

func TestGitHubEnvironment_Type(t *testing.T) {
	env := newTestGitHubEnv(nil, nil, DetectOptions{})
	assert.Equal(t, EnvironmentGitHub, env.Type())
}

func TestGitHubEnvironment_BuilderID(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{}, nil, DetectOptions{})

	id := env.BuilderID(t.Context())
	assert.Equal(t, BuilderIDGitHub, id)
}

func TestGitHubEnvironment_SourceURI(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{
		"repository": "exampleorg/examplerepo",
		"ref":        "refs/heads/main",
	}, &GitHubContext{ServerURL: "https://github.com"}, DetectOptions{})

	assert.Equal(t, "git+https://github.com/exampleorg/examplerepo@refs/heads/main", env.SourceURI())
}

func TestGitHubEnvironment_SourceURI_NoRef(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{
		"repository": "exampleorg/examplerepo",
	}, &GitHubContext{ServerURL: "https://github.com"}, DetectOptions{})

	assert.Equal(t, "git+https://github.com/exampleorg/examplerepo", env.SourceURI())
}

func TestGitHubEnvironment_SourceURI_DefaultServerURL(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{
		"repository": "exampleorg/examplerepo",
		"ref":        "refs/tags/v1.0.0",
	}, &GitHubContext{}, DetectOptions{})

	assert.Equal(t, "git+https://github.com/exampleorg/examplerepo@refs/tags/v1.0.0", env.SourceURI())
}

func TestGitHubEnvironment_SourceDigest(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{
		"sha": "abc123def456",
	}, nil, DetectOptions{})

	digest := env.SourceDigest()
	assert.Equal(t, map[string]string{"gitCommit": "abc123def456"}, digest)
}

func TestGitHubEnvironment_SourceDigest_Empty(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{}, nil, DetectOptions{})
	assert.Nil(t, env.SourceDigest())
}

func TestGitHubEnvironment_InternalParameters(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{
		"run_number":          "42",
		"run_id":              "12345",
		"run_attempt":         "1",
		"event_name":          "push",
		"ref_type":            "branch",
		"ref":                 "refs/heads/main",
		"base_ref":            "",
		"head_ref":            "",
		"actor":               "testuser",
		"sha":                 "abc123",
		"repository_owner":    "exampleorg",
		"repository_id":       "99999",
		"actor_id":            "12345",
		"repository_owner_id": "67890",
	}, &GitHubContext{
		Arch: "X64",
		OS:   "ubuntu22",
	}, DetectOptions{})

	params := env.InternalParameters()

	assert.Equal(t, "X64", params["arch"])
	assert.Equal(t, "ubuntu22", params["os"])
	assert.Equal(t, "42", params["github_run_number"])
	assert.Equal(t, "12345", params["github_run_id"])
	assert.Equal(t, "1", params["github_run_attempt"])
	assert.Equal(t, "push", params["github_event_name"])
	assert.Equal(t, "branch", params["github_ref_type"])
	assert.Equal(t, "refs/heads/main", params["github_ref"])
	assert.Equal(t, "testuser", params["github_actor"])
	assert.Equal(t, "abc123", params["github_sha1"])
	assert.Equal(t, "exampleorg", params["github_repository_owner"])
	assert.Equal(t, "99999", params["github_repository_id"])
	assert.Equal(t, "12345", params["github_actor_id"])
	assert.Equal(t, "67890", params["github_repository_owner_id"])
}

func TestGitHubEnvironment_InternalParameters_CaptureEventPayload(t *testing.T) {
	event := map[string]any{"action": "opened", "number": float64(1)}

	env := newTestGitHubEnv(map[string]any{}, &GitHubContext{
		Event: event,
	}, DetectOptions{CaptureEventPayload: true})

	params := env.InternalParameters()
	assert.Equal(t, event, params["github_event_payload"])
}

func TestGitHubEnvironment_InternalParameters_NoCaptureEventPayload(t *testing.T) {
	event := map[string]any{"action": "opened"}

	env := newTestGitHubEnv(map[string]any{}, &GitHubContext{
		Event: event,
	}, DetectOptions{CaptureEventPayload: false})

	params := env.InternalParameters()
	_, exists := params["github_event_payload"]
	assert.False(t, exists)
}

func TestGitHubEnvironment_InternalParameters_EmptyClaimsOmitted(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{}, &GitHubContext{}, DetectOptions{})

	params := env.InternalParameters()
	_, hasArch := params["arch"]
	_, hasRunNumber := params["github_run_number"]
	assert.False(t, hasArch)
	assert.False(t, hasRunNumber)
}

func TestGitHubEnvironment_ResolvedDependencies_Basic(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{
		"repository": "exampleorg/examplerepo",
		"ref":        "refs/heads/main",
		"sha":        "abc123",
	}, &GitHubContext{ServerURL: "https://github.com"}, DetectOptions{})

	deps := env.ResolvedDependencies()
	require.GreaterOrEqual(t, len(deps), 1)

	assert.Equal(t, "git+https://github.com/exampleorg/examplerepo@refs/heads/main", deps[0].URI)
	assert.Equal(t, map[string]string{"gitCommit": "abc123"}, deps[0].Digest)
}

func TestGitHubEnvironment_ResolvedDependencies_WithRunnerImage(t *testing.T) {
	t.Setenv("ImageOS", "ubuntu22")
	t.Setenv("ImageVersion", "20240101.1")

	env := newTestGitHubEnv(map[string]any{
		"repository": "exampleorg/examplerepo",
		"ref":        "refs/heads/main",
		"sha":        "abc123",
	}, &GitHubContext{ServerURL: "https://github.com"}, DetectOptions{})

	deps := env.ResolvedDependencies()
	require.GreaterOrEqual(t, len(deps), 2)

	lastDep := deps[len(deps)-1]
	assert.Equal(t, "https://github.com/actions/runner-images/releases/tag/ubuntu22/20240101.1", lastDep.URI)
}

func TestGitHubEnvironment_InvocationID(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{
		"run_id":      "12345",
		"run_attempt": "2",
	}, nil, DetectOptions{})

	assert.Equal(t, "12345-2", env.InvocationID())
}

func TestGitHubEnvironment_InvocationID_NoAttempt(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{
		"run_id": "12345",
	}, nil, DetectOptions{})

	assert.Equal(t, "12345", env.InvocationID())
}

func TestGitHubEnvironment_WorkflowInputs_WithEventInputs(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{}, &GitHubContext{
		Event: map[string]any{
			"inputs": map[string]any{"branch": "develop", "deploy": "true"},
		},
	}, DetectOptions{})

	result := env.WorkflowInputs()
	require.NotNil(t, result)

	params, ok := result.(WorkflowParameters)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"branch": "develop", "deploy": "true"}, params.EventInputs)
	assert.Nil(t, params.VarsContext)
}

func TestGitHubEnvironment_WorkflowInputs_WithVars(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{}, &GitHubContext{
		Vars: map[string]any{"ENV_NAME": "staging"},
	}, DetectOptions{})

	result := env.WorkflowInputs()
	require.NotNil(t, result)

	params, ok := result.(WorkflowParameters)
	require.True(t, ok)
	assert.Nil(t, params.EventInputs)
	assert.Equal(t, map[string]any{"ENV_NAME": "staging"}, params.VarsContext)
}

func TestGitHubEnvironment_WorkflowInputs_Both(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{}, &GitHubContext{
		Event: map[string]any{"inputs": map[string]any{"branch": "main"}},
		Vars:  map[string]any{"ENV_NAME": "prod"},
	}, DetectOptions{})

	result := env.WorkflowInputs()
	require.NotNil(t, result)

	params, ok := result.(WorkflowParameters)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"branch": "main"}, params.EventInputs)
	assert.Equal(t, map[string]any{"ENV_NAME": "prod"}, params.VarsContext)
}

func TestGitHubEnvironment_WorkflowInputs_NilWhenEmpty(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{}, &GitHubContext{}, DetectOptions{})
	assert.Nil(t, env.WorkflowInputs())
}

func TestGitHubEnvironment_Context(t *testing.T) {
	ghCtx := &GitHubContext{Repository: "exampleorg/examplerepo"}
	env := newTestGitHubEnv(nil, ghCtx, DetectOptions{})
	assert.Same(t, ghCtx, env.Context())
}

// --- Tests for getStringClaim ---

func TestGetStringClaim_String(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{"key": "value"}, nil, DetectOptions{})
	assert.Equal(t, "value", env.getStringClaim("key"))
}

func TestGetStringClaim_Float64(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{"num": float64(12345)}, nil, DetectOptions{})
	assert.Equal(t, "12345", env.getStringClaim("num"))
}

func TestGetStringClaim_OtherType(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{"flag": true}, nil, DetectOptions{})
	assert.Equal(t, "true", env.getStringClaim("flag"))
}

func TestGetStringClaim_Missing(t *testing.T) {
	env := newTestGitHubEnv(map[string]any{"key": "value"}, nil, DetectOptions{})
	assert.Empty(t, env.getStringClaim("nonexistent"))
}

func TestGetStringClaim_NilClaims(t *testing.T) {
	env := newTestGitHubEnv(nil, nil, DetectOptions{})
	assert.Empty(t, env.getStringClaim("anything"))
}

// --- Tests for serverURL ---

func TestServerURL_FromContext(t *testing.T) {
	env := newTestGitHubEnv(nil, &GitHubContext{ServerURL: "https://github.example.com"}, DetectOptions{})
	assert.Equal(t, "https://github.example.com", env.serverURL())
}

func TestServerURL_Default(t *testing.T) {
	env := newTestGitHubEnv(nil, &GitHubContext{}, DetectOptions{})
	assert.Equal(t, "https://github.com", env.serverURL())
}

// --- Tests for resolveOIDCIssuers ---

func TestResolveOIDCIssuers_Default(t *testing.T) {
	t.Setenv("GITHUB_SERVER_URL", "")
	env := newTestGitHubEnv(nil, nil, DetectOptions{})
	issuers := env.resolveOIDCIssuers()
	assert.Contains(t, issuers, githubclient.DefaultOIDCIssuer)
}

func TestResolveOIDCIssuers_GHES(t *testing.T) {
	t.Setenv("GITHUB_SERVER_URL", "https://github.examplecompany.com")
	env := newTestGitHubEnv(nil, nil, DetectOptions{})
	issuers := env.resolveOIDCIssuers()
	assert.NotEmpty(t, issuers)
}

// --- Tests for parseGitHubContext ---

func TestParseGitHubContext_Valid(t *testing.T) {
	ghContext := map[string]any{
		"repository":       "exampleorg/examplerepo",
		"repository_owner": "exampleorg",
		"sha":              "abc123",
		"ref":              "refs/heads/main",
		"ref_type":         "branch",
		"base_ref":         "",
		"head_ref":         "",
		"actor":            "testuser",
		"event_name":       "push",
		"event":            map[string]any{"action": "completed"},
		"vars":             map[string]any{"MY_VAR": "value"},
		"run_number":       "42",
		"run_id":           "12345",
		"run_attempt":      "1",
		"workflow":         "CI",
		"server_url":       "https://github.com",
	}
	data, _ := json.Marshal(ghContext)
	t.Setenv("GITHUB_CONTEXT", string(data))

	ctx, err := parseGitHubContext()
	require.NoError(t, err)

	assert.Equal(t, "exampleorg/examplerepo", ctx.Repository)
	assert.Equal(t, "exampleorg", ctx.RepositoryOwner)
	assert.Equal(t, "abc123", ctx.SHA)
	assert.Equal(t, "refs/heads/main", ctx.Ref)
	assert.Equal(t, "branch", ctx.RefType)
	assert.Equal(t, "testuser", ctx.Actor)
	assert.Equal(t, "push", ctx.EventName)
	assert.Equal(t, map[string]any{"action": "completed"}, ctx.Event)
	assert.Equal(t, map[string]any{"MY_VAR": "value"}, ctx.Vars)
	assert.Equal(t, "42", ctx.RunNumber)
	assert.Equal(t, "12345", ctx.RunID)
	assert.Equal(t, "1", ctx.RunAttempt)
	assert.Equal(t, "CI", ctx.Workflow)
	assert.Equal(t, "https://github.com", ctx.ServerURL)
}

func TestParseGitHubContext_NotSet(t *testing.T) {
	t.Setenv("GITHUB_CONTEXT", "")
	_, err := parseGitHubContext()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not set")
}

func TestParseGitHubContext_InvalidJSON(t *testing.T) {
	t.Setenv("GITHUB_CONTEXT", "not-json{{{")
	_, err := parseGitHubContext()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing GITHUB_CONTEXT")
}

func TestParseGitHubContext_IncludesRunnerEnv(t *testing.T) {
	ghContext := map[string]any{"repository": "exampleorg/examplerepo"}
	data, _ := json.Marshal(ghContext)
	t.Setenv("GITHUB_CONTEXT", string(data))
	t.Setenv("RUNNER_ARCH", "ARM64")
	t.Setenv("ImageOS", "ubuntu22")

	ctx, err := parseGitHubContext()
	require.NoError(t, err)
	assert.Equal(t, "ARM64", ctx.Arch)
	assert.Equal(t, "ubuntu22", ctx.OS)
}

// --- Tests for collectGitHubContextFromEnv ---

func TestCollectGitHubContextFromEnv(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "exampleorg/examplerepo")
	t.Setenv("GITHUB_REPOSITORY_OWNER", "exampleorg")
	t.Setenv("GITHUB_SHA", "def456")
	t.Setenv("GITHUB_REF", "refs/tags/v1.0.0")
	t.Setenv("GITHUB_REF_TYPE", "tag")
	t.Setenv("GITHUB_ACTOR", "releasebot")
	t.Setenv("GITHUB_EVENT_NAME", "release")
	t.Setenv("GITHUB_RUN_ID", "99999")
	t.Setenv("GITHUB_RUN_NUMBER", "10")
	t.Setenv("GITHUB_RUN_ATTEMPT", "1")
	t.Setenv("GITHUB_WORKFLOW", "Release")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("RUNNER_ARCH", "X64")
	t.Setenv("ImageOS", "ubuntu22")
	t.Setenv("GITHUB_EVENT_PATH", "")

	ctx, err := collectGitHubContextFromEnv()
	require.NoError(t, err)

	assert.Equal(t, "exampleorg/examplerepo", ctx.Repository)
	assert.Equal(t, "exampleorg", ctx.RepositoryOwner)
	assert.Equal(t, "def456", ctx.SHA)
	assert.Equal(t, "refs/tags/v1.0.0", ctx.Ref)
	assert.Equal(t, "tag", ctx.RefType)
	assert.Equal(t, "releasebot", ctx.Actor)
	assert.Equal(t, "release", ctx.EventName)
	assert.Equal(t, "99999", ctx.RunID)
	assert.Equal(t, "10", ctx.RunNumber)
	assert.Equal(t, "1", ctx.RunAttempt)
	assert.Equal(t, "Release", ctx.Workflow)
	assert.Equal(t, "https://github.com", ctx.ServerURL)
	assert.Equal(t, "X64", ctx.Arch)
	assert.Equal(t, "ubuntu22", ctx.OS)
}

func TestCollectGitHubContextFromEnv_WithEventPath(t *testing.T) {
	tmpDir := t.TempDir()
	eventFile := filepath.Join(tmpDir, "event.json")
	payload := map[string]any{"action": "opened", "number": float64(5)}
	data, _ := json.Marshal(payload)
	err := os.WriteFile(eventFile, data, 0o644)
	require.NoError(t, err)

	t.Setenv("GITHUB_EVENT_PATH", eventFile)
	t.Setenv("GITHUB_REPOSITORY", "exampleorg/examplerepo")

	ctx, err := collectGitHubContextFromEnv()
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"action": "opened", "number": float64(5)}, ctx.Event)
}

func TestCollectGitHubContextFromEnv_InvalidEventPath(t *testing.T) {
	t.Setenv("GITHUB_EVENT_PATH", "/nonexistent/path.json")
	t.Setenv("GITHUB_REPOSITORY", "exampleorg/examplerepo")

	ctx, err := collectGitHubContextFromEnv()
	require.Error(t, err)
	assert.Nil(t, ctx.Event)
}

// --- Tests for GitHubEnvironment.Detect ---

func TestGitHubEnvironment_Detect_NotGitHubActions(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")

	env := NewGitHubEnvironment(logger.NewNoop(), DetectOptions{})
	_, err := env.Detect(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a GitHub Actions environment")
}

func TestGitHubEnvironment_Detect_OIDCNotAvailable(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")

	env := NewGitHubEnvironment(logger.NewNoop(), DetectOptions{})
	_, err := env.Detect(t.Context())
	require.Error(t, err)

	var fatal *DetectionFatalError
	require.ErrorAs(t, err, &fatal)
	assert.Contains(t, err.Error(), "OIDC")
}

// --- Tests for NewGitHubEnvironment ---

func TestNewGitHubEnvironment(t *testing.T) {
	log := logger.NewNoop()
	opts := DetectOptions{
		BuilderID:           "custom-builder",
		CaptureEventPayload: true,
	}

	env := NewGitHubEnvironment(log, opts)
	require.NotNil(t, env)
	assert.Equal(t, opts, env.opts)
}

func TestNormalizeGitHubImageVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Three components - trim to two",
			input:    "20260518.146.0",
			expected: "20260518.146",
		},
		{
			name:     "Two components - keep as is",
			input:    "20260518.146",
			expected: "20260518.146",
		},
		{
			name:     "Four components - trim to two",
			input:    "20260518.146.0.1",
			expected: "20260518.146",
		},
		{
			name:     "Single component - keep as is",
			input:    "20260518",
			expected: "20260518",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeGitHubImageVersion(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
