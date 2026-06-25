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

package gobuilder

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/buildenv"
	cryptohash "github.com/thomsonreuters/stamp/pkg/crypto/hash"
	"github.com/thomsonreuters/stamp/pkg/executor"
	"github.com/thomsonreuters/stamp/pkg/logger"
	gobuilderpredicate "github.com/thomsonreuters/stamp/pkg/predicates/go-builder/v1"
)

// fullMockBuildEnv implements buildenv.BuildEnvironment with configurable return values.
type fullMockBuildEnv struct {
	envType        string
	builderID      string
	sourceURI      string
	sourceDigest   map[string]string
	internalParams map[string]any
	resolvedDeps   []buildenv.ResourceDescriptor
	invocationID   string
	workflowInputs any
}

func (m *fullMockBuildEnv) Type() buildenv.EnvironmentType {
	return buildenv.EnvironmentType(m.envType)
}
func (m *fullMockBuildEnv) BuilderID(_ context.Context) string { return m.builderID }
func (m *fullMockBuildEnv) SourceURI() string                  { return m.sourceURI }
func (m *fullMockBuildEnv) SourceDigest() map[string]string    { return m.sourceDigest }
func (m *fullMockBuildEnv) InternalParameters() map[string]any { return m.internalParams }
func (m *fullMockBuildEnv) ResolvedDependencies() []buildenv.ResourceDescriptor {
	return m.resolvedDeps
}
func (m *fullMockBuildEnv) InvocationID() string { return m.invocationID }
func (m *fullMockBuildEnv) WorkflowInputs() any  { return m.workflowInputs }

// --- Tests for extractProvenanceFields ---

func TestExtractProvenanceFields_AllFieldsPopulated(t *testing.T) {
	mock := &fullMockBuildEnv{
		envType:   "github-actions",
		builderID: "https://github.com/slsa-framework/slsa-github-generator/go@v1",
		sourceURI: "git+https://github.com/exampleorg/examplerepo@refs/heads/main",
		sourceDigest: map[string]string{
			"gitCommit": "abc123def456",
		},
		internalParams: map[string]any{
			"GITHUB_RUN_ID":      "12345",
			"GITHUB_RUN_ATTEMPT": "1",
		},
		resolvedDeps: []buildenv.ResourceDescriptor{
			{
				Name: "source",
				URI:  "git+https://github.com/exampleorg/examplerepo@refs/heads/main",
				Digest: map[string]string{
					"gitCommit": "abc123def456",
				},
			},
			{
				Name:   "runner-image",
				URI:    "https://github.com/actions/runner-images",
				Digest: map[string]string{"sha256": "deadbeef"},
			},
		},
		invocationID:   "12345-1",
		workflowInputs: map[string]any{"branch": "main", "deploy": "true"},
	}

	a := &Attestor{
		logger:   logger.NewNoop(),
		buildEnv: mock,
		config:   Config{},
	}
	a.metadata.StartedOn = "2026-01-01T00:00:00Z"

	a.extractProvenanceFields(t.Context())

	assert.Equal(t, "git+https://github.com/exampleorg/examplerepo@refs/heads/main", a.sourceURI)
	assert.Equal(t, "https://github.com/slsa-framework/slsa-github-generator/go@v1", a.builderID)
	assert.Equal(t, map[string]any{"GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "1"}, a.internalParams)
	assert.Equal(t, map[string]any{"branch": "main", "deploy": "true"}, a.workflowInputs)

	require.Len(t, a.resolvedDeps, 2)
	assert.Equal(t, "source", a.resolvedDeps[0].Name)
	assert.Equal(t, "git+https://github.com/exampleorg/examplerepo@refs/heads/main", a.resolvedDeps[0].URI)
	assert.Equal(t, map[string]string{"gitCommit": "abc123def456"}, a.resolvedDeps[0].Digest)
	assert.Equal(t, "runner-image", a.resolvedDeps[1].Name)
	assert.Equal(t, map[string]string{"sha256": "deadbeef"}, a.resolvedDeps[1].Digest)

	assert.Equal(t, "12345-1", a.metadata.InvocationID)
	assert.NotEmpty(t, a.metadata.StartedOn)
}

func TestExtractProvenanceFields_EmptyResolvedDeps(t *testing.T) {
	mock := &fullMockBuildEnv{
		envType:      "ec2",
		resolvedDeps: nil,
	}

	a := &Attestor{
		logger:   logger.NewNoop(),
		buildEnv: mock,
		config:   Config{},
	}

	a.extractProvenanceFields(t.Context())

	assert.Empty(t, a.resolvedDeps)
}

func TestExtractProvenanceFields_NilInternalParams(t *testing.T) {
	mock := &fullMockBuildEnv{
		envType:        "ec2",
		internalParams: nil,
	}

	a := &Attestor{
		logger:   logger.NewNoop(),
		buildEnv: mock,
		config:   Config{},
	}

	a.extractProvenanceFields(t.Context())

	assert.Nil(t, a.internalParams)
}

func TestExtractProvenanceFields_NilWorkflowInputs(t *testing.T) {
	mock := &fullMockBuildEnv{
		envType:        "github-actions",
		workflowInputs: nil,
	}

	a := &Attestor{
		logger:   logger.NewNoop(),
		buildEnv: mock,
		config:   Config{},
	}

	a.extractProvenanceFields(t.Context())

	assert.Nil(t, a.workflowInputs)
}

func TestExtractProvenanceFields_ResourceDescriptorAllFields(t *testing.T) {
	mock := &fullMockBuildEnv{
		envType: "github-actions",
		resolvedDeps: []buildenv.ResourceDescriptor{
			{
				Name:             "full-resource",
				URI:              "https://example.com/artifact",
				Digest:           map[string]string{"sha256": "abc123"},
				Content:          []byte("test-content"),
				DownloadLocation: "https://example.com/download",
				MediaType:        "application/octet-stream",
				Annotations:      map[string]any{"key": "value"},
			},
		},
	}

	a := &Attestor{
		logger:   logger.NewNoop(),
		buildEnv: mock,
		config:   Config{},
	}

	a.extractProvenanceFields(t.Context())

	require.Len(t, a.resolvedDeps, 1)
	dep := a.resolvedDeps[0]
	assert.Equal(t, "full-resource", dep.Name)
	assert.Equal(t, "https://example.com/artifact", dep.URI)
	assert.Equal(t, map[string]string{"sha256": "abc123"}, dep.Digest)
	assert.Equal(t, []byte("test-content"), dep.Content)
	assert.Equal(t, "https://example.com/download", dep.DownloadLocation)
	assert.Equal(t, "application/octet-stream", dep.MediaType)
	assert.Equal(t, map[string]any{"key": "value"}, dep.Annotations)
}

func TestExtractProvenanceFields_MultipleResolvedDeps(t *testing.T) {
	mock := &fullMockBuildEnv{
		envType: "github-actions",
		resolvedDeps: []buildenv.ResourceDescriptor{
			{URI: "dep1"},
			{URI: "dep2"},
			{URI: "dep3"},
		},
	}

	a := &Attestor{
		logger:   logger.NewNoop(),
		buildEnv: mock,
		config:   Config{},
	}

	a.extractProvenanceFields(t.Context())

	require.Len(t, a.resolvedDeps, 3)
	assert.Equal(t, "dep1", a.resolvedDeps[0].URI)
	assert.Equal(t, "dep2", a.resolvedDeps[1].URI)
	assert.Equal(t, "dep3", a.resolvedDeps[2].URI)
}

// --- Tests for collectAllData ---

func TestCollectAllData_InvalidBinaryPath(t *testing.T) {
	// Test fileHasher behavior independently since collectAllData
	// requires buildenv.Detect to succeed first.
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "exampleapp")
	err := os.WriteFile(binaryPath, []byte("fake binary content"), 0o755)
	require.NoError(t, err)

	result, err := fileHasher.HashFile(t.Context(), binaryPath)
	require.NoError(t, err)
	assert.Len(t, result.Digests[cryptohash.AlgorithmSHA256], 64) // SHA-256 hex is 64 chars

	_, err = fileHasher.HashFile(t.Context(), "/nonexistent/binary")
	require.Error(t, err)
}

func TestCollectAllData_BuildExecutionSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "exampleapp")
	configPath := filepath.Join("testdata", "minimal_config.yaml")

	require.NoError(t, os.WriteFile(binaryPath, []byte("dummy binary content"), 0755))

	mockExec := new(executor.MockCommandExecutor)

	mockVendorCmd := new(executor.MockCommand)
	mockBuildCmd := new(executor.MockCommand)

	mockExec.On("CommandContext", mock.Anything, "go", "mod", "vendor").Return(mockVendorCmd)
	mockVendorCmd.On("SetDir", tmpDir)
	mockVendorCmd.On("CombinedOutput").Return([]byte(""), nil)

	mockExec.On("CommandContext", mock.Anything, "go", "build", "-o", "exampleapp").Return(mockBuildCmd)
	mockBuildCmd.On("SetDir", tmpDir)
	mockBuildCmd.On("CombinedOutput").Return([]byte("build success"), nil)

	mockBuildEnv := &fullMockBuildEnv{
		envType:      "generic",
		builderID:    "test-builder",
		sourceURI:    "git+https://github.com/test/repo",
		sourceDigest: map[string]string{"sha256": "abc123"},
		resolvedDeps: []buildenv.ResourceDescriptor{},
		invocationID: "test-invocation",
	}

	mockDetector := func(ctx context.Context, log logger.Logger, opts buildenv.DetectOptions) (buildenv.BuildEnvironment, error) {
		return mockBuildEnv, nil
	}

	a := &Attestor{
		logger:   logger.NewNoop(),
		executor: mockExec,
		config: Config{
			BinaryPath: binaryPath,
			ConfigFile: configPath,
			WorkingDir: tmpDir,
			GoCommand:  []string{"go", "build", "-o", "exampleapp"},
		},
		buildEnvDetector: mockDetector,
	}

	err := a.collectAllData(t.Context())
	require.NoError(t, err)

	// Verify metadata state on success
	assert.NotEmpty(t, a.metadata.StartedOn, "StartedOn should be set")
	assert.NotEmpty(t, a.metadata.FinishedOn, "FinishedOn should be set on success")

	// Verify both timestamps are valid RFC3339
	startTime, err := time.Parse(time.RFC3339, a.metadata.StartedOn)
	require.NoError(t, err, "StartedOn should be a valid RFC3339 timestamp")

	finishTime, err := time.Parse(time.RFC3339, a.metadata.FinishedOn)
	require.NoError(t, err, "FinishedOn should be a valid RFC3339 timestamp")

	// Verify finish time is after or equal to start time
	assert.True(t, finishTime.After(startTime) || finishTime.Equal(startTime),
		"FinishedOn should be after or equal to StartedOn")

	mockExec.AssertExpectations(t)
	mockVendorCmd.AssertExpectations(t)
	mockBuildCmd.AssertExpectations(t)
}

func TestCollectAllData_BuildExecutionFailure(t *testing.T) {
	// Test that build execution failure is properly handled
	tmpDir := t.TempDir()
	configPath := filepath.Join("testdata", "minimal_config.yaml")

	// Create mock executor
	mockExec := new(executor.MockCommandExecutor)

	// Create mock commands for vendor and build
	mockVendorCmd := new(executor.MockCommand)
	mockBuildCmd := new(executor.MockCommand)

	// Set up mock for go mod vendor (succeeds)
	mockExec.On("CommandContext", mock.Anything, "go", "mod", "vendor").Return(mockVendorCmd)
	mockVendorCmd.On("SetDir", tmpDir)
	mockVendorCmd.On("CombinedOutput").Return([]byte(""), nil)

	// Set up mock for go build (fails)
	mockExec.On("CommandContext", mock.Anything, "go", "build", "-o", "exampleapp").Return(mockBuildCmd)
	mockBuildCmd.On("SetDir", tmpDir)
	mockBuildCmd.On("CombinedOutput").Return([]byte("build error details"), errors.New("simulated build failure"))

	mockBuildEnv := &fullMockBuildEnv{
		envType:      "generic",
		builderID:    "test-builder",
		sourceURI:    "git+https://github.com/test/repo",
		sourceDigest: map[string]string{"sha256": "abc123"},
		resolvedDeps: []buildenv.ResourceDescriptor{},
		invocationID: "test-invocation",
	}

	mockDetector := func(ctx context.Context, log logger.Logger, opts buildenv.DetectOptions) (buildenv.BuildEnvironment, error) {
		return mockBuildEnv, nil
	}

	a := &Attestor{
		logger:   logger.NewNoop(),
		executor: mockExec,
		config: Config{
			BinaryPath: filepath.Join(tmpDir, "exampleapp"),
			ConfigFile: configPath, // Use fixture from testdata
			WorkingDir: tmpDir,
			GoCommand:  []string{"go", "build", "-o", "exampleapp"},
		},
		buildEnvDetector: mockDetector,
	}

	err := a.collectAllData(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build execution")
	assert.Contains(t, err.Error(), "go build")

	// Verify metadata state on failure
	assert.NotEmpty(t, a.metadata.StartedOn, "StartedOn should be set before build execution")
	assert.Empty(t, a.metadata.FinishedOn, "FinishedOn should NOT be set when build fails")

	// Verify StartedOn is a valid RFC3339 timestamp
	_, parseErr := time.Parse(time.RFC3339, a.metadata.StartedOn)
	require.NoError(t, parseErr, "StartedOn should be a valid RFC3339 timestamp")

	// Verify mocks were called as expected
	mockExec.AssertExpectations(t)
	mockVendorCmd.AssertExpectations(t)
	mockBuildCmd.AssertExpectations(t)
}

// --- Test for predicate type conversion consistency ---

func TestResourceDescriptorConversion_Consistency(t *testing.T) {
	src := buildenv.ResourceDescriptor{
		Name:             "test",
		URI:              "https://example.com",
		Digest:           map[string]string{"sha256": "abc"},
		Content:          []byte("data"),
		DownloadLocation: "https://example.com/dl",
		MediaType:        "application/json",
		Annotations:      map[string]any{"ann": "val"},
	}

	mock := &fullMockBuildEnv{
		envType:      "github-actions",
		resolvedDeps: []buildenv.ResourceDescriptor{src},
	}

	a := &Attestor{
		logger:   logger.NewNoop(),
		buildEnv: mock,
		config:   Config{},
	}

	a.extractProvenanceFields(t.Context())

	expected := gobuilderpredicate.ResourceDescriptor{
		Name:             "test",
		URI:              "https://example.com",
		Digest:           map[string]string{"sha256": "abc"},
		Content:          []byte("data"),
		DownloadLocation: "https://example.com/dl",
		MediaType:        "application/json",
		Annotations:      map[string]any{"ann": "val"},
	}

	require.Len(t, a.resolvedDeps, 1)
	assert.Equal(t, expected, a.resolvedDeps[0])
}
