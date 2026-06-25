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
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitclient "github.com/thomsonreuters/stamp/pkg/clients/git"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func newTestGenericEnv(gitInfo *gitclient.GitInfo) *GenericEnvironment {
	env := &GenericEnvironment{
		logger:   logger.NewNoop(),
		opts:     DetectOptions{},
		hostname: "test-host",
		gitInfo:  gitInfo,
	}
	return env
}

func TestGenericEnvironment_Detect(t *testing.T) {
	env := NewGenericEnvironment(logger.NewNoop(), DetectOptions{})
	result, err := env.Detect(t.Context())

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, EnvironmentGeneric, result.Type())
}

func TestGenericEnvironment_Type(t *testing.T) {
	env := newTestGenericEnv(nil)
	assert.Equal(t, EnvironmentGeneric, env.Type())
}

func TestGenericEnvironment_BuilderID(t *testing.T) {
	env := newTestGenericEnv(nil)
	assert.Equal(t, BuilderIDGeneric, env.BuilderID(t.Context()))
}

func TestGenericEnvironment_SourceURI_WithGitInfo(t *testing.T) {
	gitInfo := &gitclient.GitInfo{
		RemoteOriginURL: "https://github.com/org/repo.git",
		Refs:            []string{"refs/heads/main"},
	}

	env := newTestGenericEnv(gitInfo)

	assert.Equal(t, "git+https://github.com/org/repo@refs/heads/main", env.SourceURI())
}

func TestGenericEnvironment_SourceURI_NoGitInfo(t *testing.T) {
	env := newTestGenericEnv(nil)
	assert.Empty(t, env.SourceURI())
}

func TestGenericEnvironment_SourceDigest_WithGitInfo(t *testing.T) {
	gitInfo := &gitclient.GitInfo{
		CommitHash: "abc123def456",
	}
	env := newTestGenericEnv(gitInfo)
	assert.Equal(t, map[string]string{"gitCommit": "abc123def456"}, env.SourceDigest())
}

func TestGenericEnvironment_SourceDigest_NoGitInfo(t *testing.T) {
	env := newTestGenericEnv(nil)
	assert.Nil(t, env.SourceDigest())
}

func TestGenericEnvironment_InternalParameters(t *testing.T) {
	env := newTestGenericEnv(nil)

	params := env.InternalParameters()
	assert.Equal(t, "generic", params["environment_type"])
	assert.Len(t, params, 1) // Only environment_type should be present
}

func TestGenericEnvironment_ResolvedDependencies(t *testing.T) {
	gitInfo := &gitclient.GitInfo{
		RemoteOriginURL: "https://github.com/org/repo.git",
		Refs:            []string{"refs/heads/main"},
		CommitHash:      "abc123",
	}

	env := newTestGenericEnv(gitInfo)

	deps := env.ResolvedDependencies()
	require.Len(t, deps, 1)
	assert.Equal(t, "git+https://github.com/org/repo@refs/heads/main", deps[0].URI)
	assert.Equal(t, map[string]string{"gitCommit": "abc123"}, deps[0].Digest)
}

func TestGenericEnvironment_InvocationID(t *testing.T) {
	env := newTestGenericEnv(nil)
	invocationID := env.InvocationID()

	// Should be a valid UUID
	assert.NotEmpty(t, invocationID)
	// Should be 36 characters long (including hyphens)
	assert.Len(t, invocationID, 36)
	// Verify it's a valid UUID
	_, err := uuid.Parse(invocationID)
	assert.NoError(t, err)
}

func TestGenericEnvironment_WorkflowInputs(t *testing.T) {
	env := newTestGenericEnv(nil)
	assert.Nil(t, env.WorkflowInputs())
}

func TestGenericEnvironment_Detect_WorkingDirValidation(t *testing.T) {
	t.Run("Valid user-supplied directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		opts := DetectOptions{WorkingDir: tmpDir}

		env := NewGenericEnvironment(logger.NewNoop(), opts)
		result, err := env.Detect(t.Context())

		require.NoError(t, err)
		assert.NotNil(t, result)

		// WorkingDir should be converted to absolute path
		genericEnv, ok := result.(*GenericEnvironment)
		require.True(t, ok)
		assert.True(t, filepath.IsAbs(genericEnv.opts.WorkingDir))
	})

	t.Run("Non-existent directory", func(t *testing.T) {
		opts := DetectOptions{WorkingDir: "/non/existent/path"}

		env := NewGenericEnvironment(logger.NewNoop(), opts)
		result, err := env.Detect(t.Context())

		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "working directory does not exist")
	})

	t.Run("File instead of directory", func(t *testing.T) {
		// Create a file in t.TempDir() (auto-cleaned)
		tmpFile, err := os.CreateTemp(t.TempDir(), "test-file")
		require.NoError(t, err)
		require.NoError(t, tmpFile.Close())

		opts := DetectOptions{WorkingDir: tmpFile.Name()}

		env := NewGenericEnvironment(logger.NewNoop(), opts)
		result, err := env.Detect(t.Context())

		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "working directory is not a directory")
	})

	t.Run("Empty WorkingDir uses current directory", func(t *testing.T) {
		opts := DetectOptions{WorkingDir: ""}

		env := NewGenericEnvironment(logger.NewNoop(), opts)
		result, err := env.Detect(t.Context())

		require.NoError(t, err)
		assert.NotNil(t, result)

		// Should use current working directory
		genericEnv, ok := result.(*GenericEnvironment)
		require.True(t, ok)
		currentDir, _ := os.Getwd()
		assert.Equal(t, currentDir, genericEnv.opts.WorkingDir)
	})
}
