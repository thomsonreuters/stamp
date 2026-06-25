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
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	awsec2 "github.com/thomsonreuters/stamp/pkg/clients/aws/ec2"
	gitclient "github.com/thomsonreuters/stamp/pkg/clients/git"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func newTestEC2Env(gitInfo *gitclient.GitInfo) *EC2Environment {
	return &EC2Environment{
		logger:           logger.NewNoop(),
		opts:             DetectOptions{},
		instanceID:       "i-0123456789abcdef0",
		instanceType:     "m5.large",
		region:           "us-east-1",
		availabilityZone: "us-east-1a",
		accountID:        "123456789012",
		imageID:          "ami-0abcdef1234567890",
		architecture:     "x86_64",
		gitInfo:          gitInfo,
	}
}

func TestEC2Environment_Type(t *testing.T) {
	env := newTestEC2Env(nil)
	assert.Equal(t, EnvironmentEC2, env.Type())
}

func TestEC2Environment_BuilderID(t *testing.T) {
	env := newTestEC2Env(nil)
	assert.Equal(t, BuilderIDEC2, env.BuilderID(t.Context()))
}

func TestEC2Environment_SourceURI_WithGitInfo(t *testing.T) {
	info := &gitclient.GitInfo{
		RemoteOriginURL: "git@github.com:exampleorg/examplerepo.git",
		Branch:          "main",
		CommitHash:      "abc123def456",
	}

	env := newTestEC2Env(info)
	assert.Equal(t, "git+https://github.com/exampleorg/examplerepo@refs/heads/main", env.SourceURI())
}

func TestEC2Environment_SourceURI_DetachedHead(t *testing.T) {
	info := &gitclient.GitInfo{
		RemoteOriginURL: "git@github.com:exampleorg/examplerepo.git",
		Branch:          "",
		CommitHash:      "abc123def456",
	}

	env := newTestEC2Env(info)
	assert.Equal(t, "git+https://github.com/exampleorg/examplerepo@abc123def456", env.SourceURI())
}

func TestEC2Environment_SourceURI_NoGitInfo(t *testing.T) {
	env := newTestEC2Env(nil)
	assert.Empty(t, env.SourceURI())
}

func TestEC2Environment_SourceDigest_WithGitInfo(t *testing.T) {
	info := &gitclient.GitInfo{CommitHash: "abc123def456"}
	env := newTestEC2Env(info)
	assert.Equal(t, map[string]string{"gitCommit": "abc123def456"}, env.SourceDigest())
}

func TestEC2Environment_SourceDigest_NoGitInfo(t *testing.T) {
	env := newTestEC2Env(nil)
	assert.Nil(t, env.SourceDigest())
}

func TestEC2Environment_InternalParameters(t *testing.T) {
	env := newTestEC2Env(nil)
	params := env.InternalParameters()

	// Should only contain EC2-specific information
	assert.Equal(t, "ec2", params["environment_type"])
	assert.Equal(t, "i-0123456789abcdef0", params["instance_id"])
	assert.Equal(t, "m5.large", params["instance_type"])
	assert.Equal(t, "us-east-1", params["region"])
	assert.Equal(t, "us-east-1a", params["availability_zone"])
	assert.Equal(t, "123456789012", params["account_id"])
	assert.Equal(t, "ami-0abcdef1234567890", params["image_id"])
	assert.Equal(t, "x86_64", params["architecture"])

	assert.Len(t, params, 8)
}

func TestEC2Environment_ResolvedDependencies_WithGitAndAMI(t *testing.T) {
	info := &gitclient.GitInfo{
		RemoteOriginURL: "git@github.com:exampleorg/examplerepo.git",
		Branch:          "main",
		CommitHash:      "abc123",
	}

	env := newTestEC2Env(info)
	deps := env.ResolvedDependencies()

	require.Len(t, deps, 2)
	assert.Equal(t, "git+https://github.com/exampleorg/examplerepo@refs/heads/main", deps[0].URI)
	assert.Equal(t, map[string]string{"gitCommit": "abc123"}, deps[0].Digest)
	assert.Equal(t, "https://aws.amazon.com/ec2/ami/us-east-1/ami-0abcdef1234567890", deps[1].URI)
}

func TestEC2Environment_ResolvedDependencies_NoGit(t *testing.T) {
	env := newTestEC2Env(nil)
	deps := env.ResolvedDependencies()

	require.Len(t, deps, 1)
	assert.Contains(t, deps[0].URI, "ami-0abcdef1234567890")
}

func TestEC2Environment_ResolvedDependencies_NoAMI(t *testing.T) {
	info := &gitclient.GitInfo{
		RemoteOriginURL: "git@github.com:exampleorg/examplerepo.git",
		Branch:          "main",
		CommitHash:      "abc123",
	}

	env := &EC2Environment{
		logger:  logger.NewNoop(),
		gitInfo: info,
	}
	deps := env.ResolvedDependencies()

	require.Len(t, deps, 1)
	assert.Equal(t, "git+https://github.com/exampleorg/examplerepo@refs/heads/main", deps[0].URI)
}

func TestEC2Environment_InvocationID(t *testing.T) {
	t.Run("Plain EC2", func(t *testing.T) {
		env := newTestEC2Env(nil)
		invocationID := env.InvocationID()

		// Should contain instance ID and timestamp
		assert.NotEmpty(t, invocationID)
		assert.Contains(t, invocationID, "i-0123456789abcdef0-")

		// Verify format: instanceID-microsecondTimestamp
		parts := strings.Split(invocationID, "-")
		assert.Len(t, parts, 3) // i-xxxx-timestamp
		assert.Equal(t, "i", parts[0])
		assert.Equal(t, "0123456789abcdef0", parts[1])

		// Verify timestamp is a valid number
		var timestamp int64
		_, err := fmt.Sscanf(parts[2], "%d", &timestamp)
		require.NoError(t, err)
		assert.Positive(t, timestamp)
	})

	t.Run("CodeBuild", func(t *testing.T) {
		// Set CodeBuild environment variable
		t.Setenv("CODEBUILD_BUILD_ID", "example-project:build:123")

		env := newTestEC2Env(nil)
		invocationID := env.InvocationID()

		// Should have format: buildID:instanceID:timestamp
		assert.Contains(t, invocationID, "example-project:build:123:")
		assert.Contains(t, invocationID, "i-0123456789abcdef0:")

		parts := strings.Split(invocationID, ":")
		assert.GreaterOrEqual(t, len(parts), 4) // buildID parts + instanceID + timestamp

		// Verify timestamp is at the end
		var timestamp int64
		_, err := fmt.Sscanf(parts[len(parts)-1], "%d", &timestamp)
		require.NoError(t, err)
		assert.Positive(t, timestamp)
	})

	t.Run("CodePipeline", func(t *testing.T) {
		// Set CodePipeline environment variable
		t.Setenv("CODEPIPELINE_EXECUTION_ID", "exec-12345")

		env := newTestEC2Env(nil)
		invocationID := env.InvocationID()

		// Should have format: pipeline:executionID:instanceID:timestamp
		assert.Contains(t, invocationID, "pipeline:exec-12345:")
		assert.Contains(t, invocationID, "i-0123456789abcdef0:")

		parts := strings.Split(invocationID, ":")
		assert.Len(t, parts, 4) // pipeline + executionID + instanceID + timestamp
		assert.Equal(t, "pipeline", parts[0])
		assert.Equal(t, "exec-12345", parts[1])
		assert.Contains(t, parts[2], "i-0123456789abcdef0")

		// Verify timestamp
		var timestamp int64
		_, err := fmt.Sscanf(parts[3], "%d", &timestamp)
		require.NoError(t, err)
		assert.Positive(t, timestamp)
	})
}

func TestEC2Environment_WorkflowInputs(t *testing.T) {
	env := newTestEC2Env(nil)
	assert.Nil(t, env.WorkflowInputs())
}

func TestEC2Environment_Detect_FatalErrorWhenNoGitRepo(t *testing.T) {
	// Use SetupMockClient to swap the package-level New variable
	mockClient := awsec2.SetupMockClient(t)
	mockClient.On("CheckIMDSAccessibility", mock.Anything, mock.Anything).Return(nil)
	mockClient.On("GetInstanceIdentityDocument", mock.Anything, mock.Anything).Return(&awsec2.InstanceIdentityDocument{
		InstanceID:       "i-0123456789abcdef0",
		InstanceType:     "m5.large",
		Region:           "us-east-1",
		AvailabilityZone: "us-east-1a",
		AccountID:        "123456789012",
		ImageID:          "ami-0abcdef1234567890",
		Architecture:     "x86_64",
	}, nil)

	// Use a temp directory that is NOT a git repo
	tmpDir := t.TempDir()

	env := &EC2Environment{
		logger: logger.NewNoop(),
		opts:   DetectOptions{WorkingDir: tmpDir},
	}

	_, err := env.Detect(t.Context())
	require.Error(t, err)

	var fatal *DetectionFatalError
	require.ErrorAs(t, err, &fatal, "expected DetectionFatalError, got: %v", err)
	assert.Contains(t, fatal.Error(), "no git repository found")
}
