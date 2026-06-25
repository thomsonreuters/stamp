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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/buildenv"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/logger"
	gobuilderpredicate "github.com/thomsonreuters/stamp/pkg/predicates/go-builder/v1"
)

func TestAttestor_ID(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "go-builder", a.ID())
}

func TestAttestor_PredicateURI(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "https://slsa.dev/provenance/v1", a.PredicateURI())
	assert.Equal(t, gobuilderpredicate.PredicateURI, a.PredicateURI())
}

func TestAttestor_Name(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "Go Builder Attestor", a.Name())
}

func TestAttestor_Description(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	assert.Equal(
		t,
		"Generates SLSA provenance attestation for Go binary builds (auto-detects GitHub Actions and EC2; all other environments use generic mode)",
		a.Description(),
	)
}

func TestAttestor_ConfigSchema(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	schema := a.ConfigSchema()

	assert.NotEmpty(t, schema)

	fieldNames := make(map[string]bool)
	for _, field := range schema {
		fieldNames[field.Name] = true
	}

	expectedFields := []string{
		"build-config",
		"capture-event-payload",
	}

	for _, expected := range expectedFields {
		assert.True(t, fieldNames[expected], "Expected field %q in schema", expected)
	}

	for _, field := range schema {
		assert.NotEmpty(t, field.Name)
		assert.NotEmpty(t, field.Type)
		assert.NotEmpty(t, field.Description)

		if field.Name == "build-config" {
			assert.Equal(t, "string", field.Type)
			assert.True(t, field.Required)
		}

		if field.Name == "capture-event-payload" {
			assert.Equal(t, "bool", field.Type)
			assert.Equal(t, true, field.Default)
		}
	}
}

func TestAttestor_ValidateConfig_BothProvided(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	config := core.Config{
		"build-config":          ".slsa-goreleaser.yml",
		"capture-event-payload": true,
	}
	err := a.ValidateConfig(config)
	assert.NoError(t, err)
}

func TestAttestor_ValidateConfig_OnlyBuildConfig(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	config := core.Config{
		"build-config": ".slsa-goreleaser.yml",
	}
	err := a.ValidateConfig(config)
	assert.NoError(t, err)
}

func TestAttestor_ValidateConfig_NoBuildConfig(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	config := core.Config{}
	err := a.ValidateConfig(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build-config is required")
}

func TestAttestor_PreAttest_WithBuildConfig(t *testing.T) {
	path := filepath.Join("testdata", "build_config.yaml")

	a := &Attestor{logger: logger.NewNoop()}
	config := core.Config{
		"build-config": path,
	}

	t.Setenv("GITHUB_WORKSPACE", "")

	err := a.PreAttest(t.Context(), config)
	require.NoError(t, err)

	cwd, err := os.Getwd()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(cwd, "testapp"), a.config.BinaryPath)
	assert.Equal(t, "testapp", a.config.BinaryName)
	assert.Equal(t, []string{"go", "build", "-mod=vendor", "-trimpath", "-o", "testapp", "./cmd/testapp"}, a.config.GoCommand)
	assert.Equal(t, []string{"GOOS=linux", "GOARCH=amd64"}, a.config.GoEnv)
}

// Reproduces a bug where dir=subdir produced a relative BinaryPath.
func TestAttestor_PreAttest_DirSubdirectory_BinaryPathIsAbsolute(t *testing.T) {
	fixtureContent, err := os.ReadFile(filepath.Join("testdata", "dir_subdirectory.yaml"))
	require.NoError(t, err)

	parentDir := t.TempDir()
	subDir := filepath.Join(parentDir, "testapp")
	require.NoError(t, os.MkdirAll(subDir, 0o755))

	configPath := filepath.Join(parentDir, ".slsa-goreleaser.yml")
	require.NoError(t, os.WriteFile(configPath, fixtureContent, 0o600))

	parentDir, _ = filepath.EvalSymlinks(parentDir)
	t.Setenv("GITHUB_WORKSPACE", "")
	t.Chdir(parentDir)

	a := &Attestor{logger: logger.NewNoop()}
	config := core.Config{
		"build-config": configPath,
	}

	err = a.PreAttest(t.Context(), config)
	require.NoError(t, err)

	expectedBinaryPath := filepath.Join(parentDir, "testapp", "testapp")
	assert.Equal(t, expectedBinaryPath, a.config.BinaryPath)
	assert.Equal(t, "testapp", a.config.BinaryName)
	assert.Equal(t, filepath.Join(parentDir, "testapp"), a.config.WorkingDir)
	assert.True(t, filepath.IsAbs(a.config.BinaryPath), "BinaryPath must be absolute")
}

func TestAttestor_PreAttest_InvalidConfigFile(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	config := core.Config{
		"build-config": "/nonexistent/file.yml",
	}

	err := a.PreAttest(t.Context(), config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing configuration")
}

func TestAttestor_PreAttest_RejectsTraversalAfterTemplateResolution(t *testing.T) {
	t.Setenv("MALICIOUS_BINARY", "../../etc/cron.d/evil")

	path := filepath.Join("testdata", "traversal_binary.yaml")

	a := &Attestor{logger: logger.NewNoop()}
	config := core.Config{
		"build-config": path,
	}

	err := a.PreAttest(t.Context(), config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not traverse above")
}

func TestAttestor_PreAttest_RejectsAbsolutePathAfterTemplateResolution(t *testing.T) {
	t.Setenv("MALICIOUS_DIR", "/tmp/evil")

	path := filepath.Join("testdata", "absolute_dir_template.yaml")

	a := &Attestor{logger: logger.NewNoop()}
	config := core.Config{
		"build-config": path,
	}

	err := a.PreAttest(t.Context(), config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be a relative path")
}

func TestAttestor_PostAttest(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	err := a.PostAttest(t.Context(), core.Config{})
	assert.NoError(t, err)
}

func TestAttestor_GeneratePredicate(t *testing.T) {
	mockEnv := &buildenv.MockBuildEnvironment{}
	mockEnv.On("Type").Return(buildenv.EnvironmentType("github-actions"))

	a := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			BinaryName: "testapp",
		},
		buildEnv:  mockEnv,
		sourceURI: "git+https://github.com/exampleorg/examplerepo@refs/heads/main",
		builderID: "https://github.com/slsa-framework/slsa-github-generator/go@v1",
		internalParams: map[string]any{
			"GITHUB_RUN_ID": "123",
		},
		resolvedDeps: []gobuilderpredicate.ResourceDescriptor{
			{
				URI: "git+https://github.com/exampleorg/examplerepo@refs/heads/main",
				Digest: map[string]string{
					"gitCommit": "abc123",
				},
			},
		},
		workflowInputs: map[string]any{"branch": "main"},
		metadata: gobuilderpredicate.Metadata{
			InvocationID: "123-1",
			StartedOn:    "2025-01-01T00:00:00Z",
			FinishedOn:   "2025-01-01T00:01:00Z",
		},
	}

	result, err := a.GeneratePredicate(core.Config{})
	require.NoError(t, err)

	predicate, ok := result.(gobuilderpredicate.Predicate)
	require.True(t, ok)

	assert.Equal(t, BuildTypeGolang, predicate.BuildDefinition.BuildType)
	assert.Equal(t, "git+https://github.com/exampleorg/examplerepo@refs/heads/main", predicate.BuildDefinition.ExternalParameters.Source)
	assert.Equal(t, map[string]any{"branch": "main"}, predicate.BuildDefinition.ExternalParameters.Inputs)
	assert.Equal(t, map[string]any{"GITHUB_RUN_ID": "123"}, predicate.BuildDefinition.InternalParameters)
	assert.Len(t, predicate.BuildDefinition.ResolvedDependencies, 1)
	assert.Equal(t, "git+https://github.com/exampleorg/examplerepo@refs/heads/main", predicate.BuildDefinition.ResolvedDependencies[0].URI)

	assert.Equal(t, "https://github.com/slsa-framework/slsa-github-generator/go@v1", predicate.RunDetails.Builder.ID)
	assert.Equal(t, "123-1", predicate.RunDetails.Metadata.InvocationID)
	assert.Equal(t, "2025-01-01T00:00:00Z", predicate.RunDetails.Metadata.StartedOn)
	assert.Equal(t, "2025-01-01T00:01:00Z", predicate.RunDetails.Metadata.FinishedOn)
	assert.Empty(t, predicate.RunDetails.Byproducts)
}

func TestAttestor_Subjects(t *testing.T) {
	a := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			BinaryName: "testapp-linux-amd64",
		},
		binaryDigest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}

	subjects := a.Subjects(core.Config{})
	require.Len(t, subjects, 1)
	assert.Equal(t, "testapp-linux-amd64", subjects[0].Name)
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", subjects[0].Digest["sha256"])
}

func TestAttestor_Schema(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	schema := a.Schema()

	assert.NotNil(t, schema)
	assert.Equal(t, "Go Builder Provenance", schema.Title)
	assert.Equal(t, "Provenance predicate for Go binary builds", schema.Description)
}
