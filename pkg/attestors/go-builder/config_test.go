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
)

func TestLoadBuildConfig_ValidFullConfig(t *testing.T) {
	path := filepath.Join("testdata", "valid_full_config.yaml")

	cfg, err := LoadBuildConfig(path)
	require.NoError(t, err)

	assert.Equal(t, 1, cfg.Version)
	assert.Equal(t, "exampleapp", cfg.Binary)
	assert.Equal(t, "./cmd/exampleapp", cfg.Main)
	assert.Equal(t, "build", cfg.Dir)
	assert.Equal(t, "linux", cfg.Goos)
	assert.Equal(t, "amd64", cfg.Goarch)
	assert.Equal(t, []string{"CGO_ENABLED=0", "GOFLAGS=-trimpath"}, cfg.Env)
	assert.Equal(t, []string{"-trimpath", "-v"}, cfg.Flags)
	assert.Equal(t, []string{"-s -w", "-X main.version=1.0.0"}, cfg.Ldflags)
}

func TestLoadBuildConfig_MinimalConfig(t *testing.T) {
	path := filepath.Join("testdata", "minimal_config.yaml")

	cfg, err := LoadBuildConfig(path)
	require.NoError(t, err)

	assert.Equal(t, 1, cfg.Version)
	assert.Equal(t, "exampleapp", cfg.Binary)
	assert.Empty(t, cfg.Main)
	assert.Empty(t, cfg.Dir)
	assert.Empty(t, cfg.Goos)
	assert.Empty(t, cfg.Goarch)
	assert.Empty(t, cfg.Env)
	assert.Empty(t, cfg.Flags)
	assert.Empty(t, cfg.Ldflags)
}

func TestLoadBuildConfig_FileNotFound(t *testing.T) {
	_, err := LoadBuildConfig("/nonexistent/path.yml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading config file")
}

func TestLoadBuildConfig_InvalidYAML(t *testing.T) {
	path := filepath.Join("testdata", "invalid_yaml.yaml")

	_, err := LoadBuildConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing config file")
}

func TestLoadBuildConfig_UnsupportedVersion(t *testing.T) {
	path := filepath.Join("testdata", "unsupported_version.yaml")

	_, err := LoadBuildConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported config version 2")
}

func TestLoadBuildConfig_MissingVersion(t *testing.T) {
	path := filepath.Join("testdata", "missing_version.yaml")

	_, err := LoadBuildConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported config version 0")
}

func TestLoadBuildConfig_MissingBinary(t *testing.T) {
	path := filepath.Join("testdata", "missing_binary.yaml")

	_, err := LoadBuildConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'binary' field is required")
}

func TestBuildConfig_ToGoCommand_Full(t *testing.T) {
	bc := &BuildConfig{
		Binary:  "exampleapp",
		Main:    "./cmd/exampleapp",
		Flags:   []string{"-trimpath", "-v"},
		Ldflags: []string{"-s -w", "-X main.version=1.0.0"},
	}

	cmd := bc.ToGoCommand()
	expected := []string{
		"go", "build", "-mod=vendor",
		"-trimpath", "-v",
		"-ldflags=-s -w -X main.version=1.0.0",
		"-o", "exampleapp",
		"./cmd/exampleapp",
	}
	assert.Equal(t, expected, cmd)
}

func TestBuildConfig_ToGoCommand_Minimal(t *testing.T) {
	bc := &BuildConfig{
		Binary: "exampleapp",
	}

	cmd := bc.ToGoCommand()
	expected := []string{"go", "build", "-mod=vendor", "-o", "exampleapp"}
	assert.Equal(t, expected, cmd)
}

func TestBuildConfig_ToGoCommand_FlagsOnly(t *testing.T) {
	bc := &BuildConfig{
		Binary: "exampleapp",
		Flags:  []string{"-trimpath"},
	}

	cmd := bc.ToGoCommand()
	expected := []string{"go", "build", "-mod=vendor", "-trimpath", "-o", "exampleapp"}
	assert.Equal(t, expected, cmd)
}

func TestBuildConfig_ToGoCommand_LdflagsOnly(t *testing.T) {
	bc := &BuildConfig{
		Binary:  "exampleapp",
		Ldflags: []string{"-s -w"},
	}

	cmd := bc.ToGoCommand()
	expected := []string{"go", "build", "-mod=vendor", "-ldflags=-s -w", "-o", "exampleapp"}
	assert.Equal(t, expected, cmd)
}

func TestBuildConfig_ToEnv_Full(t *testing.T) {
	bc := &BuildConfig{
		Env:    []string{"CGO_ENABLED=0", "GOFLAGS=-trimpath"},
		Goos:   "linux",
		Goarch: "amd64",
	}

	env := bc.ToEnv()
	expected := []string{"CGO_ENABLED=0", "GOFLAGS=-trimpath", "GOOS=linux", "GOARCH=amd64"}
	assert.Equal(t, expected, env)
}

func TestBuildConfig_ToEnv_Empty(t *testing.T) {
	bc := &BuildConfig{}

	env := bc.ToEnv()
	assert.Empty(t, env)
}

func TestBuildConfig_ToEnv_OnlyGoos(t *testing.T) {
	bc := &BuildConfig{
		Goos: "darwin",
	}

	env := bc.ToEnv()
	assert.Equal(t, []string{"GOOS=darwin"}, env)
}

func TestBuildConfig_ToEnv_OnlyGoarch(t *testing.T) {
	bc := &BuildConfig{
		Goarch: "arm64",
	}

	env := bc.ToEnv()
	assert.Equal(t, []string{"GOARCH=arm64"}, env)
}

func TestBuildConfig_BinaryPath_WithDir(t *testing.T) {
	bc := &BuildConfig{
		Binary: "exampleapp",
		Dir:    "build/output",
	}

	assert.Equal(t, filepath.Join("build/output", "exampleapp"), bc.BinaryPath())
}

func TestBuildConfig_BinaryPath_DirIsDot(t *testing.T) {
	bc := &BuildConfig{
		Binary: "exampleapp",
		Dir:    ".",
	}

	assert.Equal(t, "exampleapp", bc.BinaryPath())
}

func TestBuildConfig_BinaryPath_NoDir(t *testing.T) {
	bc := &BuildConfig{
		Binary: "exampleapp",
	}

	assert.Equal(t, "exampleapp", bc.BinaryPath())
}

func TestBuildConfig_Resolve_LdflagsTemplate(t *testing.T) {
	t.Setenv("APP_VERSION", "v1.2.3")

	bc := &BuildConfig{
		Version: 1,
		Binary:  "exampleapp",
		Ldflags: []string{"-X main.version={{.Env.APP_VERSION}}"},
	}

	bc.Resolve()

	assert.Equal(t, []string{"-X main.version=v1.2.3"}, bc.Ldflags)
}

func TestBuildConfig_Resolve_EnvTemplate(t *testing.T) {
	t.Setenv("BUILD_TAG", "release-42")

	bc := &BuildConfig{
		Version: 1,
		Binary:  "exampleapp-{{.Env.BUILD_TAG}}",
		Env:     []string{"TAG={{.Env.BUILD_TAG}}"},
	}

	bc.Resolve()

	assert.Equal(t, "exampleapp-release-42", bc.Binary)
	assert.Equal(t, []string{"TAG=release-42"}, bc.Env)
}

func TestBuildConfig_Resolve_UnsetEnvVar(t *testing.T) {
	t.Setenv("UNSET_VAR", "")

	bc := &BuildConfig{
		Version: 1,
		Binary:  "exampleapp",
		Ldflags: []string{"-X main.version={{.Env.UNSET_VAR}}"},
	}

	bc.Resolve()

	// Unset env var resolves to empty string
	assert.Equal(t, []string{"-X main.version="}, bc.Ldflags)
}

func TestBuildConfig_Resolve_NoTemplates(t *testing.T) {
	bc := &BuildConfig{
		Version: 1,
		Binary:  "exampleapp",
		Ldflags: []string{"-s -w"},
		Flags:   []string{"-trimpath"},
	}

	bc.Resolve()

	// No change when no templates present
	assert.Equal(t, "exampleapp", bc.Binary)
	assert.Equal(t, []string{"-s -w"}, bc.Ldflags)
	assert.Equal(t, []string{"-trimpath"}, bc.Flags)
}

// writeTestConfig writes YAML content to a temp file and returns the path.
func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".slsa-goreleaser.yml")
	err := os.WriteFile(path, []byte(content), 0o600)
	require.NoError(t, err)
	return path
}

// --- Path validation edge case tests ---

func TestLoadBuildConfig_RejectsAbsoluteBinary(t *testing.T) {
	path := filepath.Join("testdata", "absolute_binary.yaml")
	_, err := LoadBuildConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be a relative path")
}

func TestLoadBuildConfig_RejectsBinaryPathTraversal(t *testing.T) {
	path := filepath.Join("testdata", "binary_traversal.yaml")
	_, err := LoadBuildConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not traverse above")
}

func TestLoadBuildConfig_RejectsAbsoluteDir(t *testing.T) {
	path := filepath.Join("testdata", "absolute_dir.yaml")
	_, err := LoadBuildConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be a relative path")
}

func TestLoadBuildConfig_RejectsDirPathTraversal(t *testing.T) {
	path := filepath.Join("testdata", "dir_traversal.yaml")
	_, err := LoadBuildConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not traverse above")
}

func TestLoadBuildConfig_RejectsAbsoluteMain(t *testing.T) {
	path := filepath.Join("testdata", "absolute_main.yaml")
	_, err := LoadBuildConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be a relative path")
}

func TestLoadBuildConfig_RejectsNullBytesInBinary(t *testing.T) {
	path := writeTestConfig(t, "version: 1\nbinary: \"my\\x00app\"\nmain: ./cmd/app\n")
	_, err := LoadBuildConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "null bytes")
}

func TestLoadBuildConfig_AllowsSubdirBinary(t *testing.T) {
	path := filepath.Join("testdata", "subdir_binary.yaml")
	cfg, err := LoadBuildConfig(path)
	require.NoError(t, err)
	assert.Equal(t, "dist/exampleapp", cfg.Binary)
}

func TestLoadBuildConfig_AllowsNestedDir(t *testing.T) {
	path := filepath.Join("testdata", "nested_dir.yaml")
	cfg, err := LoadBuildConfig(path)
	require.NoError(t, err)
	assert.Equal(t, "sub/deep/dir", cfg.Dir)
}

func TestLoadBuildConfig_AllowsDotSlashMain(t *testing.T) {
	path := filepath.Join("testdata", "dot_slash_main.yaml")
	cfg, err := LoadBuildConfig(path)
	require.NoError(t, err)
	assert.Equal(t, "./cmd/app", cfg.Main)
}
