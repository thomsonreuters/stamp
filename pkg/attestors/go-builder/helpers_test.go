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
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestParseConfig_WithBuildConfigFile(t *testing.T) {
	path := filepath.Join("testdata", "config_with_ldflags.yaml")

	config := core.Config{
		"build-config": path,
	}

	a := &Attestor{logger: logger.NewNoop()}
	err := a.parseConfig(config)
	require.NoError(t, err)

	assert.True(t, filepath.IsAbs(a.config.BinaryPath), "BinaryPath should be absolute")
	assert.Equal(t, "exampleapp", filepath.Base(a.config.BinaryPath))
	assert.Equal(t, "exampleapp", a.config.BinaryName)
	assert.Equal(t, []string{"go", "build", "-mod=vendor", "-trimpath", "-ldflags=-s -w", "-o", "exampleapp", "./cmd/exampleapp"}, a.config.GoCommand)
	assert.Equal(t, []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64"}, a.config.GoEnv)
	assert.Contains(t, a.config.WorkingDir, "build") // absolute path ending in /build
}

func TestParseConfig_CaptureEventDefault(t *testing.T) {
	path := filepath.Join("testdata", "minimal_config.yaml")

	config := core.Config{
		"build-config": path,
	}

	a := &Attestor{logger: logger.NewNoop()}
	err := a.parseConfig(config)
	require.NoError(t, err)

	assert.True(t, a.config.CaptureEvent)
}

func TestParseConfig_CaptureEventDisabled(t *testing.T) {
	path := filepath.Join("testdata", "minimal_config.yaml")

	config := core.Config{
		"build-config":          path,
		"capture-event-payload": false,
	}

	a := &Attestor{logger: logger.NewNoop()}
	err := a.parseConfig(config)
	require.NoError(t, err)

	assert.False(t, a.config.CaptureEvent)
}

func TestParseConfig_InvalidConfigFile(t *testing.T) {
	config := core.Config{
		"build-config": "/nonexistent/file.yml",
	}

	a := &Attestor{logger: logger.NewNoop()}
	err := a.parseConfig(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading build config")
}

func TestParseConfig_InvalidConfigFileContent(t *testing.T) {
	path := filepath.Join("testdata", "version_only.yaml")

	config := core.Config{
		"build-config": path,
	}

	a := &Attestor{logger: logger.NewNoop()}
	err := a.parseConfig(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'binary' field is required")
}

func TestApplyConfigFile_ResolvesTemplates(t *testing.T) {
	t.Setenv("MY_VERSION", "v2.0.0")

	path := filepath.Join("testdata", "template_ldflags.yaml")

	a := &Attestor{
		logger: logger.NewNoop(),
		config: Config{ConfigFile: path},
	}

	err := a.applyConfigFile()
	require.NoError(t, err)

	assert.Contains(t, a.config.GoCommand, "-ldflags=-X main.version=v2.0.0")
}

func TestApplyConfigFile_WorkingDirResolved(t *testing.T) {
	t.Setenv("GITHUB_WORKSPACE", filepath.FromSlash("/home/runner/work/examplerepo/examplerepo"))

	path := filepath.Join("testdata", "config_with_dir.yaml")

	a := &Attestor{
		logger: logger.NewNoop(),
		config: Config{ConfigFile: path},
	}

	err := a.applyConfigFile()
	require.NoError(t, err)

	assert.Equal(t, filepath.Join("/home/runner/work/examplerepo/examplerepo", "build"), a.config.WorkingDir)
}

func TestApplyConfigFile_WorkingDirDot(t *testing.T) {
	t.Setenv("GITHUB_WORKSPACE", filepath.FromSlash("/home/runner/work/examplerepo/examplerepo"))

	path := filepath.Join("testdata", "config_with_dir_dot.yaml")

	a := &Attestor{
		logger: logger.NewNoop(),
		config: Config{ConfigFile: path},
	}

	err := a.applyConfigFile()
	require.NoError(t, err)

	assert.Equal(t, filepath.FromSlash("/home/runner/work/examplerepo/examplerepo"), a.config.WorkingDir)
}

func TestApplyConfigFile_WorkingDirNoGithubWorkspace(t *testing.T) {
	t.Setenv("GITHUB_WORKSPACE", "")

	path := filepath.Join("testdata", "config_with_dir.yaml")

	a := &Attestor{
		logger: logger.NewNoop(),
		config: Config{ConfigFile: path},
	}

	err := a.applyConfigFile()
	require.NoError(t, err)

	cwd, _ := os.Getwd()
	assert.Equal(t, filepath.Join(cwd, "build"), a.config.WorkingDir)
}

func TestResolveWorkingDir_EmptyDir(t *testing.T) {
	t.Setenv("GITHUB_WORKSPACE", filepath.FromSlash("/workspace"))
	assert.Equal(t, filepath.FromSlash("/workspace"), resolveWorkingDir(""))
}

func TestResolveWorkingDir_DotDir(t *testing.T) {
	t.Setenv("GITHUB_WORKSPACE", filepath.FromSlash("/workspace"))
	assert.Equal(t, filepath.FromSlash("/workspace"), resolveWorkingDir("."))
}

func TestResolveWorkingDir_SubDir(t *testing.T) {
	t.Setenv("GITHUB_WORKSPACE", filepath.FromSlash("/workspace"))
	assert.Equal(t, filepath.Join(filepath.FromSlash("/workspace"), "subdir"), resolveWorkingDir("subdir"))
}

func TestPathIsInside(t *testing.T) {
	tests := []struct {
		name   string
		child  string
		parent string
		want   bool
	}{
		{"child inside parent", "/a/b/c", "/a/b", true},
		{"same path", "/a/b", "/a/b", true},
		{"parent traversal", "/a/b/../c", "/a/b", false},
		{"sibling with shared prefix", "/ab", "/a", false},
		{"completely outside", "/x/y", "/a/b", false},
		{"parent is root", "/a/b", "/", true},
		{"dot relative same", ".", ".", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pathIsInside(filepath.FromSlash(tt.child), filepath.FromSlash(tt.parent))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestApplyConfigFile_RejectsResolvedMainTraversal(t *testing.T) {
	t.Setenv("MALICIOUS_MAIN", "../../etc/exploit")

	path := filepath.Join("testdata", "traversal_main_template.yaml")

	a := &Attestor{
		logger: logger.NewNoop(),
		config: Config{ConfigFile: path},
	}

	err := a.applyConfigFile()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "main (resolved)")
}
