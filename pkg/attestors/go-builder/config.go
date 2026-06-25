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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/thomsonreuters/stamp/pkg/validation"
	"gopkg.in/yaml.v3"
)

// envTemplatePattern matches Go template-style environment variable references: {{.Env.VAR_NAME}}.
var envTemplatePattern = regexp.MustCompile(`\{\{\s*\.Env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

// BuildConfig represents a declarative Go build specification.
type BuildConfig struct {
	Version int      `yaml:"version"`
	Binary  string   `yaml:"binary"`
	Main    string   `yaml:"main"`
	Dir     string   `yaml:"dir"`
	Goos    string   `yaml:"goos"`
	Goarch  string   `yaml:"goarch"`
	Env     []string `yaml:"env"`
	Flags   []string `yaml:"flags"`
	Ldflags []string `yaml:"ldflags"`
}

const supportedConfigVersion = 1

// LoadBuildConfig reads and parses a Go Builder build configuration file.
func LoadBuildConfig(path string) (*BuildConfig, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	var cfg BuildConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}

	if cfg.Version != supportedConfigVersion {
		return nil, fmt.Errorf("unsupported config version %d (supported: %d)", cfg.Version, supportedConfigVersion)
	}

	if cfg.Binary == "" {
		return nil, fmt.Errorf("config file %q: 'binary' field is required", path)
	}

	if err := validation.ValidateRelativePath("binary", cfg.Binary); err != nil {
		return nil, fmt.Errorf("config file %q: %w", path, err)
	}

	if cfg.Dir != "" && cfg.Dir != "." {
		if err := validation.ValidateRelativePath("dir", cfg.Dir); err != nil {
			return nil, fmt.Errorf("config file %q: %w", path, err)
		}
	}

	if cfg.Main != "" {
		if err := validation.ValidateRelativePath("main", cfg.Main); err != nil {
			return nil, fmt.Errorf("config file %q: %w", path, err)
		}
	}

	return &cfg, nil
}

// Resolve expands {{.Env.VAR}} template variables in all string fields.
func (bc *BuildConfig) Resolve() {
	bc.Binary = resolveEnvTemplates(bc.Binary)
	bc.Main = resolveEnvTemplates(bc.Main)
	bc.Dir = resolveEnvTemplates(bc.Dir)
	bc.Goos = resolveEnvTemplates(bc.Goos)
	bc.Goarch = resolveEnvTemplates(bc.Goarch)

	for i, v := range bc.Env {
		bc.Env[i] = resolveEnvTemplates(v)
	}
	for i, v := range bc.Flags {
		bc.Flags[i] = resolveEnvTemplates(v)
	}
	for i, v := range bc.Ldflags {
		bc.Ldflags[i] = resolveEnvTemplates(v)
	}
}

// resolveEnvTemplates replaces all {{.Env.VAR}} patterns with os.Getenv("VAR").
func resolveEnvTemplates(s string) string {
	return envTemplatePattern.ReplaceAllStringFunc(s, func(match string) string {
		submatches := envTemplatePattern.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}
		return os.Getenv(submatches[1])
	})
}

// ToGoCommand constructs the full `go build` command from the config.
func (bc *BuildConfig) ToGoCommand() []string {
	cmd := []string{"go", "build", "-mod=vendor"}

	cmd = append(cmd, bc.Flags...)

	if len(bc.Ldflags) > 0 {
		cmd = append(cmd, "-ldflags="+strings.Join(bc.Ldflags, " "))
	}

	cmd = append(cmd, "-o", bc.Binary)

	if bc.Main != "" {
		cmd = append(cmd, bc.Main)
	}

	return cmd
}

// ToEnv constructs the environment variable list, including GOOS/GOARCH if set.
func (bc *BuildConfig) ToEnv() []string {
	env := make([]string, 0, len(bc.Env)+2)
	env = append(env, bc.Env...)

	if bc.Goos != "" {
		env = append(env, "GOOS="+bc.Goos)
	}
	if bc.Goarch != "" {
		env = append(env, "GOARCH="+bc.Goarch)
	}

	return env
}

// BinaryPath returns the output binary path based on dir and binary name.
func (bc *BuildConfig) BinaryPath() string {
	if bc.Dir != "" && bc.Dir != "." {
		return filepath.Join(bc.Dir, bc.Binary)
	}
	return bc.Binary
}
