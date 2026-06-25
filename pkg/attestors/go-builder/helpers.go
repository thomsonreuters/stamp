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
	"strings"

	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/validation"
)

func (a *Attestor) parseConfig(config core.Config) error {
	a.config = Config{
		ConfigFile:   config.GetString("build-config", ""),
		CaptureEvent: config.GetBool("capture-event-payload", true),
	}

	// Load, resolve templates, and apply the build config file.
	if err := a.applyConfigFile(); err != nil {
		return err
	}

	return nil
}

func (a *Attestor) applyConfigFile() error {
	bc, err := LoadBuildConfig(a.config.ConfigFile)
	if err != nil {
		return fmt.Errorf("loading build config: %w", err)
	}

	bc.Resolve()

	if err := validation.ValidateRelativePath("binary (resolved)", bc.Binary); err != nil {
		return fmt.Errorf("resolved build config: %w", err)
	}
	if bc.Dir != "" && bc.Dir != "." {
		if err := validation.ValidateRelativePath("dir (resolved)", bc.Dir); err != nil {
			return fmt.Errorf("resolved build config: %w", err)
		}
	}
	if bc.Main != "" {
		if err := validation.ValidateRelativePath("main (resolved)", bc.Main); err != nil {
			return fmt.Errorf("resolved build config: %w", err)
		}
	}

	a.config.ConfigVersion = bc.Version
	a.config.BinaryName = bc.Binary

	a.config.GoCommand = bc.ToGoCommand()
	a.config.GoEnv = bc.ToEnv()
	a.config.WorkingDir = resolveWorkingDir(bc.Dir)

	a.config.BinaryPath = filepath.Join(a.config.WorkingDir, bc.Binary)

	if !pathIsInside(a.config.BinaryPath, a.config.WorkingDir) {
		return fmt.Errorf("binary path %q escapes working directory %q", a.config.BinaryPath, a.config.WorkingDir)
	}

	return nil
}

func pathIsInside(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func resolveWorkingDir(dir string) string {
	base := os.Getenv("GITHUB_WORKSPACE")
	if base == "" {
		base, _ = os.Getwd()
	}

	if dir == "" || dir == "." {
		return base
	}

	return filepath.Join(base, dir)
}
