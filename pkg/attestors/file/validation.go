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

package file

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

const (
	MinDepth     = -1
	MaxDepth     = 1000
	MinThreshold = 0
	MaxThreshold = 1073741824 // 1GB
)

// validateConfig validates all configuration fields including schema and custom validation.
func (a *Attestor) validateConfig(config core.Config) error {
	if err := config.Validate(a.ConfigSchema()); err != nil {
		return err
	}

	a.parseConfig(config)
	defer func() {
		a.config = Config{}
	}()

	if len(a.config.Paths) == 0 {
		return pkgerrors.NewWithContext("file_attestor", "validate", "at least one path must be specified")
	}

	if a.config.BasePath != "" {
		if info, err := os.Stat(a.config.BasePath); err != nil {
			return pkgerrors.WrapWithContext(err, "file_attestor", "validate",
				fmt.Sprintf("base path '%s' does not exist or is not accessible", a.config.BasePath))
		} else if !info.IsDir() {
			return pkgerrors.NewWithContext("file_attestor", "validate",
				fmt.Sprintf("base path '%s' must be a directory, got file", a.config.BasePath))
		}
	}

	if a.config.MaxDepth < MinDepth || a.config.MaxDepth > MaxDepth {
		return pkgerrors.NewWithContext("file_attestor", "validate",
			fmt.Sprintf("max-depth must be between -1 (unlimited) and 1000, got %d", a.config.MaxDepth))
	}

	if a.config.SizeWarningThreshold < MinThreshold || a.config.SizeWarningThreshold > MaxThreshold {
		return pkgerrors.NewWithContext("file_attestor", "validate",
			fmt.Sprintf("size-warning-threshold must be between 0 and 1GB (1073741824 bytes), got %d", a.config.SizeWarningThreshold))
	}

	if err := a.validateHashAlgorithms(); err != nil {
		return err
	}

	if !slices.Contains(validSubjectModes, a.config.SubjectMode) {
		return pkgerrors.NewWithContext("file_attestor", "validate",
			fmt.Sprintf("invalid subject-mode '%s' (supported: manifest-only, hybrid, all-files)", a.config.SubjectMode))
	}

	if a.config.SubjectMode == subjectModeHybrid && len(a.config.SubjectInclude) == 0 {
		a.logger.Warn("hybrid subject mode specified but no subject-include patterns provided - will behave like manifest-only")
	}

	if err := a.validateGlobPatterns(); err != nil {
		a.logger.Error("pattern validation failed", "error", err.Error())
		return err
	}

	return nil
}

// validateAndResolvePaths validates and resolves all configured paths to absolute paths.
func (a *Attestor) validateAndResolvePaths() error {
	resolvedPaths := make([]string, 0, len(a.config.Paths))

	for i, path := range a.config.Paths {
		if path == "" {
			a.logger.Warn("empty path in configuration", "index", i)
			continue
		}

		resolvedPath, err := a.resolvePath(path)
		if err != nil {
			if a.config.ErrorOnMissing {
				a.logger.Error("path validation failed", "path", path, "error", err.Error())
				return pkgerrors.WrapWithContext(err, "file_attestor", "validate",
					fmt.Sprintf("path validation failed: %s", path))
			}
			a.logger.Warn("path does not exist, will be skipped", "path", path, "error", err.Error())
			continue
		}

		if err := a.validatePathSecurity(resolvedPath); err != nil {
			a.logger.Error("path security validation failed", "path", resolvedPath, "error", err.Error())
			return err
		}

		resolvedPaths = append(resolvedPaths, resolvedPath)
	}

	if len(resolvedPaths) == 0 {
		a.logger.Error("no valid paths found after validation")
		return pkgerrors.NewWithContext("file_attestor", "validate",
			"no valid paths found - all paths are missing or invalid")
	}

	a.config.Paths = resolvedPaths
	return nil
}

// resolvePath resolves a path to its absolute form and checks if it exists.
func (a *Attestor) resolvePath(path string) (string, error) {
	var absPath string
	var err error

	if filepath.IsAbs(path) {
		absPath = path
	} else {
		absPath = filepath.Join(a.config.BasePath, path)
	}

	absPath = utils.NormalizePath(absPath)

	if _, err = os.Stat(absPath); err != nil {
		return "", pkgerrors.WrapWithContext(err, "file_attestor", "resolve",
			fmt.Sprintf("path does not exist or is not accessible: %s", path))
	}

	if a.config.NormalizePaths {
		absPath = utils.NormalizePath(absPath)
	}

	return absPath, nil
}

// validatePathSecurity prevents path traversal attacks by ensuring paths stay within base path boundary.
func (a *Attestor) validatePathSecurity(resolvedPath string) error {
	relPath, err := filepath.Rel(a.config.BasePath, resolvedPath)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "file_attestor", "security",
			"failed to validate path boundary")
	}

	if strings.HasPrefix(relPath, "..") || strings.HasPrefix(relPath, ".."+string(os.PathSeparator)) {
		return pkgerrors.NewWithContext("file_attestor", "security",
			fmt.Sprintf("path traversal detected: %s escapes base path %s", resolvedPath, a.config.BasePath))
	}

	if !a.config.FollowSymlinks { //nolint:nestif // Symlink validation requires multiple nested checks for security
		fileInfo, err := os.Lstat(resolvedPath)
		if err != nil {
			return pkgerrors.WrapWithContext(err, "file_attestor", "security",
				fmt.Sprintf("failed to check symlink status: %s", resolvedPath))
		}

		if fileInfo.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(resolvedPath)
			if err != nil {
				return pkgerrors.WrapWithContext(err, "file_attestor", "security",
					fmt.Sprintf("failed to read symlink target: %s", resolvedPath))
			}

			var targetAbs string
			if filepath.IsAbs(target) {
				targetAbs = target
			} else {
				targetAbs = filepath.Join(filepath.Dir(resolvedPath), target)
			}
			targetAbs = utils.NormalizePath(targetAbs)

			targetRel, err := filepath.Rel(a.config.BasePath, targetAbs)
			if err == nil && (strings.HasPrefix(targetRel, "..") || strings.HasPrefix(targetRel, ".."+string(os.PathSeparator))) {
				return pkgerrors.NewWithContext("file_attestor", "security",
					fmt.Sprintf("symlink %s points outside base path: %s", resolvedPath, targetAbs))
			}
		}
	}

	return nil
}

// validateHashAlgorithms validates that all configured hash algorithms are supported.
func (a *Attestor) validateHashAlgorithms() error {
	if len(a.config.HashAlgorithms) == 0 {
		return nil
	}

	normalizedAlgorithms := utils.SliceToLower(a.config.HashAlgorithms)
	if ok, notFoundAlgorithms := utils.SliceAllIn(normalizedAlgorithms, validHashAlgorithms); !ok {
		return pkgerrors.NewWithContext("file_attestor", "validate",
			fmt.Sprintf("invalid hash algorithms: %v (supported: %v)", strings.Join(notFoundAlgorithms, ", "), validHashAlgorithms))
	}

	return nil
}

// validateGlobPatterns validates glob patterns at config time to fail fast.
func (a *Attestor) validateGlobPatterns() error {
	if err := utils.ValidateGlobPatterns(a.config.ExcludePatterns, "exclude"); err != nil {
		return pkgerrors.WrapWithContext(err, "file_attestor", "validate", "invalid exclude pattern")
	}

	if err := utils.ValidateGlobPatterns(a.config.IncludePatterns, "include"); err != nil {
		return pkgerrors.WrapWithContext(err, "file_attestor", "validate", "invalid include pattern")
	}

	if err := utils.ValidateGlobPatterns(a.config.SubjectInclude, "subject-include"); err != nil {
		return pkgerrors.WrapWithContext(err, "file_attestor", "validate", "invalid subject-include pattern")
	}

	return nil
}
