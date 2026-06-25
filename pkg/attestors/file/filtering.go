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
	"path/filepath"

	"github.com/thomsonreuters/stamp/pkg/utils"
)

// shouldSkipPath determines if a path should be skipped based on include/exclude patterns.
// For directories, only exclude patterns are checked — include patterns are not applied
// to directories because file-specific patterns (e.g. "**/*.md") would prevent directory
// traversal before any child files could be individually filtered.
func (a *Attestor) shouldSkipPath(path string, isDir bool) bool {
	relPath, err := filepath.Rel(a.config.BasePath, path)
	if err != nil {
		a.logger.Warn("failed to compute relative path for filtering", "path", path, "error", err.Error())
		relPath = path
	}

	relPath = utils.NormalizePath(relPath)

	if a.matchesExcludePattern(relPath) {
		return true
	}

	if !isDir && !a.matchesIncludePattern(relPath) {
		return true
	}

	return false
}

// matchesExcludePattern checks if a path matches any of the exclude patterns.
func (a *Attestor) matchesExcludePattern(relPath string) bool {
	matched, err := utils.MatchesAnyPattern(relPath, a.config.ExcludePatterns)
	if err != nil {
		a.logger.Warn("pattern matching error", "path", relPath, "error", err.Error())
		return false
	}
	return matched
}

// matchesIncludePattern checks if a path matches any of the include patterns.
func (a *Attestor) matchesIncludePattern(relPath string) bool {
	if len(a.config.IncludePatterns) == 0 {
		return true
	}

	matched, err := utils.MatchesAnyPattern(relPath, a.config.IncludePatterns)
	if err != nil {
		a.logger.Warn("pattern matching error", "path", relPath, "error", err.Error())
		return false
	}
	return matched
}

// matchesSubjectIncludePattern checks if a path matches any subject-include patterns (hybrid mode).
func (a *Attestor) matchesSubjectIncludePattern(relPath string) bool {
	if len(a.config.SubjectInclude) == 0 {
		return false
	}

	matched, err := utils.MatchesAnyPattern(relPath, a.config.SubjectInclude)
	if err != nil {
		a.logger.Warn("pattern matching error", "path", relPath, "error", err.Error())
		return false
	}
	return matched
}
