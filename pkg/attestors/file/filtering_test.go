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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// Note: Pattern matching logic is now tested in pkg/utils/pattern_test.go
// via TestMatchesAnyPattern. The tests here focus on the attestor's wrapper
// methods that add logging and config-specific behavior.

func TestMatchesExcludePattern(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		patterns []string
		expected bool
	}{
		{
			name:     "matches_exclude",
			path:     "node_modules/package.json",
			patterns: []string{"node_modules/**"},
			expected: true,
		},
		{
			name:     "no_exclude_patterns",
			path:     "src/main.go",
			patterns: []string{},
			expected: false,
		},
		{
			name:     "does_not_match_exclude",
			path:     "src/main.go",
			patterns: []string{"*.txt", "*.md"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Attestor{
				logger: logger.NewNoop(),
				config: Config{
					ExcludePatterns: tt.patterns,
				},
			}

			result := a.matchesExcludePattern(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchesIncludePattern(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		patterns []string
		expected bool
	}{
		{
			name:     "matches_include",
			path:     "src/main.go",
			patterns: []string{"src/**/*.go"},
			expected: true,
		},
		{
			name:     "no_include_patterns_matches_all",
			path:     "anything.txt",
			patterns: []string{},
			expected: true,
		},
		{
			name:     "does_not_match_include",
			path:     "docs/readme.md",
			patterns: []string{"src/**/*.go"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Attestor{
				logger: logger.NewNoop(),
				config: Config{
					IncludePatterns: tt.patterns,
				},
			}

			result := a.matchesIncludePattern(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchesSubjectIncludePattern(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		patterns []string
		expected bool
	}{
		{
			name:     "matches_subject_include",
			path:     "dist/app.exe",
			patterns: []string{"dist/**"},
			expected: true,
		},
		{
			name:     "no_subject_patterns_matches_none",
			path:     "dist/app.exe",
			patterns: []string{},
			expected: false,
		},
		{
			name:     "does_not_match_subject_include",
			path:     "src/main.go",
			patterns: []string{"dist/**"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Attestor{
				logger: logger.NewNoop(),
				config: Config{
					SubjectInclude: tt.patterns,
				},
			}

			result := a.matchesSubjectIncludePattern(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestShouldSkipPath(t *testing.T) {
	tests := []struct {
		name            string
		path            string
		isDir           bool
		basePath        string
		includePatterns []string
		excludePatterns []string
		expected        bool
	}{
		{
			name:            "file_excluded_by_pattern",
			path:            "/project/node_modules/package.json",
			basePath:        "/project",
			includePatterns: []string{},
			excludePatterns: []string{"node_modules/**"},
			expected:        true,
		},
		{
			name:            "file_not_in_include_pattern",
			path:            "/project/docs/readme.md",
			basePath:        "/project",
			includePatterns: []string{"src/**/*.go"},
			excludePatterns: []string{},
			expected:        true,
		},
		{
			name:            "file_included_and_not_excluded",
			path:            "/project/src/main.go",
			basePath:        "/project",
			includePatterns: []string{"src/**/*.go"},
			excludePatterns: []string{"*_test.go"},
			expected:        false,
		},
		{
			name:            "file_no_patterns_includes_all",
			path:            "/project/any/file.txt",
			basePath:        "/project",
			includePatterns: []string{},
			excludePatterns: []string{},
			expected:        false,
		},
		{
			name:            "directory_not_blocked_by_include",
			path:            "/project/docs",
			isDir:           true,
			basePath:        "/project",
			includePatterns: []string{"**/*.go"},
			excludePatterns: []string{},
			expected:        false,
		},
		{
			name:            "directory_still_excluded_by_exclude",
			path:            "/project/node_modules",
			isDir:           true,
			basePath:        "/project",
			includePatterns: []string{"**/*.go"},
			excludePatterns: []string{"node_modules"},
			expected:        true,
		},
		{
			name:            "directory_with_both_patterns",
			path:            "/project/src",
			isDir:           true,
			basePath:        "/project",
			includePatterns: []string{"**/*.md"},
			excludePatterns: []string{},
			expected:        false,
		},
		{
			name:            "file_exclude_wins_over_include",
			path:            "/project/docs/README.md",
			basePath:        "/project",
			includePatterns: []string{"**/*.md"},
			excludePatterns: []string{"**/*.md"},
			expected:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Attestor{
				logger: logger.NewNoop(),
				config: Config{
					BasePath:        tt.basePath,
					IncludePatterns: tt.includePatterns,
					ExcludePatterns: tt.excludePatterns,
				},
			}

			result := a.shouldSkipPath(tt.path, tt.isDir)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Benchmarks to measure pattern matching performance
// Note: Generic pattern matching benchmarks are in pkg/utils/pattern_test.go
// These benchmarks focus on the attestor's wrapper methods with logging overhead.

func BenchmarkMatchesExcludePattern(b *testing.B) {
	a := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			ExcludePatterns: []string{
				"**/node_modules/**",
				"**/dist/**",
				"**/.git/**",
				"**/__pycache__/**",
				"*.pyc",
			},
		},
	}

	paths := []string{
		"src/main.go",
		"node_modules/package.json",
		"dist/bundle.js",
		"src/utils/helper.go",
		".git/config",
	}

	for b.Loop() {
		for _, path := range paths {
			a.matchesExcludePattern(path)
		}
	}
}

func BenchmarkShouldSkipPath(b *testing.B) {
	a := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			BasePath: "/project",
			IncludePatterns: []string{
				"src/**/*.go",
				"pkg/**/*.go",
			},
			ExcludePatterns: []string{
				"**/*_test.go",
				"**/testdata/**",
				"**/vendor/**",
			},
		},
	}

	paths := []string{
		"/project/src/main.go",
		"/project/src/main_test.go",
		"/project/pkg/utils/helper.go",
		"/project/vendor/package/file.go",
		"/project/docs/readme.md",
	}

	for b.Loop() {
		for _, path := range paths {
			a.shouldSkipPath(path, false)
		}
	}
}
