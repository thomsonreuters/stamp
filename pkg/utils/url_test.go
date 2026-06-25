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

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "HTTPS with PAT",
			input:    "https://ghp_abc123@github.com/org/repo.git",
			expected: "https://github.com/org/repo.git",
		},
		{
			name:     "HTTPS with user:pass",
			input:    "https://user:password@github.com/org/repo.git",
			expected: "https://github.com/org/repo.git",
		},
		{
			name:     "HTTPS without credentials",
			input:    "https://github.com/org/repo.git",
			expected: "https://github.com/org/repo.git",
		},
		{
			name:     "HTTP with credentials",
			input:    "http://token@gitlab.com/group/project.git",
			expected: "http://gitlab.com/group/project.git",
		},
		{
			name:     "SSH URL unchanged",
			input:    "git@github.com:org/repo.git",
			expected: "git@github.com:org/repo.git",
		},
		{
			name:     "git:// with credentials",
			input:    "git://user:token@github.com/org/repo.git",
			expected: "git://github.com/org/repo.git",
		},
		{
			name:     "ssh:// with credentials",
			input:    "ssh://user:password@github.com/org/repo.git",
			expected: "ssh://github.com/org/repo.git",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
