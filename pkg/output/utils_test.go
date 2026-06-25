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

package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// clearCIEnvVars clears all CI environment variables for the duration of the test.
// Uses the ciVars list from utils.go to ensure tests stay in sync with production code.
func clearCIEnvVars(t *testing.T) {
	t.Helper()
	for _, v := range ciVars {
		t.Setenv(v, "")
	}
}

func TestIsTTY(t *testing.T) {
	// IsTTY depends on the actual terminal state
	// In tests, stdout is typically not a TTY (piped to test runner)
	result := IsTTY()
	// Just verify it returns a boolean without error
	assert.IsType(t, false, result)
}

func TestIsCI_WithNoEnvVars(t *testing.T) {
	clearCIEnvVars(t)
	assert.False(t, IsCI())
}

func TestIsCI_WithCIEnvVar(t *testing.T) {
	testCases := []struct {
		name   string
		envVar string
	}{
		{"CI generic", "CI"},
		{"GitHub Actions", "GITHUB_ACTIONS"},
		{"GitLab CI", "GITLAB_CI"},
		{"Jenkins", "JENKINS_URL"},
		{"CircleCI", "CIRCLECI"},
		{"Travis", "TRAVIS"},
		{"Buildkite", "BUILDKITE"},
		{"Azure Pipelines", "AZURE_PIPELINES"},
		{"Azure DevOps", "TF_BUILD"},
		{"TeamCity", "TEAMCITY_VERSION"},
		{"AWS CodeBuild", "CODEBUILD_BUILD_ID"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear all CI vars first
			clearCIEnvVars(t)

			// Set the specific CI var
			t.Setenv(tc.envVar, "true")

			assert.True(t, IsCI())
		})
	}
}

func TestIsCI_WithEmptyValue(t *testing.T) {
	clearCIEnvVars(t)

	// Setting to empty string is different from not set in some systems
	// but os.Getenv returns "" for both
	t.Setenv("CI", "")

	assert.False(t, IsCI())
}
