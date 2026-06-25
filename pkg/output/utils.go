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
	"os"

	"golang.org/x/term"
)

var ciVars = []string{
	"CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL",
	"CIRCLECI", "TRAVIS", "BUILDKITE", "AZURE_PIPELINES",
	"TF_BUILD", "TEAMCITY_VERSION", "CODEBUILD_BUILD_ID",
}

// IsTTY returns true if stdout is a terminal (not piped or redirected).
func IsTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// IsCI returns true if running in a CI environment.
func IsCI() bool {
	for _, v := range ciVars {
		if os.Getenv(v) != "" {
			return true
		}
	}
	return false
}
