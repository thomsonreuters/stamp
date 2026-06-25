// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package githubworkflow

// MissingEventBehavior values.
const (
	MissingEventBehaviorAllow = "allow"
	MissingEventBehaviorWarn  = "warn"
	MissingEventBehaviorFail  = "fail"
)

var validMissingEventBehaviors = []string{
	MissingEventBehaviorAllow,
	MissingEventBehaviorWarn,
	MissingEventBehaviorFail,
}

// Critical fields that cannot be redacted.
const (
	CriticalFieldWorkflowRunID     = "workflow.run_id"
	CriticalFieldRunID             = "run_id"
	CriticalFieldRepositorySHA     = "repository.sha"
	CriticalFieldMetadataStartedOn = "metadata.started_on"
)

var criticalFields = []string{
	CriticalFieldWorkflowRunID,
	CriticalFieldRunID,
	CriticalFieldRepositorySHA,
	CriticalFieldMetadataStartedOn,
}

// Dangerous regex patterns that would match everything.
var dangerousRegexPatterns = []string{
	".*",        // Matches everything
	".+",        // Matches everything
	"^.*$",      // Matches entire lines
	"[\\s\\S]*", // Matches everything including newlines
}

// Env patterns.
var (
	EnvIncludePatterns = []string{"GITHUB_*", "RUNNER_*", "CI", "ACTIONS_*"}
	EnvExcludePatterns = []string{"*TOKEN*", "*SECRET*", "*PASSWORD*", "*KEY*", "*CREDENTIAL*", "GITHUB_TOKEN", "GH_TOKEN"}
)

// Built-in security exclusions - ALWAYS applied to prevent credential leakage.
var builtinSecurityExclusions = []string{
	"*TOKEN*",           // Generic tokens (GITHUB_TOKEN, NPM_TOKEN, etc.)
	"*SECRET*",          // Generic secrets
	"*PASSWORD*",        // Passwords
	"*API_KEY*",         // API keys
	"*ACCESS_KEY*",      // Access keys (AWS, etc.)
	"*PRIVATE_KEY*",     // Private keys
	"*CREDENTIALS*",     // Credential files/data
	"ACTIONS_ID_TOKEN*", // GitHub Actions OIDC tokens
	"ACTIONS_RUNTIME*",  // GitHub Actions runtime tokens
	"*_SIGNING_KEY*",    // Signing keys
	"*AUTH*TOKEN*",      // Authentication tokens
}
