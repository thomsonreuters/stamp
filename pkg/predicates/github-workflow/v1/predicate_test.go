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

package v1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPredicateURI(t *testing.T) {
	assert.Equal(t, "https://github.com/thomsonreuters/stamp/github-workflow/v1", PredicateURI)
}

func TestPredicate_JSONMarshal(t *testing.T) {
	predicate := Predicate{
		Workflow: WorkflowInfo{
			Job:        "build",
			Action:     "actions/checkout@v4",
			ActionPath: ".github/actions/custom",
		},
		Runner: RunnerInfo{
			Name: "GitHub Actions 1",
			OS:   "Linux",
			Arch: "X64",
			Environment: map[string]string{
				"NODE_VERSION": "20",
				"GO_VERSION":   "1.21",
			},
		},
		Trigger: TriggerInfo{
			EventPayload:     json.RawMessage(`{"ref":"refs/heads/main"}`),
			EventPayloadSize: 1024,
		},
		Repository: RepositoryInfo{
			RefName: "main",
		},
		Metadata: MetadataInfo{
			ServerURL: "https://github.com",
		},
		OIDC: &OIDCInfo{
			Issuer:  "https://token.actions.githubusercontent.com",
			Subject: "repo:octocat/hello-world:ref:refs/heads/main",
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	assert.Contains(t, string(data), "workflow")
	assert.Contains(t, string(data), "runner")
	assert.Contains(t, string(data), "trigger")
	assert.Contains(t, string(data), "repository")
	assert.Contains(t, string(data), "metadata")
}

func TestPredicate_JSONUnmarshal(t *testing.T) {
	jsonData := `{
		"workflow": {
			"name": "Test Workflow",
			"ref": "refs/heads/develop/.github/workflows/test.yml",
			"run_id": "67890",
			"run_number": 100,
			"run_attempt": 2,
			"job": "test"
		},
		"runner": {
			"name": "Self-Hosted Runner",
			"os": "macOS",
			"arch": "ARM64",
			"hosted_type": "self-hosted"
		},
		"trigger": {
			"event_name": "pull_request",
			"actor": "contributor",
			"head_ref": "feature-branch",
			"base_ref": "main"
		},
		"repository": {
			"full_name": "org/repo",
			"owner": "org",
			"sha": "commit123",
			"ref": "refs/pull/42/merge",
			"ref_name": "42/merge",
			"ref_type": "branch"
		},
		"metadata": {
			"invocation_id": "inv-456",
			"started_on": "2025-11-12T10:00:00Z"
		}
	}`

	var predicate Predicate
	err := json.Unmarshal([]byte(jsonData), &predicate)
	require.NoError(t, err)

	assert.Equal(t, "test", predicate.Workflow.Job)
	assert.Equal(t, "Self-Hosted Runner", predicate.Runner.Name)
}

func TestWorkflowInfo_Complete(t *testing.T) {
	workflow := WorkflowInfo{
		Job:        "deploy-production",
		Action:     "actions/deploy@v1",
		ActionPath: ".github/actions/deploy",
	}

	data, err := json.Marshal(workflow)
	require.NoError(t, err)

	assert.Contains(t, string(data), "deploy-production")
	assert.Contains(t, string(data), "actions/deploy@v1")

	var result WorkflowInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, workflow.Job, result.Job)
	assert.Equal(t, workflow.Action, result.Action)
	assert.Equal(t, workflow.ActionPath, result.ActionPath)
}

func TestWorkflowInfo_OmitEmptyFields(t *testing.T) {
	workflow := WorkflowInfo{
		Job: "simple-job",
	}

	data, err := json.Marshal(workflow)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "action")
	assert.NotContains(t, string(data), "action_path")
}

func TestRunnerInfo_GitHubHosted(t *testing.T) {
	runner := RunnerInfo{
		Name: "GitHub Actions 2",
		OS:   "Linux",
		Arch: "X64",
	}

	data, err := json.Marshal(runner)
	require.NoError(t, err)

	var result RunnerInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "Linux", result.OS)
	assert.Equal(t, "X64", result.Arch)
}

func TestRunnerInfo_SelfHosted(t *testing.T) {
	runner := RunnerInfo{
		Name: "My Runner",
		OS:   "macOS",
		Arch: "ARM64",
		Environment: map[string]string{
			"CUSTOM_VAR": "value",
		},
	}

	data, err := json.Marshal(runner)
	require.NoError(t, err)

	var result RunnerInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "macOS", result.OS)
	assert.Equal(t, "ARM64", result.Arch)
	assert.Equal(t, "value", result.Environment["CUSTOM_VAR"])
}

func TestRunnerInfo_OmitEmptyEnvironment(t *testing.T) {
	runner := RunnerInfo{
		Name: "Runner",
		OS:   "Windows",
		Arch: "X64",
	}

	data, err := json.Marshal(runner)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "environment")
}

func TestTriggerInfo_PushEvent(t *testing.T) {
	payload := json.RawMessage(`{"ref":"refs/heads/main","commits":[{"sha":"abc123"}]}`)

	trigger := TriggerInfo{
		EventPayload:     payload,
		EventPayloadSize: int64(len(payload)),
	}

	data, err := json.Marshal(trigger)
	require.NoError(t, err)

	var result TriggerInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.JSONEq(t, string(payload), string(result.EventPayload))
	assert.Equal(t, int64(len(payload)), result.EventPayloadSize)
}

func TestTriggerInfo_PullRequestEvent(t *testing.T) {
	payload := json.RawMessage(`{"action":"opened"}`)
	trigger := TriggerInfo{
		EventPayload:     payload,
		EventPayloadSize: int64(len(payload)),
	}

	data, err := json.Marshal(trigger)
	require.NoError(t, err)

	var result TriggerInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.JSONEq(t, string(payload), string(result.EventPayload))
}

func TestTriggerInfo_OmitEmptyFields(t *testing.T) {
	trigger := TriggerInfo{}

	data, err := json.Marshal(trigger)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "event_payload")
	assert.NotContains(t, string(data), "event_payload_size")
}

func TestTriggerInfo_EventPayloadRedacted(t *testing.T) {
	trigger := TriggerInfo{
		EventPayloadSize: 5120,
	}

	data, err := json.Marshal(trigger)
	require.NoError(t, err)

	var result TriggerInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, int64(5120), result.EventPayloadSize)
	assert.Nil(t, result.EventPayload)
}

func TestRepositoryInfo_Complete(t *testing.T) {
	repo := RepositoryInfo{
		RefName: "main",
	}

	data, err := json.Marshal(repo)
	require.NoError(t, err)

	var result RepositoryInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, repo.RefName, result.RefName)
}

func TestRepositoryInfo_TagRef(t *testing.T) {
	repo := RepositoryInfo{
		RefName: "v1.0.0",
	}

	data, err := json.Marshal(repo)
	require.NoError(t, err)

	var result RepositoryInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "v1.0.0", result.RefName)
}

func TestRepositoryInfo_OmitEmptyFields(t *testing.T) {
	repo := RepositoryInfo{
		RefName: "develop",
	}

	data, err := json.Marshal(repo)
	require.NoError(t, err)

	assert.Contains(t, string(data), "develop")
}

func TestMetadataInfo_Complete(t *testing.T) {
	meta := MetadataInfo{
		ServerURL: "https://github.com",
	}

	data, err := json.Marshal(meta)
	require.NoError(t, err)

	var result MetadataInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "https://github.com", result.ServerURL)
}

func TestMetadataInfo_EnterpriseServer(t *testing.T) {
	meta := MetadataInfo{
		ServerURL: "https://github.enterprise.com",
	}

	data, err := json.Marshal(meta)
	require.NoError(t, err)

	assert.Contains(t, string(data), "github.enterprise.com")

	var result MetadataInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Contains(t, result.ServerURL, "enterprise")
}

func TestMetadataInfo_OmitEmptyServerURL(t *testing.T) {
	meta := MetadataInfo{}

	data, err := json.Marshal(meta)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "server_url")
}

func TestPredicate_Complete(t *testing.T) {
	eventPayload := json.RawMessage(`{"action":"opened","number":42}`)

	predicate := Predicate{
		Workflow: WorkflowInfo{
			Job:        "full-pipeline",
			Action:     "actions/checkout@v4",
			ActionPath: ".github/actions/custom",
		},
		Runner: RunnerInfo{
			Name: "Runner-1",
			OS:   "Linux",
			Arch: "X64",
			Environment: map[string]string{
				"CI":           "true",
				"GITHUB_TOKEN": "[REDACTED]",
			},
		},
		Trigger: TriggerInfo{
			EventPayload:     eventPayload,
			EventPayloadSize: int64(len(eventPayload)),
		},
		Repository: RepositoryInfo{
			RefName: "42/merge",
		},
		Metadata: MetadataInfo{
			ServerURL: "https://github.com",
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, predicate.Workflow.Job, result.Workflow.Job)
	assert.Equal(t, predicate.Runner.OS, result.Runner.OS)
	assert.Equal(t, predicate.Repository.RefName, result.Repository.RefName)
}

func TestPredicate_EventTypes(t *testing.T) {
	tests := []struct {
		name       string
		eventName  string
		hasPayload bool
	}{
		{
			name:       "Push Event",
			eventName:  "push",
			hasPayload: true,
		},
		{
			name:       "Pull Request",
			eventName:  "pull_request",
			hasPayload: true,
		},
		{
			name:       "Workflow Dispatch",
			eventName:  "workflow_dispatch",
			hasPayload: false,
		},
		{
			name:       "Schedule",
			eventName:  "schedule",
			hasPayload: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trigger := TriggerInfo{}

			if tt.hasPayload {
				trigger.EventPayload = json.RawMessage(`{"test":"data"}`)
				trigger.EventPayloadSize = 15
			}

			data, err := json.Marshal(trigger)
			require.NoError(t, err)

			var result TriggerInfo
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			if tt.hasPayload {
				assert.NotNil(t, result.EventPayload)
			}
		})
	}
}

func TestRunnerInfo_OSTypes(t *testing.T) {
	osTypes := []struct {
		os   string
		arch string
	}{
		{"Linux", "X64"},
		{"macOS", "ARM64"},
		{"macOS", "X64"},
		{"Windows", "X64"},
	}

	for _, tt := range osTypes {
		t.Run(tt.os+"_"+tt.arch, func(t *testing.T) {
			runner := RunnerInfo{
				Name: "Test Runner",
				OS:   tt.os,
				Arch: tt.arch,
			}

			data, err := json.Marshal(runner)
			require.NoError(t, err)

			var result RunnerInfo
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.os, result.OS)
			assert.Equal(t, tt.arch, result.Arch)
		})
	}
}

func TestRepositoryInfo_RefTypes(t *testing.T) {
	tests := []struct {
		name    string
		refName string
	}{
		{
			name:    "Main Branch",
			refName: "main",
		},
		{
			name:    "Feature Branch",
			refName: "feature/new-feature",
		},
		{
			name:    "Release Tag",
			refName: "v1.2.3",
		},
		{
			name:    "PR Merge",
			refName: "123/merge",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := RepositoryInfo{
				RefName: tt.refName,
			}

			data, err := json.Marshal(repository)
			require.NoError(t, err)

			var result RepositoryInfo
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.refName, result.RefName)
		})
	}
}

func TestMetadataInfo_TimeFormats(t *testing.T) {
	tests := []struct {
		name     string
		jsonTime string
		valid    bool
	}{
		{
			name:     "RFC3339 format",
			jsonTime: `{"started_on":"2025-11-12T10:00:00Z"}`,
			valid:    true,
		},
		{
			name:     "RFC3339 with timezone",
			jsonTime: `{"started_on":"2025-11-12T10:00:00+05:30"}`,
			valid:    true,
		},
		{
			name:     "RFC3339 with nanoseconds",
			jsonTime: `{"started_on":"2025-11-12T10:00:00.123456Z"}`,
			valid:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var meta MetadataInfo
			err := json.Unmarshal([]byte(tt.jsonTime), &meta)

			if tt.valid {
				require.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestTriggerInfo_LargeEventPayload(t *testing.T) {
	// Create a large valid JSON payload
	commits := make([]string, 100)
	for i := range commits {
		commits[i] = `{"sha":"abc` + string(rune('0'+i%10)) + `","message":"commit message"}`
	}
	largePayload := json.RawMessage(`{"ref":"refs/heads/main","commits":[` +
		commits[0] + `,` + commits[1] + `,` + commits[2] + `]}`)

	trigger := TriggerInfo{
		EventPayload:     largePayload,
		EventPayloadSize: int64(len(largePayload)),
	}

	data, err := json.Marshal(trigger)
	require.NoError(t, err)

	var result TriggerInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, int64(len(largePayload)), result.EventPayloadSize)
	assert.NotNil(t, result.EventPayload)
}

func TestRunnerInfo_EmptyEnvironment(t *testing.T) {
	runner := RunnerInfo{
		Name:        "Test Runner",
		OS:          "Linux",
		Arch:        "X64",
		Environment: make(map[string]string),
	}

	data, err := json.Marshal(runner)
	require.NoError(t, err)

	var result RunnerInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "Test Runner", result.Name)
}

func TestPredicate_Minimal(t *testing.T) {
	predicate := Predicate{
		Workflow: WorkflowInfo{
			Job: "job",
		},
		Runner: RunnerInfo{
			Name: "runner",
			OS:   "Linux",
			Arch: "X64",
		},
		Trigger: TriggerInfo{},
		Repository: RepositoryInfo{
			RefName: "main",
		},
		Metadata: MetadataInfo{
			ServerURL: "https://github.com",
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "job", result.Workflow.Job)
	assert.Equal(t, "main", result.Repository.RefName)
}
