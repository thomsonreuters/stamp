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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProvenanceV1URI(t *testing.T) {
	assert.Equal(t, "https://slsa.dev/provenance/v1", ProvenanceV1URI)
}

func TestBuildDefinition_JSONMarshal(t *testing.T) {
	buildDefinition := BuildDefinition{
		BuildType: "https://example.com/build-type",
		ExternalParameters: map[string]any{
			"repo": "https://github.com/example/repo",
			"ref":  "refs/heads/main",
		},
		InternalParameters: map[string]any{
			"env": "production",
		},
		ResolvedDependencies: []ResourceDescriptor{
			{
				URI: "pkg:npm/express@4.18.0",
				Digest: map[string]string{
					"sha256": "abc123",
				},
			},
		},
	}

	data, err := json.Marshal(buildDefinition)
	require.NoError(t, err)

	assert.Contains(t, string(data), "build_type")
	assert.Contains(t, string(data), "external_parameters")
	assert.Contains(t, string(data), "internal_parameters")
	assert.Contains(t, string(data), "resolved_dependencies")
}

func TestBuildDefinition_JSONUnmarshal(t *testing.T) {
	jsonData := `{
		"build_type": "https://example.com/build-type",
		"external_parameters": {
			"repo": "https://github.com/example/repo"
		},
		"internal_parameters": {
			"env": "production"
		},
		"resolved_dependencies": [
			{
				"uri": "pkg:npm/express@4.18.0",
				"digest": {
					"sha256": "abc123"
				}
			}
		]
	}`

	var buildDefinition BuildDefinition
	err := json.Unmarshal([]byte(jsonData), &buildDefinition)
	require.NoError(t, err)

	assert.Equal(t, "https://example.com/build-type", buildDefinition.BuildType)
	assert.Equal(t, "https://github.com/example/repo", buildDefinition.ExternalParameters["repo"])
	assert.Equal(t, "production", buildDefinition.InternalParameters["env"])
	require.Len(t, buildDefinition.ResolvedDependencies, 1)
	assert.Equal(t, "pkg:npm/express@4.18.0", buildDefinition.ResolvedDependencies[0].URI)
}

func TestBuildDefinition_OmitEmpty(t *testing.T) {
	buildDefinition := BuildDefinition{
		BuildType:          "https://example.com/build-type",
		ExternalParameters: map[string]any{},
		InternalParameters: map[string]any{},
	}

	data, err := json.Marshal(buildDefinition)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "resolved_dependencies")
}

func TestRunDetails_JSONMarshal(t *testing.T) {
	now := time.Now().UTC()
	runDetails := RunDetails{
		Builder: Builder{
			ID: "https://example.com/builder",
			Version: map[string]string{
				"builder": "1.0.0",
			},
		},
		Metadata: BuilderMetadata{
			InvocationID: "build-123",
			StartedOn:    now,
		},
	}

	data, err := json.Marshal(runDetails)
	require.NoError(t, err)

	assert.Contains(t, string(data), "builder")
	assert.Contains(t, string(data), "metadata")
	assert.Contains(t, string(data), "invocation_id")
	assert.Contains(t, string(data), "started_on")
}

func TestRunDetails_JSONUnmarshal(t *testing.T) {
	jsonData := `{
		"builder": {
			"id": "https://example.com/builder",
			"version": {
				"builder": "1.0.0"
			}
		},
		"metadata": {
			"invocation_id": "build-123",
			"started_on": "2025-11-12T10:00:00Z"
		}
	}`

	var runDetails RunDetails
	err := json.Unmarshal([]byte(jsonData), &runDetails)
	require.NoError(t, err)

	assert.Equal(t, "https://example.com/builder", runDetails.Builder.ID)
	assert.Equal(t, "1.0.0", runDetails.Builder.Version["builder"])
	assert.Equal(t, "build-123", runDetails.Metadata.InvocationID)
	assert.Equal(t, 2025, runDetails.Metadata.StartedOn.Year())
}

func TestBuilder_JSONMarshal(t *testing.T) {
	builder := Builder{
		ID: "https://github.com/actions/runner",
		Version: map[string]string{
			"github-actions": "1.0",
		},
	}

	data, err := json.Marshal(builder)
	require.NoError(t, err)

	assert.Contains(t, string(data), "id")
	assert.Contains(t, string(data), "version")
}

func TestBuilder_OmitEmpty(t *testing.T) {
	builder := Builder{
		ID: "https://github.com/actions/runner",
	}

	data, err := json.Marshal(builder)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "version")
}

func TestBuilderMetadata_JSONMarshal(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)
	builderMetadata := BuilderMetadata{
		InvocationID: "inv-456",
		StartedOn:    now,
	}

	data, err := json.Marshal(builderMetadata)
	require.NoError(t, err)

	assert.Contains(t, string(data), "invocation_id")
	assert.Contains(t, string(data), "started_on")
	assert.Contains(t, string(data), "2025-11-12T10:00:00Z")
}

func TestBuilderMetadata_JSONUnmarshal(t *testing.T) {
	jsonData := `{
		"invocation_id": "inv-456",
		"started_on": "2025-11-12T10:00:00Z"
	}`

	var builderMetadata BuilderMetadata
	err := json.Unmarshal([]byte(jsonData), &builderMetadata)
	require.NoError(t, err)

	assert.Equal(t, "inv-456", builderMetadata.InvocationID)
	assert.Equal(t, 2025, builderMetadata.StartedOn.Year())
	assert.Equal(t, time.November, builderMetadata.StartedOn.Month())
	assert.Equal(t, 12, builderMetadata.StartedOn.Day())
}

func TestResourceDescriptor_JSONMarshal(t *testing.T) {
	resourceDescription := ResourceDescriptor{
		URI: "pkg:npm/lodash@4.17.21",
		Digest: map[string]string{
			"sha256": "def456",
			"sha512": "ghi789",
		},
	}

	data, err := json.Marshal(resourceDescription)
	require.NoError(t, err)

	assert.Contains(t, string(data), "uri")
	assert.Contains(t, string(data), "digest")
	assert.Contains(t, string(data), "sha256")
}

func TestResourceDescriptor_JSONUnmarshal(t *testing.T) {
	jsonData := `{
		"uri": "pkg:npm/lodash@4.17.21",
		"digest": {
			"sha256": "def456",
			"sha512": "ghi789"
		}
	}`

	var resourceDescription ResourceDescriptor
	err := json.Unmarshal([]byte(jsonData), &resourceDescription)
	require.NoError(t, err)

	assert.Equal(t, "pkg:npm/lodash@4.17.21", resourceDescription.URI)
	assert.Equal(t, "def456", resourceDescription.Digest["sha256"])
	assert.Equal(t, "ghi789", resourceDescription.Digest["sha512"])
}

func TestProvenanceV1_CompleteExample(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	provenance := struct {
		Type      string `json:"_type"`
		Predicate any    `json:"predicate"`
	}{
		Type: ProvenanceV1URI,
		Predicate: map[string]any{
			"build_definition": BuildDefinition{
				BuildType: "https://slsa.dev/build-type/v1",
				ExternalParameters: map[string]any{
					"repository": "https://github.com/example/project",
					"ref":        "refs/heads/main",
				},
				InternalParameters: map[string]any{
					"environment": "production",
				},
				ResolvedDependencies: []ResourceDescriptor{
					{
						URI: "pkg:github/actions/checkout@v3",
						Digest: map[string]string{
							"sha256": "abc123def456",
						},
					},
				},
			},
			"run_details": RunDetails{
				Builder: Builder{
					ID: "https://github.com/actions/runner",
					Version: map[string]string{
						"runner": "2.0.0",
					},
				},
				Metadata: BuilderMetadata{
					InvocationID: "build-789",
					StartedOn:    now,
				},
			},
		},
	}

	data, err := json.MarshalIndent(provenance, "", "  ")
	require.NoError(t, err)

	assert.Contains(t, string(data), ProvenanceV1URI)
	assert.Contains(t, string(data), "build_definition")
	assert.Contains(t, string(data), "run_details")

	var result map[string]any
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, ProvenanceV1URI, result["_type"])
	assert.NotNil(t, result["predicate"])
}

func TestBuildDefinition_EmptyMaps(t *testing.T) {
	builderDefinition := BuildDefinition{
		BuildType:          "test-build",
		ExternalParameters: make(map[string]any),
		InternalParameters: make(map[string]any),
	}

	data, err := json.Marshal(builderDefinition)
	require.NoError(t, err)

	var result BuildDefinition
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "test-build", result.BuildType)
	assert.NotNil(t, result.ExternalParameters)
	assert.NotNil(t, result.InternalParameters)
}

func TestResourceDescriptor_MultipleDigests(t *testing.T) {
	resourceDescription := ResourceDescriptor{
		URI: "pkg:maven/com.example/library@1.0",
		Digest: map[string]string{
			"sha1":   "abc",
			"sha256": "def",
			"sha512": "ghi",
			"md5":    "jkl",
		},
	}

	data, err := json.Marshal(resourceDescription)
	require.NoError(t, err)

	var result ResourceDescriptor
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Len(t, result.Digest, 4)
	assert.Equal(t, "abc", result.Digest["sha1"])
	assert.Equal(t, "def", result.Digest["sha256"])
}

func TestBuilderMetadata_TimeFormats(t *testing.T) {
	tests := []struct {
		name     string
		jsonTime string
		valid    bool
	}{
		{
			name:     "RFC3339 format",
			jsonTime: `{"invocation_id":"test","started_on":"2025-11-12T10:00:00Z"}`,
			valid:    true,
		},
		{
			name:     "RFC3339 with timezone",
			jsonTime: `{"invocation_id":"test","started_on":"2025-11-12T10:00:00+05:30"}`,
			valid:    true,
		},
		{
			name:     "RFC3339 with nanoseconds",
			jsonTime: `{"invocation_id":"test","started_on":"2025-11-12T10:00:00.123456Z"}`,
			valid:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var builderMetadata BuilderMetadata
			err := json.Unmarshal([]byte(tt.jsonTime), &builderMetadata)

			if tt.valid {
				require.NoError(t, err)
				assert.Equal(t, "test", builderMetadata.InvocationID)
				assert.False(t, builderMetadata.StartedOn.IsZero())
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestBuildDefinition_NilMaps(t *testing.T) {
	buildDefinition := BuildDefinition{
		BuildType: "test-build",
	}

	data, err := json.Marshal(buildDefinition)
	require.NoError(t, err)

	var result BuildDefinition
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "test-build", result.BuildType)
}

func TestResourceDescriptor_EmptyDigest(t *testing.T) {
	resourceDescription := ResourceDescriptor{
		URI:    "pkg:npm/test@1.0",
		Digest: make(map[string]string),
	}

	data, err := json.Marshal(resourceDescription)
	require.NoError(t, err)

	var result ResourceDescriptor
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "pkg:npm/test@1.0", result.URI)
}

func TestBuilder_EmptyVersion(t *testing.T) {
	builder := Builder{
		ID:      "builder-id",
		Version: make(map[string]string),
	}

	data, err := json.Marshal(builder)
	require.NoError(t, err)

	var result Builder
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "builder-id", result.ID)
}

func TestProvenanceV1_Complete(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)
	finished := time.Date(2025, 11, 12, 10, 30, 0, 0, time.UTC)

	provenance := ProvenanceV1{
		BuildDefinition: BuildDefinition{
			BuildType: "https://slsa.dev/build-type/v1",
			ExternalParameters: map[string]any{
				"repository": "https://github.com/example/project",
			},
			InternalParameters: map[string]any{
				"environment": "production",
			},
			ResolvedDependencies: []ResourceDescriptor{
				{
					URI:    "pkg:npm/express@4.18.0",
					Digest: map[string]string{"sha256": "abc123"},
					Name:   "express",
				},
			},
		},
		RunDetails: RunDetails{
			Builder: Builder{
				ID: "https://github.com/actions/runner",
				Version: map[string]string{
					"runner": "2.0.0",
				},
			},
			Metadata: BuilderMetadata{
				InvocationID: "build-123",
				StartedOn:    now,
				FinishedOn:   finished,
			},
		},
	}

	data, err := json.Marshal(provenance)
	require.NoError(t, err)

	assert.Contains(t, string(data), "build_definition")
	assert.Contains(t, string(data), "run_details")
	assert.Contains(t, string(data), "finished_on")

	var result ProvenanceV1
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "https://slsa.dev/build-type/v1", result.BuildDefinition.BuildType)
	assert.Equal(t, "build-123", result.RunDetails.Metadata.InvocationID)
	assert.Equal(t, finished.Unix(), result.RunDetails.Metadata.FinishedOn.Unix())
}

func TestBuilderMetadata_FinishedOn(t *testing.T) {
	started := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)
	finished := time.Date(2025, 11, 12, 10, 30, 0, 0, time.UTC)

	builderMetadata := BuilderMetadata{
		InvocationID: "inv-123",
		StartedOn:    started,
		FinishedOn:   finished,
	}

	data, err := json.Marshal(builderMetadata)
	require.NoError(t, err)

	assert.Contains(t, string(data), "finished_on")

	var result BuilderMetadata
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, finished.Unix(), result.FinishedOn.Unix())
}

func TestBuilderMetadata_FinishedOnZeroValue(t *testing.T) {
	started := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	builderMetadata := BuilderMetadata{
		InvocationID: "inv-123",
		StartedOn:    started,
	}

	data, err := json.Marshal(builderMetadata)
	require.NoError(t, err)

	var result BuilderMetadata
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "inv-123", result.InvocationID)
	assert.True(t, result.FinishedOn.IsZero() || result.FinishedOn.Year() == 1)
}

func TestBuilder_BuilderDependencies(t *testing.T) {
	builder := Builder{
		ID: "builder-id",
		Version: map[string]string{
			"version": "1.0",
		},
		BuilderDependencies: []ResourceDescriptor{
			{
				URI:    "pkg:docker/builder@sha256:abc",
				Digest: map[string]string{"sha256": "abc123"},
				Name:   "builder-image",
			},
		},
	}

	data, err := json.Marshal(builder)
	require.NoError(t, err)

	assert.Contains(t, string(data), "builder_dependencies")

	var result Builder
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	require.Len(t, result.BuilderDependencies, 1)
	assert.Equal(t, "pkg:docker/builder@sha256:abc", result.BuilderDependencies[0].URI)
}

func TestRunDetails_Byproducts(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	runDetails := RunDetails{
		Builder: Builder{
			ID: "builder-id",
		},
		Metadata: BuilderMetadata{
			InvocationID: "inv-123",
			StartedOn:    now,
		},
		Byproducts: []ResourceDescriptor{
			{
				URI:       "https://logs.example.com/build-123.log",
				Name:      "build-log",
				MediaType: "text/plain",
			},
		},
	}

	data, err := json.Marshal(runDetails)
	require.NoError(t, err)

	assert.Contains(t, string(data), "byproducts")

	var result RunDetails
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	require.Len(t, result.Byproducts, 1)
	assert.Equal(t, "build-log", result.Byproducts[0].Name)
}

func TestResourceDescriptor_AllFields(t *testing.T) {
	resourceDescription := ResourceDescriptor{
		URI:              "pkg:npm/lodash@4.17.21",
		Digest:           map[string]string{"sha256": "abc123"},
		Name:             "lodash",
		DownloadLocation: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
		MediaType:        "application/vnd.npm.package",
		Content:          []byte("package content"),
		Annotations: map[string]any{
			"build_id": "12345",
			"verified": true,
		},
	}

	data, err := json.Marshal(resourceDescription)
	require.NoError(t, err)

	assert.Contains(t, string(data), "name")
	assert.Contains(t, string(data), "download_location")
	assert.Contains(t, string(data), "media_type")
	assert.Contains(t, string(data), "content")
	assert.Contains(t, string(data), "annotations")

	var result ResourceDescriptor
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "lodash", result.Name)
	assert.Equal(t, "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", result.DownloadLocation)
	assert.Equal(t, "application/vnd.npm.package", result.MediaType)
	assert.Equal(t, []byte("package content"), result.Content)
	assert.Equal(t, "12345", result.Annotations["build_id"])
}

func TestResourceDescriptor_OmitEmptyFields(t *testing.T) {
	resourceDescription := ResourceDescriptor{
		URI: "pkg:npm/test@1.0",
	}

	data, err := json.Marshal(resourceDescription)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "digest")
	assert.NotContains(t, string(data), "name")
	assert.NotContains(t, string(data), "download_location")
	assert.NotContains(t, string(data), "media_type")
	assert.NotContains(t, string(data), "content")
	assert.NotContains(t, string(data), "annotations")
}
