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

package git

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	gitclient "github.com/thomsonreuters/stamp/pkg/clients/git"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/logger"
	gitpredicate "github.com/thomsonreuters/stamp/pkg/predicates/git/v1"
)

func TestID(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "git", attestor.ID())
}

func TestName(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "Git Attestor", attestor.Name())
}

func TestDescription(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "Generates Git repository attestation with source control metadata", attestor.Description())
}

func TestPredicateURI(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, gitpredicate.PredicateURI, attestor.PredicateURI())
}

func TestConfigSchema(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	schema := attestor.ConfigSchema()

	require.NotEmpty(t, schema)

	fieldNames := make(map[string]bool)
	for _, field := range schema {
		fieldNames[field.Name] = true
	}

	expectedFields := []string{
		"git-working-dir",
		"dirty-behavior",
		"include-binary-hash",
		"include-signature",
		"include-refs",
		"include-all-remotes",
		"include-tags",
		"include-submodules",
		"hash-algorithms",
		"redact-identity",
		"sensitive-fields",
	}

	for _, expected := range expectedFields {
		assert.True(t, fieldNames[expected], "Expected field %s to be in schema", expected)
	}

	// Verify all fields have required properties and spot-check specific defaults
	for _, field := range schema {
		assert.NotEmpty(t, field.Name)
		assert.NotEmpty(t, field.Type)
		assert.NotEmpty(t, field.Description)

		switch field.Name {
		case "git-working-dir":
			assert.Equal(t, "string", field.Type)
			assert.Equal(t, ".", field.Default)
		case "dirty-behavior":
			assert.Equal(t, "string", field.Type)
			assert.Equal(t, "allow", field.Default)
		case "include-signature":
			assert.Equal(t, "bool", field.Type)
			assert.Equal(t, true, field.Default)
		case "hash-algorithms":
			assert.Equal(t, "[]string", field.Type)
		}
	}
}

func TestSchema(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	schema := attestor.Schema()

	require.NotNil(t, schema)
	assert.Equal(t, "Git Source Control Attestation", schema.Title)
	assert.Contains(t, schema.ID.String(), "github.com/thomsonreuters/stamp/pkg/predicates/git/v1")
}

func TestPreAttest(t *testing.T) {
	tests := []struct {
		name        string
		config      core.Config
		setupMock   func(*gitclient.MockClient)
		expectError bool
		validate    func(*testing.T, *Attestor)
	}{
		{
			name: "successful pre-attest with default config",
			config: core.Config{
				"git-working-dir": ".",
			},
			setupMock: func(m *gitclient.MockClient) {
				m.On("IsGitRepository", mock.Anything, mock.Anything).Return(true).Maybe()
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				assert.NotEmpty(t, a.workingDir)
				assert.Equal(t, "allow", a.config.DirtyBehavior)
			},
		},
		{
			name: "with custom config options",
			config: core.Config{
				"git-working-dir":     ".",
				"dirty-behavior":      "fail",
				"include-signature":   false,
				"include-refs":        true,
				"include-all-remotes": true,
			},
			setupMock: func(m *gitclient.MockClient) {
				m.On("IsGitRepository", mock.Anything, mock.Anything).Return(true).Maybe()
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				assert.Equal(t, "fail", a.config.DirtyBehavior)
				assert.False(t, a.config.IncludeSignature)
				assert.True(t, a.config.IncludeRefs)
				assert.True(t, a.config.IncludeAllRemotes)
			},
		},
		{
			name: "not a git repository",
			config: core.Config{
				"git-working-dir": ".",
			},
			setupMock: func(m *gitclient.MockClient) {
				m.On("IsGitRepository", mock.Anything, mock.Anything).Return(false).Maybe()
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := gitclient.SetupMockClient(t)
			if tt.setupMock != nil {
				tt.setupMock(mockClient)
			}

			attestor := &Attestor{logger: logger.NewNoop()}
			err := attestor.PreAttest(t.Context(), tt.config)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, attestor)
				}
			}
		})
	}
}

func TestPostAttest(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	err := attestor.PostAttest(t.Context(), core.Config{})

	// PostAttest is a no-op for this attestor
	assert.NoError(t, err)
}

func TestGeneratePredicate(t *testing.T) {
	tests := []struct {
		name     string
		config   core.Config
		validate func(*testing.T, any)
	}{
		{
			name:   "basic predicate without redaction",
			config: core.Config{},
			validate: func(t *testing.T, pred any) {
				p, ok := pred.(gitpredicate.Predicate)
				require.True(t, ok)

				assert.Equal(t, "https://github.com/test/repo", p.Repository.URL)
				assert.Equal(t, "main", p.Repository.Branch)
				assert.Equal(t, "abc123def456", p.Commit.Hash)
				assert.Equal(t, "Test Author", p.Commit.Author.Name)
				assert.Equal(t, "author@example.com", p.Commit.Author.Email)
				assert.NotNil(t, p.GitBinary)
				assert.Equal(t, "/usr/bin/git", p.GitBinary.Path)
				assert.Len(t, p.Refs, 2)
				assert.Len(t, p.Remotes, 1)
				assert.Len(t, p.Tags, 1)
				assert.Len(t, p.Submodules, 1)
			},
		},
		{
			name: "with author redaction",
			config: core.Config{
				"redact-identity": true,
			},
			validate: func(t *testing.T, pred any) {
				p, ok := pred.(gitpredicate.Predicate)
				require.True(t, ok)

				assert.Equal(t, "[REDACTED]", p.Commit.Author.Name)
				assert.Equal(t, "[REDACTED]", p.Commit.Author.Email)
				assert.Equal(t, "[REDACTED]", p.Commit.Committer.Name)
				assert.Equal(t, "[REDACTED]", p.Commit.Committer.Email)
				// Other fields should be preserved
				assert.Equal(t, "abc123def456", p.Commit.Hash)
			},
		},
		{
			name: "with sensitive fields redaction",
			config: core.Config{
				"sensitive-fields": []string{"repository", "commit.message"},
			},
			validate: func(t *testing.T, pred any) {
				p, ok := pred.(gitpredicate.Predicate)
				require.True(t, ok)

				assert.Equal(t, "[REDACTED]", p.Repository.URL)
				assert.Equal(t, "[REDACTED]", p.Commit.Message)
			},
		},
		{
			name: "combined redaction",
			config: core.Config{
				"redact-identity":  true,
				"sensitive-fields": []string{"branch", "refs"},
			},
			validate: func(t *testing.T, pred any) {
				p, ok := pred.(gitpredicate.Predicate)
				require.True(t, ok)

				assert.Equal(t, "[REDACTED]", p.Commit.Author.Name)
				assert.Equal(t, "[REDACTED]", p.Repository.Branch)
				assert.Nil(t, p.Refs)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh attestor for each test
			a := createTestAttestor()
			a.parseConfig(tt.config)

			predicate, err := a.GeneratePredicate(tt.config)

			require.NoError(t, err)
			require.NotNil(t, predicate)

			if tt.validate != nil {
				tt.validate(t, predicate)
			}
		})
	}
}

func TestSubjects(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		commitMetadata: gitpredicate.CommitMetadata{
			Hash: "abc123def456",
			CommitDigest: gitpredicate.DigestSet{
				"sha256": "sha256hash",
				"sha512": "sha512hash",
			},
		},
		repoURL: "https://github.com/test/repo",
	}

	subjects := attestor.Subjects(core.Config{})

	require.Len(t, subjects, 1)

	subject := subjects[0]
	assert.Equal(t, "git+https://github.com/test/repo@abc123def456", subject.Name)
	assert.Contains(t, subject.Digest, "sha1")
	assert.Equal(t, "abc123def456", subject.Digest["sha1"])
	assert.Contains(t, subject.Digest, "sha256")
	assert.Equal(t, "sha256hash", subject.Digest["sha256"])
	assert.Contains(t, subject.Digest, "sha512")
	assert.Equal(t, "sha512hash", subject.Digest["sha512"])
}

func TestHandleDirtyRepository(t *testing.T) {
	tests := []struct {
		name          string
		dirtyBehavior string
		wantErr       bool
	}{
		{
			name:          "allow behavior",
			dirtyBehavior: DirtyBehaviorAllow,
			wantErr:       false,
		},
		{
			name:          "warn behavior",
			dirtyBehavior: DirtyBehaviorWarn,
			wantErr:       false,
		},
		{
			name:          "fail behavior",
			dirtyBehavior: DirtyBehaviorFail,
			wantErr:       true,
		},
		{
			name:          "invalid behavior defaults to allow",
			dirtyBehavior: "invalid",
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
				config: Config{
					DirtyBehavior: tt.dirtyBehavior,
				},
			}

			err := attestor.handleDirtyRepository(t.Context(), 5)

			if tt.wantErr {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrRepositoryDirty)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGitBinaryNilWhenNotCollected(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		commitMetadata: gitpredicate.CommitMetadata{
			Hash: "abc123",
		},
		repositoryStatus: gitpredicate.RepositoryStatus{},
		gitBinary: gitpredicate.GitBinaryInfo{
			// Path is empty, indicating binary info wasn't collected
			Path: "",
		},
	}

	config := core.Config{}
	predicate, err := attestor.GeneratePredicate(config)

	require.NoError(t, err)

	gitPred, ok := predicate.(gitpredicate.Predicate)
	require.True(t, ok)
	assert.Nil(t, gitPred.GitBinary, "GitBinary should be nil when not collected")
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   core.Config
		expected Config
	}{
		{
			name: "all fields",
			config: core.Config{
				"git-working-dir":     "/path/to/repo",
				"dirty-behavior":      "fail",
				"include-binary-hash": true,
				"include-signature":   false,
				"include-refs":        true,
				"include-all-remotes": true,
				"include-tags":        true,
				"include-submodules":  true,
				"hash-algorithms":     []string{"sha256", "sha512"},
				"redact-identity":     true,
				"sensitive-fields":    []string{"branch", "message"},
			},
			expected: Config{
				WorkingDir:        "/path/to/repo",
				DirtyBehavior:     "fail",
				IncludeBinaryHash: true,
				IncludeSignature:  false,
				IncludeRefs:       true,
				IncludeAllRemotes: true,
				IncludeTags:       true,
				IncludeSubmodules: true,
				HashAlgorithms:    []string{"sha256", "sha512"},
				RedactIdentity:    true,
				SensitiveFields:   []string{"branch", "message"},
			},
		},
		{
			name:   "empty config uses defaults",
			config: core.Config{},
			expected: Config{
				WorkingDir:       ".",
				DirtyBehavior:    "allow",
				IncludeSignature: true,
				HashAlgorithms:   []string{"sha1", "sha256"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{logger: logger.NewNoop()}
			attestor.parseConfig(tt.config)

			assert.Equal(t, tt.expected.WorkingDir, attestor.config.WorkingDir)
			assert.Equal(t, tt.expected.DirtyBehavior, attestor.config.DirtyBehavior)
			assert.Equal(t, tt.expected.IncludeBinaryHash, attestor.config.IncludeBinaryHash)
			assert.Equal(t, tt.expected.IncludeSignature, attestor.config.IncludeSignature)
			assert.Equal(t, tt.expected.IncludeRefs, attestor.config.IncludeRefs)
			assert.Equal(t, tt.expected.IncludeAllRemotes, attestor.config.IncludeAllRemotes)
			assert.Equal(t, tt.expected.IncludeTags, attestor.config.IncludeTags)
			assert.Equal(t, tt.expected.IncludeSubmodules, attestor.config.IncludeSubmodules)
			assert.Equal(t, tt.expected.RedactIdentity, attestor.config.RedactIdentity)
		})
	}
}

func TestAttestorInterfaceCompliance(t *testing.T) {
	var _ core.Attestor = (*Attestor)(nil)
}

func createTestAttestor() *Attestor {
	return &Attestor{
		logger:     logger.NewNoop(),
		workingDir: "/test/repo",
		commitMetadata: gitpredicate.CommitMetadata{
			Hash:         "abc123def456",
			TreeHash:     "tree123",
			ParentHashes: []string{"parent1", "parent2"},
			Author: gitpredicate.PersonInfo{
				Name:      "Test Author",
				Email:     "author@example.com",
				Timestamp: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			Committer: gitpredicate.PersonInfo{
				Name:      "Test Committer",
				Email:     "committer@example.com",
				Timestamp: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			Message:      "Test commit message",
			Signature:    "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----",
			CommitDigest: gitpredicate.DigestSet{"sha1": "abc123def456", "sha256": "sha256hash"},
		},
		branch:  "main",
		repoURL: "https://github.com/test/repo",
		repositoryStatus: gitpredicate.RepositoryStatus{
			IsDirty:      false,
			FileStatus:   map[string]gitpredicate.FileStatus{},
			DetachedHead: false,
			ShallowClone: false,
		},
		gitBinary: gitpredicate.GitBinaryInfo{
			Tool: "git version 2.39.0",
			Path: "/usr/bin/git",
			Hash: gitpredicate.DigestSet{"sha256": "binaryhash"},
		},
		refs: []string{"refs/heads/main", "refs/tags/v1.0.0"},
		remotes: []gitpredicate.RemoteInfo{
			{Name: "origin", FetchURL: "https://github.com/test/repo.git", PushURL: "https://github.com/test/repo.git"},
		},
		tags: []gitpredicate.TagInfo{
			{
				Name:        "v1.0.0",
				TaggerName:  "Tagger",
				TaggerEmail: "tagger@example.com",
				When:        time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
				Message:     "Release v1.0.0",
			},
		},
		submodules: []gitpredicate.SubmoduleInfo{
			{Path: "submodule/path", Commit: "subhash", URL: "https://github.com/test/submodule.git", Status: " "},
		},
	}
}
