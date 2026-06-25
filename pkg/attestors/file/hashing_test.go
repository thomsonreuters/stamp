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
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/thomsonreuters/stamp/pkg/crypto/hash"
	"github.com/thomsonreuters/stamp/pkg/logger"
	filepredicate "github.com/thomsonreuters/stamp/pkg/predicates/file/v1"
)

// TestGenerateManifestDigestImpl_Success verifies successful manifest generation.
func TestGenerateManifestDigestImpl_Success(t *testing.T) {
	mockHasher := hash.NewMockHasher()
	mockHasher.On("HashBytes", context.Background(), []byte("file1.txt\x00hash1\x00file2.txt\x00hash2\x00"), "manifest").Return(
		hash.Result{
			Digests: map[string]string{
				"sha256": "manifestHash123",
			},
		}, nil)

	a := &Attestor{
		logger: logger.NewNoop(),
		hasher: mockHasher,
		config: Config{
			HashAlgorithms: []string{"sha256"},
		},
		artifacts: []filepredicate.ArtifactInfo{
			{
				Path: "file2.txt",
				Digests: map[string]string{
					"sha256": "hash2",
				},
			},
			{
				Path: "file1.txt",
				Digests: map[string]string{
					"sha256": "hash1",
				},
			},
		},
	}

	result := a.generateManifestDigest()
	assert.NotNil(t, result)
	assert.Equal(t, "manifestHash123", result["sha256"])
	mockHasher.AssertExpectations(t)
}

// TestGenerateManifestDigestImpl_EmptyArtifacts verifies empty artifact handling.
func TestGenerateManifestDigestImpl_EmptyArtifacts(t *testing.T) {
	mockHasher := hash.NewMockHasher()
	mockHasher.On("HashBytes", context.Background(), []byte(""), "manifest").Return(
		hash.Result{
			Digests: map[string]string{
				"sha256": "emptyHash",
			},
		}, nil)

	a := &Attestor{
		logger: logger.NewNoop(),
		hasher: mockHasher,
		config: Config{
			HashAlgorithms: []string{"sha256"},
		},
		artifacts: []filepredicate.ArtifactInfo{},
	}

	result := a.generateManifestDigest()
	assert.NotNil(t, result)
	assert.Equal(t, "emptyHash", result["sha256"])
	mockHasher.AssertExpectations(t)
}

// TestGenerateManifestDigestImpl_MultipleAlgorithms verifies multiple hash algorithms.
func TestGenerateManifestDigestImpl_MultipleAlgorithms(t *testing.T) {
	manifestData := "file1.txt\x00sha256hash1\x00sha512hash1\x00"

	mockHasher := hash.NewMockHasher()
	mockHasher.On("HashBytes", context.Background(), []byte(manifestData), "manifest").Return(
		hash.Result{
			Digests: map[string]string{
				"sha256": "manifestSha256",
				"sha512": "manifestSha512",
			},
		}, nil)

	a := &Attestor{
		logger: logger.NewNoop(),
		hasher: mockHasher,
		config: Config{
			HashAlgorithms: []string{"sha256", "sha512"},
		},
		artifacts: []filepredicate.ArtifactInfo{
			{
				Path: "file1.txt",
				Digests: map[string]string{
					"sha256": "sha256hash1",
					"sha512": "sha512hash1",
				},
			},
		},
	}

	result := a.generateManifestDigest()
	assert.NotNil(t, result)
	assert.Equal(t, "manifestSha256", result["sha256"])
	assert.Equal(t, "manifestSha512", result["sha512"])
	mockHasher.AssertExpectations(t)
}

// TestGenerateManifestDigestImpl_SortedOrder verifies artifacts are sorted.
func TestGenerateManifestDigestImpl_SortedOrder(t *testing.T) {
	// Manifest should be sorted by path: a.txt, b.txt, c.txt
	expectedManifest := "a.txt\x00hashA\x00b.txt\x00hashB\x00c.txt\x00hashC\x00"

	mockHasher := hash.NewMockHasher()
	mockHasher.On("HashBytes", context.Background(), []byte(expectedManifest), "manifest").Return(
		hash.Result{
			Digests: map[string]string{"sha256": "sortedHash"},
		}, nil)

	a := &Attestor{
		logger: logger.NewNoop(),
		hasher: mockHasher,
		config: Config{
			HashAlgorithms: []string{"sha256"},
		},
		artifacts: []filepredicate.ArtifactInfo{
			{Path: "c.txt", Digests: map[string]string{"sha256": "hashC"}},
			{Path: "a.txt", Digests: map[string]string{"sha256": "hashA"}},
			{Path: "b.txt", Digests: map[string]string{"sha256": "hashB"}},
		},
	}

	result := a.generateManifestDigest()
	assert.NotNil(t, result)
	assert.Equal(t, "sortedHash", result["sha256"])
	mockHasher.AssertExpectations(t)
}

// TestGenerateManifestDigestImpl_HashError verifies error handling.
func TestGenerateManifestDigestImpl_HashError(t *testing.T) {
	mockHasher := hash.NewMockHasher()
	mockHasher.On("HashBytes", context.Background(), []byte("file1.txt\x00hash1\x00"), "manifest").Return(
		hash.Result{},
		errors.New("hash error"))

	a := &Attestor{
		logger: logger.NewNoop(),
		hasher: mockHasher,
		config: Config{
			HashAlgorithms: []string{"sha256"},
		},
		artifacts: []filepredicate.ArtifactInfo{
			{Path: "file1.txt", Digests: map[string]string{"sha256": "hash1"}},
		},
	}

	result := a.generateManifestDigest()
	assert.NotNil(t, result)
	assert.Empty(t, result) // Should return empty map on error
	mockHasher.AssertExpectations(t)
}

// TestGenerateManifestDigestImpl_ResultError verifies result error handling.
func TestGenerateManifestDigestImpl_ResultError(t *testing.T) {
	mockHasher := hash.NewMockHasher()
	mockHasher.On("HashBytes", context.Background(), []byte("file1.txt\x00hash1\x00"), "manifest").Return(
		hash.Result{
			Error: errors.New("result error"),
		}, nil)

	a := &Attestor{
		logger: logger.NewNoop(),
		hasher: mockHasher,
		config: Config{
			HashAlgorithms: []string{"sha256"},
		},
		artifacts: []filepredicate.ArtifactInfo{
			{Path: "file1.txt", Digests: map[string]string{"sha256": "hash1"}},
		},
	}

	result := a.generateManifestDigest()
	assert.NotNil(t, result)
	assert.Empty(t, result) // Should return empty map on error
	mockHasher.AssertExpectations(t)
}

// TestGenerateManifestDigestImpl_LargeArtifactSet verifies handling of many artifacts.
func TestGenerateManifestDigestImpl_LargeArtifactSet(t *testing.T) {
	artifacts := make([]filepredicate.ArtifactInfo, 100)
	for i := range 100 {
		artifacts[i] = filepredicate.ArtifactInfo{
			Path: string(rune('a'+(i%26))) + ".txt",
			Digests: map[string]string{
				"sha256": "hash",
			},
		}
	}

	mockHasher := hash.NewMockHasher()
	// Use mock.Anything to match any byte slice
	mockHasher.On("HashBytes", context.Background(), mock.Anything, "manifest").Return(
		hash.Result{
			Digests: map[string]string{"sha256": "largeSetHash"},
		}, nil)

	a := &Attestor{
		logger: logger.NewNoop(),
		hasher: mockHasher,
		config: Config{
			HashAlgorithms: []string{"sha256"},
		},
		artifacts: artifacts,
	}

	result := a.generateManifestDigest()
	assert.NotNil(t, result)
	assert.Equal(t, "largeSetHash", result["sha256"])
	mockHasher.AssertExpectations(t)
}

// TestGenerateManifestDigestImpl_MissingDigests verifies handling of missing algorithm digests.
func TestGenerateManifestDigestImpl_MissingDigests(t *testing.T) {
	// File has sha256 but not sha512
	manifestData := "file1.txt\x00hash1\x00"

	mockHasher := hash.NewMockHasher()
	mockHasher.On("HashBytes", context.Background(), []byte(manifestData), "manifest").Return(
		hash.Result{
			Digests: map[string]string{
				"sha256": "manifestHash",
			},
		}, nil)

	a := &Attestor{
		logger: logger.NewNoop(),
		hasher: mockHasher,
		config: Config{
			HashAlgorithms: []string{"sha256", "sha512"},
		},
		artifacts: []filepredicate.ArtifactInfo{
			{
				Path: "file1.txt",
				Digests: map[string]string{
					"sha256": "hash1",
					// sha512 missing
				},
			},
		},
	}

	result := a.generateManifestDigest()
	assert.NotNil(t, result)
	assert.Equal(t, "manifestHash", result["sha256"])
	mockHasher.AssertExpectations(t)
}
