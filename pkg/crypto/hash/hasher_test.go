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

package hash

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("with defaults", func(t *testing.T) {
		hasher := New(Config{})
		assert.NotNil(t, hasher)

		// Test that defaults work by actually hashing
		result, err := hasher.HashBytes(context.Background(), []byte("test"), "test")
		require.NoError(t, err)
		assert.NotEmpty(t, result.Digests[AlgorithmSHA256])
	})

	t.Run("with custom config", func(t *testing.T) {
		hasher := New(Config{
			Algorithms: []string{AlgorithmSHA256, AlgorithmBLAKE3},
			Workers:    4,
			BufferSize: 128 * 1024,
		})
		assert.NotNil(t, hasher)

		// Test that custom algorithms work
		result, err := hasher.HashBytes(context.Background(), []byte("test"), "test")
		require.NoError(t, err)
		assert.Len(t, result.Digests, 2)
		assert.NotEmpty(t, result.Digests[AlgorithmSHA256])
		assert.NotEmpty(t, result.Digests[AlgorithmBLAKE3])
	})

	t.Run("single worker configuration", func(t *testing.T) {
		// Explicitly test single worker (simulates single-CPU system)
		hasher := New(Config{
			Workers: 1,
		})
		assert.NotNil(t, hasher)

		// Verify it can hash files without deadlock
		files := []string{
			createTestFile(t, "file1"),
			createTestFile(t, "file2"),
		}
		defer func() {
			for _, f := range files {
				_ = os.Remove(f)
			}
		}()

		results, err := hasher.HashFiles(context.Background(), files)
		require.NoError(t, err)
		assert.Len(t, results, 2)
		for _, result := range results {
			require.NoError(t, result.Error)
			assert.NotEmpty(t, result.Digests)
		}
	})
}

func TestHash(t *testing.T) {
	t.Run("hash from io.Reader", func(t *testing.T) {
		data := "hello world"
		reader := bytes.NewReader([]byte(data))

		hasher := New(Config{
			Algorithms: []string{AlgorithmSHA256},
		})

		result, err := hasher.Hash(context.Background(), reader, "test-data")

		require.NoError(t, err)
		assert.Equal(t, "test-data", result.Path)
		assert.Equal(t, int64(11), result.Size)
		assert.Len(t, result.Digests, 1)

		// Verify SHA256 of "hello world"
		expectedSHA256 := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
		assert.Equal(t, expectedSHA256, result.Digests[AlgorithmSHA256])
	})

	t.Run("hash with context cancellation", func(t *testing.T) {
		// Create large data source
		data := make([]byte, 10*1024*1024) // 10MB
		reader := bytes.NewReader(data)

		hasher := New(Config{
			Algorithms: []string{AlgorithmSHA256},
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		result, err := hasher.Hash(ctx, reader, "test-data")

		require.Error(t, err)
		assert.Equal(t, context.Canceled, result.Error)
	})
}

func TestHashBytes(t *testing.T) {
	t.Run("hash byte slice", func(t *testing.T) {
		data := []byte("hello world")

		hasher := New(Config{
			Algorithms: []string{AlgorithmSHA256, AlgorithmSHA512},
		})

		result, err := hasher.HashBytes(context.Background(), data, "example-data")

		require.NoError(t, err)
		assert.Equal(t, "example-data", result.Path)
		assert.Equal(t, int64(11), result.Size)
		assert.Len(t, result.Digests, 2)

		// Verify SHA256 of "hello world"
		expectedSHA256 := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
		assert.Equal(t, expectedSHA256, result.Digests[AlgorithmSHA256])
		assert.NotEmpty(t, result.Digests[AlgorithmSHA512])
	})

	t.Run("hash empty byte slice", func(t *testing.T) {
		data := []byte{}

		hasher := New(Config{
			Algorithms: []string{AlgorithmSHA256},
		})

		result, err := hasher.HashBytes(context.Background(), data, "empty")

		require.NoError(t, err)
		assert.Equal(t, "empty", result.Path)
		assert.Equal(t, int64(0), result.Size)

		// SHA256 of empty string
		expectedSHA256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		assert.Equal(t, expectedSHA256, result.Digests[AlgorithmSHA256])
	})
}

func TestHashFile(t *testing.T) {
	t.Run("hash single algorithm", func(t *testing.T) {
		// Create test file
		tmpFile := createTestFile(t, "hello world")
		defer func() { _ = os.Remove(tmpFile) }()

		hasher := New(Config{
			Algorithms: []string{AlgorithmSHA256},
		})

		result, err := hasher.HashFile(context.Background(), tmpFile)

		require.NoError(t, err)
		assert.Equal(t, tmpFile, result.Path)
		assert.Equal(t, int64(11), result.Size)
		assert.Len(t, result.Digests, 1)

		// Verify SHA256 of "hello world"
		expectedSHA256 := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
		assert.Equal(t, expectedSHA256, result.Digests[AlgorithmSHA256])
	})

	t.Run("hash multiple algorithms", func(t *testing.T) {
		tmpFile := createTestFile(t, "test data")
		defer func() { _ = os.Remove(tmpFile) }()

		hasher := New(Config{
			Algorithms: []string{AlgorithmSHA256, AlgorithmSHA512, AlgorithmBLAKE3},
		})

		result, err := hasher.HashFile(context.Background(), tmpFile)

		require.NoError(t, err)
		assert.Len(t, result.Digests, 3)
		assert.NotEmpty(t, result.Digests[AlgorithmSHA256])
		assert.NotEmpty(t, result.Digests[AlgorithmSHA512])
		assert.NotEmpty(t, result.Digests[AlgorithmBLAKE3])

		// All digests should be different (different algorithms)
		assert.NotEqual(t, result.Digests[AlgorithmSHA256], result.Digests[AlgorithmSHA512])
	})

	t.Run("hash with context cancellation", func(t *testing.T) {
		// Create large file
		tmpFile := createLargeTestFile(t, 10*1024*1024) // 10MB
		defer func() { _ = os.Remove(tmpFile) }()

		hasher := New(Config{
			Algorithms: []string{AlgorithmSHA256},
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		result, err := hasher.HashFile(ctx, tmpFile)

		require.Error(t, err)
		assert.Equal(t, context.Canceled, result.Error)
	})

	t.Run("file not found", func(t *testing.T) {
		hasher := New(Config{
			Algorithms: []string{AlgorithmSHA256},
		})

		result, err := hasher.HashFile(context.Background(), "/nonexistent/file.txt")

		require.Error(t, err)
		require.Error(t, result.Error)
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		tmpFile := createTestFile(t, "test")
		defer func() { _ = os.Remove(tmpFile) }()

		hasher := New(Config{
			Algorithms: []string{"md5"}, // Unsupported
		})

		result, err := hasher.HashFile(context.Background(), tmpFile)

		require.Error(t, err)
		require.Error(t, result.Error)
		assert.Contains(t, err.Error(), "unsupported")
	})
}

func TestHashFiles(t *testing.T) {
	t.Run("hash multiple files in parallel", func(t *testing.T) {
		// Create test files
		files := []string{
			createTestFile(t, "file1"),
			createTestFile(t, "file2"),
			createTestFile(t, "file3"),
		}
		defer func() {
			for _, f := range files {
				_ = os.Remove(f)
			}
		}()

		hasher := New(Config{
			Algorithms: []string{AlgorithmSHA256},
			Workers:    2,
		})

		results, err := hasher.HashFiles(context.Background(), files)

		require.NoError(t, err)
		assert.Len(t, results, 3)

		// Verify results are in correct order
		for i, result := range results {
			assert.Equal(t, files[i], result.Path)
			require.NoError(t, result.Error)
			assert.NotEmpty(t, result.Digests[AlgorithmSHA256])
		}

		// Verify hashes are different (different content)
		assert.NotEqual(t, results[0].Digests[AlgorithmSHA256], results[1].Digests[AlgorithmSHA256])
	})

	t.Run("empty file list", func(t *testing.T) {
		hasher := New(Config{})

		results, err := hasher.HashFiles(context.Background(), []string{})

		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("with context cancellation", func(t *testing.T) {
		// Create many large files to ensure cancellation happens during processing
		files := make([]string, 50)
		for i := range files {
			files[i] = createLargeTestFile(t, 5*1024*1024) // 5MB each
		}
		defer func() {
			for _, f := range files {
				_ = os.Remove(f)
			}
		}()

		hasher := New(Config{
			Algorithms: []string{AlgorithmSHA256},
			Workers:    1, // Single worker to make cancellation more likely
		})

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		results, err := hasher.HashFiles(ctx, files)

		// Should return error due to cancellation OR some results should have errors
		if err != nil {
			assert.Equal(t, context.DeadlineExceeded, err)
		} else {
			// If no overall error, check individual results
			errorCount := 0
			for _, result := range results {
				if result.Error != nil {
					errorCount++
				}
			}
			// Either we got an overall error or some individual errors
			assert.True(t, errorCount > 0 || err != nil,
				"expected either overall error or some results with errors due to cancellation")
		}
	})

	t.Run("handles individual file errors", func(t *testing.T) {
		files := []string{
			createTestFile(t, "valid"),
			"/nonexistent/file.txt",
			createTestFile(t, "also valid"),
		}
		defer func() {
			_ = os.Remove(files[0])
			_ = os.Remove(files[2])
		}()

		hasher := New(Config{
			Algorithms: []string{AlgorithmSHA256},
		})

		results, err := hasher.HashFiles(context.Background(), files)

		require.NoError(t, err) // Overall operation succeeds
		assert.Len(t, results, 3)

		// First file succeeds
		require.NoError(t, results[0].Error)
		assert.NotEmpty(t, results[0].Digests)

		// Second file fails
		require.Error(t, results[1].Error)

		// Third file succeeds
		require.NoError(t, results[2].Error)
		assert.NotEmpty(t, results[2].Digests)
	})
}

func TestValidateAlgorithm(t *testing.T) {
	tests := []struct {
		algorithm string
		valid     bool
	}{
		{AlgorithmSHA256, true},
		{AlgorithmSHA512, true},
		{AlgorithmBLAKE3, true},
		{AlgorithmSHA3_256, true},
		{AlgorithmSHA3_512, true},
		{"md5", false},
		{"sha1", false},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			result := ValidateAlgorithm(tt.algorithm)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestSupportedAlgorithms(t *testing.T) {
	algorithms := SupportedAlgorithms

	assert.Len(t, algorithms, 5)
	assert.Contains(t, algorithms, AlgorithmSHA256)
	assert.Contains(t, algorithms, AlgorithmSHA512)
	assert.Contains(t, algorithms, AlgorithmBLAKE3)
	assert.Contains(t, algorithms, AlgorithmSHA3_256)
	assert.Contains(t, algorithms, AlgorithmSHA3_512)
}

func TestConcurrentHashing(t *testing.T) {
	hasher := New(Config{
		Algorithms: []string{AlgorithmSHA256},
		BufferSize: 32 * 1024,
	})

	// Test concurrent access (which relies on buffer pooling)
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := range numGoroutines {
		go func(id int) {
			data := fmt.Appendf(nil, "concurrent test %d", id)
			result, err := hasher.HashBytes(context.Background(), data, fmt.Sprintf("test-%d", id))
			assert.NoError(t, err)
			assert.NotEmpty(t, result.Digests[AlgorithmSHA256])
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for range numGoroutines {
		<-done
	}
}

func TestParallelism(t *testing.T) {
	// Create many files to test parallel processing
	numFiles := 20
	files := make([]string, numFiles)
	for i := range numFiles {
		files[i] = createTestFile(t, string(rune('a'+i)))
	}
	defer func() {
		for _, f := range files {
			_ = os.Remove(f)
		}
	}()

	// Hash with different worker counts
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprintf("%d_workers", workers), func(t *testing.T) {
			hasher := New(Config{
				Algorithms: []string{AlgorithmSHA256},
				Workers:    workers,
			})

			start := time.Now()
			results, err := hasher.HashFiles(context.Background(), files)
			duration := time.Since(start)

			require.NoError(t, err)
			assert.Len(t, results, numFiles)

			t.Logf("Hashed %d files with %d workers in %v", numFiles, workers, duration)

			// Verify all hashes are present
			for i, result := range results {
				assert.Equal(t, files[i], result.Path)
				require.NoError(t, result.Error)
				assert.NotEmpty(t, result.Digests[AlgorithmSHA256])
			}
		})
	}
}

// Helper functions

func createTestFile(t *testing.T, content string) string {
	t.Helper()

	tmpFile, err := os.CreateTemp(t.TempDir(), "hash-test-*")
	require.NoError(t, err)

	_, err = tmpFile.WriteString(content)
	require.NoError(t, err)

	err = tmpFile.Close()
	require.NoError(t, err)

	return tmpFile.Name()
}

func createLargeTestFile(t *testing.T, size int) string {
	t.Helper()

	tmpFile, err := os.CreateTemp(t.TempDir(), "hash-test-large-*")
	require.NoError(t, err)

	// Write in chunks
	chunk := make([]byte, 64*1024)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}

	written := 0
	for written < size {
		toWrite := min(size-written, len(chunk))
		_, writeErr := tmpFile.Write(chunk[:toWrite])
		require.NoError(t, writeErr)
		written += toWrite
	}

	err = tmpFile.Close()
	require.NoError(t, err)

	return tmpFile.Name()
}

// Benchmark tests

func BenchmarkHashFile(b *testing.B) {
	sizes := []struct {
		bytes int
		name  string
	}{
		{1024, "1KB"},
		{64 * 1024, "64KB"},
		{1024 * 1024, "1MB"},
		{10 * 1024 * 1024, "10MB"},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			tmpFile, err := os.CreateTemp(b.TempDir(), "bench-*")
			require.NoError(b, err)
			defer func() { _ = os.Remove(tmpFile.Name()) }()

			data := make([]byte, size.bytes)
			_, _ = tmpFile.Write(data)
			_ = tmpFile.Close()

			hasher := New(Config{
				Algorithms: []string{AlgorithmSHA256},
			})

			b.ResetTimer()
			b.ReportAllocs()

			for range b.N {
				_, err := hasher.HashFile(context.Background(), tmpFile.Name())
				require.NoError(b, err)
			}
		})
	}
}

func BenchmarkHashFilesParallel(b *testing.B) {
	// Create test files
	numFiles := 100
	files := make([]string, numFiles)
	for i := range numFiles {
		tmpFile, _ := os.CreateTemp(b.TempDir(), "bench-*")
		_, _ = tmpFile.WriteString("test data")
		_ = tmpFile.Close()
		files[i] = tmpFile.Name()
	}
	defer func() {
		for _, f := range files {
			_ = os.Remove(f)
		}
	}()

	hasher := New(Config{
		Algorithms: []string{AlgorithmSHA256},
		Workers:    4,
	})

	b.ReportAllocs()

	for b.Loop() {
		_, err := hasher.HashFiles(context.Background(), files)
		require.NoError(b, err)
	}
}
