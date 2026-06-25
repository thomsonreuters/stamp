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

// Package hash provides generic, high-performance cryptographic hashing utilities
// for any data source: files, byte slices, HTTP responses, streams, etc.

package hash

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"runtime"
	"slices"
	"sync"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/zeebo/blake3"
)

const (
	// DefaultBufferSize is the default buffer size for reading files (64KB).
	DefaultBufferSize = 64 * 1024

	// DefaultWorkers is 0, which means runtime.NumCPU() / 2 (minimum 1).
	DefaultWorkers = 0

	// DefaultWorkerDivisor is used to calculate the default number of workers.
	DefaultWorkerDivisor = 2

	// MinWorkers is the minimum number of workers to prevent deadlock.
	MinWorkers = 1
)

// Supported hash algorithms.
const (
	AlgorithmSHA256   = "sha256"
	AlgorithmSHA512   = "sha512"
	AlgorithmBLAKE3   = "blake3"
	AlgorithmSHA3_256 = "sha3-256"
	AlgorithmSHA3_512 = "sha3-512"
)

var (
	SupportedAlgorithms = []string{
		AlgorithmSHA256,
		AlgorithmSHA512,
		AlgorithmBLAKE3,
		AlgorithmSHA3_256,
		AlgorithmSHA3_512,
	}
)

// Config holds configuration for the hasher.
type Config struct {
	// Algorithms is the list of hash algorithms to use.
	Algorithms []string

	// Workers is the number of parallel workers for hashing.
	// 0 means runtime.NumCPU() / 2 (minimum 1).
	Workers int

	// BufferSize is the size of the buffer for reading files.
	BufferSize int
}

// Result holds the hashing result for a single file.
type Result struct {
	// Path is the file path that was hashed.
	Path string

	// Digests maps algorithm name to hex-encoded digest.
	Digests map[string]string

	// Size is the file size in bytes.
	Size int64

	// Error is any error that occurred during hashing.
	Error error
}

// Hasher provides high-performance cryptographic hashing capabilities.
type Hasher interface {
	// Hash computes hashes for data from an io.Reader using all configured algorithms.
	Hash(ctx context.Context, reader io.Reader, name string) (Result, error)

	// HashBytes computes hashes for in-memory byte data.
	HashBytes(ctx context.Context, data []byte, name string) (Result, error)

	// HashFile computes hashes for a single file.
	HashFile(ctx context.Context, filePath string) (Result, error)

	// HashFiles computes hashes for multiple files in parallel.
	HashFiles(ctx context.Context, files []string) ([]Result, error)
}

// hasher is the default implementation of the Hasher interface.
type hasher struct {
	config Config
	pool   *sync.Pool
}

// hashJob represents a file hashing job for the worker pool.
type hashJob struct {
	path  string
	index int // Original index for result ordering
}

// hashResult represents the result of a file hashing operation.
type hashResult struct {
	index  int
	result Result
}

// Hash computes hashes for data from an io.Reader using all configured algorithms.
// This is the most generic method that can hash any readable source (files, HTTP bodies, streams, etc.).
// The name parameter is used for identification in the result (e.g., filename, URL, or description).
func (h *hasher) Hash(ctx context.Context, reader io.Reader, name string) (Result, error) {
	result := Result{
		Path:    name,
		Digests: make(map[string]string),
	}

	if err := ctx.Err(); err != nil {
		result.Error = err
		return result, err
	}

	hashers := make(map[string]hash.Hash)
	for _, alg := range h.config.Algorithms {
		hasher, err := h.createHasher(alg)
		if err != nil {
			result.Error = err
			return result, err
		}
		hashers[alg] = hasher
	}

	writers := make([]io.Writer, 0, len(hashers))
	for _, hasher := range hashers {
		writers = append(writers, hasher)
	}
	multiWriter := io.MultiWriter(writers...)

	bufPtr, _ := h.pool.Get().(*[]byte)
	defer h.pool.Put(bufPtr)
	buffer := *bufPtr

	var totalRead int64
	for {
		select {
		case <-ctx.Done():
			result.Error = ctx.Err()
			return result, result.Error
		default:
			n, readErr := reader.Read(buffer)
			if n > 0 {
				totalRead += int64(n)

				if _, writeErr := multiWriter.Write(buffer[:n]); writeErr != nil {
					result.Error = pkgerrors.WrapWithContext(writeErr, "crypto.hash", "write",
						fmt.Sprintf("failed to write to hasher: %s", name))
					return result, result.Error
				}
			}
			if readErr == io.EOF {
				result.Size = totalRead
				for alg, hasher := range hashers {
					result.Digests[alg] = hex.EncodeToString(hasher.Sum(nil))
				}
				return result, nil
			}
			if readErr != nil {
				result.Error = pkgerrors.WrapWithContext(readErr, "crypto.hash", "read",
					fmt.Sprintf("failed to read data: %s", name))
				return result, result.Error
			}
		}
	}
}

// HashBytes computes hashes for in-memory byte data using all configured algorithms.
// This is a convenience wrapper around Hash for byte slices.
func (h *hasher) HashBytes(ctx context.Context, data []byte, name string) (Result, error) {
	return h.Hash(ctx, bytes.NewReader(data), name)
}

// HashFile computes hashes for a single file using all configured algorithms.
// This is a convenience wrapper around Hash for files on disk.
func (h *hasher) HashFile(ctx context.Context, filePath string) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{Path: filePath, Error: err}, err
	}

	file, err := os.Open(filePath)
	if err != nil {
		result := Result{
			Path:  filePath,
			Error: pkgerrors.WrapWithContext(err, "crypto.hash", "open", fmt.Sprintf("failed to open file: %s", filePath)),
		}
		return result, result.Error
	}
	defer func() { _ = file.Close() }()

	return h.Hash(ctx, file, filePath)
}

// HashFiles computes hashes for multiple files in parallel.
// Returns results in the same order as input files.
func (h *hasher) HashFiles(ctx context.Context, files []string) ([]Result, error) {
	if len(files) == 0 {
		return []Result{}, nil
	}

	jobs := make(chan hashJob, len(files))
	results := make(chan hashResult, len(files))

	var wg sync.WaitGroup
	wg.Add(h.config.Workers)
	for range h.config.Workers {
		go func() {
			defer wg.Done()
			h.worker(ctx, jobs, results)
		}()
	}

	go func() {
	jobLoop:
		for i, file := range files {
			select {
			case <-ctx.Done():
				break jobLoop
			case jobs <- hashJob{path: file, index: i}:
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	resultMap := make(map[int]Result)
	for result := range results {
		resultMap[result.index] = result.result
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	orderedResults := make([]Result, len(files))
	for i := range files {
		if result, ok := resultMap[i]; ok {
			orderedResults[i] = result
		} else {
			orderedResults[i] = Result{
				Path:  files[i],
				Error: ctx.Err(),
			}
		}
	}

	return orderedResults, nil
}

// worker processes hash jobs from the jobs channel.
func (h *hasher) worker(ctx context.Context, jobs <-chan hashJob, results chan<- hashResult) {
	for job := range jobs {
		if ctx.Err() != nil {
			results <- hashResult{
				index: job.index,
				result: Result{
					Path:  job.path,
					Error: ctx.Err(),
				},
			}
			continue
		}

		result, _ := h.HashFile(ctx, job.path)
		results <- hashResult{
			index:  job.index,
			result: result,
		}
	}
}

// createHasher creates a hash.Hash for the specified algorithm.
func (h *hasher) createHasher(algorithm string) (hash.Hash, error) {
	switch algorithm {
	case AlgorithmSHA256:
		return sha256.New(), nil
	case AlgorithmSHA512:
		return sha512.New(), nil
	case AlgorithmBLAKE3:
		return blake3.New(), nil
	case AlgorithmSHA3_256:
		return sha3.New256(), nil
	case AlgorithmSHA3_512:
		return sha3.New512(), nil
	default:
		return nil, pkgerrors.NewWithContext("crypto.hash", "unsupported_algorithm",
			fmt.Sprintf("unsupported hash algorithm: %s", algorithm))
	}
}

func newHasher(config Config) Hasher {
	if config.BufferSize == 0 {
		config.BufferSize = DefaultBufferSize
	}
	if config.Workers == 0 {
		// Ensure at least MinWorkers to prevent deadlock on single-CPU systems
		config.Workers = max(MinWorkers, runtime.NumCPU()/DefaultWorkerDivisor)
	}
	if len(config.Algorithms) == 0 {
		config.Algorithms = []string{AlgorithmSHA256}
	}

	pool := &sync.Pool{
		New: func() any {
			b := make([]byte, config.BufferSize)
			return &b
		},
	}

	return &hasher{
		config: config,
		pool:   pool,
	}
}

// New creates a new Hasher with the given configuration.
var New = newHasher

// ValidateAlgorithm checks if an algorithm is supported.
func ValidateAlgorithm(algorithm string) bool {
	return slices.Contains(SupportedAlgorithms, algorithm)
}
