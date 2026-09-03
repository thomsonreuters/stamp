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

// Package file provides a filesystem destination for writing attestations to local files.
//
// The file destination supports path resolution with optional template variables, automatic
// directory creation, file compression, and atomic writes for reliability. It implements
// the destination.Destination interface and registers itself automatically.
//
// Features:
//   - Path-based file generation with optional variable substitution
//   - Automatic directory creation with configurable permissions
//   - Optional compression (gzip, zstd)
//   - Atomic writes using temporary files
//   - Overwrite policy control
//   - Multiple output formats: JSON, YAML, YAML-stream
//   - Aggregate mode for writing multiple attestations to a single file
//   - Health checks for filesystem accessibility
//
// Path template variables available:
//   - ${id}: Attestation UUID
//   - ${attestor}: Attestor identifier (empty for collections)
//   - ${date}: Current date (YYYY-MM-DD)
//   - ${timestamp}: Unix timestamp
//   - ${year}: Current year (YYYY)
//   - ${month}: Current month (01-12)
//   - ${day}: Current day (01-31)
//   - ${sha256}: Content hash
//   - ${workflow}: Workflow name (when running in workflow mode)
//   - ${predicate_type}: Full predicate type URL
//   - ${short_predicate_type}: Short predicate type name
//   - Environment variables: ${ENV_VAR} or ${ENV_VAR:default}
package file

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/thomsonreuters/stamp/pkg/destination"
	"gopkg.in/yaml.v3"
)

// Compile-time interface check.
var _ destination.Destination = (*Destination)(nil)

// Destination implements the file destination for writing attestations to the filesystem.
type Destination struct {
	config *Config
	mu     sync.RWMutex
}

func init() {
	destination.Register("file", func() destination.Destination {
		return New()
	})
}

// New creates a new file destination.
func New() *Destination {
	return &Destination{
		config: DefaultConfig(),
	}
}

// Type returns the destination type identifier.
func (d *Destination) Type() string {
	return "file"
}

// Name returns the human-readable name.
func (d *Destination) Name() string {
	return "File System"
}

// Description returns a description of the destination.
func (d *Destination) Description() string {
	return "Write attestations to local filesystem with template-based naming"
}

// ValidateConfig validates the destination configuration.
func (d *Destination) ValidateConfig(config map[string]any) error {
	cfg := configFromMap(config)

	if err := cfg.Validate(); err != nil {
		return destination.ErrConfigurationInvalid("validation", err)
	}

	return nil
}

// Configure applies the configuration to the destination.
func (d *Destination) Configure(config map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	cfg := configFromMap(config)

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	d.config = cfg
	return nil
}

// GetConfigSchema returns the configuration schema.
func (d *Destination) GetConfigSchema() []destination.ConfigField {
	return []destination.ConfigField{
		{
			Name:        "path",
			Type:        "string",
			Required:    true,
			Default:     "./attestations/${attestor}/${id}.json",
			Description: "Output file path for attestations, can contain template variables: ${id}, ${attestor}, ${workflow}, ${date}, ${timestamp}, ${sha256}, ${predicate_type}, ${short_predicate_type}. In aggregate mode, cannot use per-attestation variables (${id}, ${sha256}, ${attestor}, ${predicate_type}).",
			Examples: []string{
				"./attestations/${attestor}/${id}.json",
				"./output/${workflow}-${date}.json",
				"./collections/${workflow}/${date}-collection-${id}.json",
			},
		},
		{
			Name:        "permissions",
			Type:        "string",
			Required:    false,
			Default:     "0644",
			Description: "File permissions in octal format",
			Examples:    []string{"0644", "0600", "0755"},
		},
		{
			Name:        "create_dirs",
			Type:        "bool",
			Required:    false,
			Default:     true,
			Description: "Automatically create parent directories",
		},
		{
			Name:        "overwrite",
			Type:        "bool",
			Required:    false,
			Default:     false,
			Description: "Overwrite existing files",
		},
		{
			Name:        "compression",
			Type:        "string",
			Required:    false,
			Default:     "none",
			Description: "Compression type: none, gzip, zstd",
			Examples:    []string{"none", "gzip", "zstd"},
		},
		{
			Name:        "pretty",
			Type:        "bool",
			Required:    false,
			Default:     false,
			Description: "Pretty print JSON output",
		},
		{
			Name:        "atomic_writes",
			Type:        "bool",
			Required:    false,
			Default:     true,
			Description: "Use atomic writes via temporary files",
		},
		{
			Name:        "format",
			Type:        "string",
			Required:    false,
			Default:     "json",
			Description: "Output format: json, yaml, yaml-stream",
			Examples:    []string{"json", "yaml", "yaml-stream"},
		},
		{
			Name:        "aggregate",
			Type:        "bool",
			Required:    false,
			Default:     false,
			Description: "Write all attestations to a single file. Path cannot use per-attestation variables (${id}, ${sha256}, ${attestor}, ${predicate_type}).",
		},
	}
}

// Write writes a single attestation to the filesystem.
func (d *Destination) Write(ctx context.Context, attestation *destination.Attestation) (*destination.WriteResult, error) {
	return d.writeInternal(ctx, attestation, "")
}

// writeInternal is the internal write implementation that accepts a workflow name.
func (d *Destination) writeInternal(
	ctx context.Context,
	attestation *destination.Attestation,
	workflowName string,
) (*destination.WriteResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, destination.NewDestinationError("file", "context_cancelled", err, false)
	}

	d.mu.RLock()
	config := d.config
	d.mu.RUnlock()

	start := time.Now()

	outputPath, err := config.ResolvePath(attestation, workflowName)
	if err != nil {
		return nil, destination.NewDestinationError("file", "resolve_path", err, false)
	}

	if config.CreateDirs {
		parentDir := filepath.Dir(outputPath)
		if err = os.MkdirAll(parentDir, 0755); err != nil {
			return nil, destination.NewDestinationError("file", "create_directory",
				fmt.Errorf("failed to create directory %s: %w", parentDir, err), false)
		}
	}

	if !config.Overwrite {
		if _, err = os.Stat(outputPath); err == nil {
			return nil, destination.NewDestinationError("file", "overwrite_check",
				fmt.Errorf("file exists and overwrite is disabled: %s", outputPath), false)
		}
	}

	var data []byte

	if config.Pretty {
		data, err = json.MarshalIndent(attestation.Envelope, "", "  ")
	} else {
		data, err = json.Marshal(attestation.Envelope)
	}

	if err != nil {
		return nil, destination.NewDestinationError("file", "serialize_attestation",
			fmt.Errorf("failed to marshal attestation envelope: %w", err), false)
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, destination.NewDestinationError("file", "context_cancelled", ctxErr, false)
	}

	actualSize, err := d.writeFile(ctx, outputPath, data, config)
	if err != nil {
		return nil, destination.NewDestinationError("file", "write_file",
			fmt.Errorf("failed to write file %s: %w", outputPath, err), true)
	}

	return &destination.WriteResult{
		Location:  outputPath,
		ID:        filepath.Base(outputPath),
		Timestamp: time.Now(),
		Size:      int64(actualSize),
		Metadata: map[string]string{
			"compression": config.Compression,
			"atomic":      strconv.FormatBool(config.AtomicWrites),
			"duration_ms": strconv.FormatInt(time.Since(start).Milliseconds(), 10),
		},
	}, nil
}

// WriteBatch writes multiple attestations to the filesystem.
func (d *Destination) WriteBatch(
	ctx context.Context,
	attestations []*destination.Attestation,
	opts destination.WriteOptions,
) ([]*destination.WriteResult, error) {
	if len(attestations) == 0 {
		return nil, nil
	}

	d.mu.RLock()
	config := d.config
	d.mu.RUnlock()

	// Handle aggregate mode
	if config.Aggregate {
		return d.writeBatchAggregate(ctx, attestations, config, opts)
	}

	// Individual file writes with workflow name from opts
	results := make([]*destination.WriteResult, 0, len(attestations))

	for _, attestation := range attestations {
		result, err := d.writeInternal(ctx, attestation, opts.WorkflowName)
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}

	return results, nil
}

// writeBatchAggregate writes all attestations to a single file in aggregate mode.
func (d *Destination) writeBatchAggregate(
	ctx context.Context,
	attestations []*destination.Attestation,
	config *Config,
	opts destination.WriteOptions,
) ([]*destination.WriteResult, error) {
	start := time.Now()

	outputPath, err := config.ResolvePath(attestations[0], opts.WorkflowName)
	if err != nil {
		return nil, destination.NewDestinationError("file", "resolve_path", err, false)
	}

	envelopes := make([]any, len(attestations))
	for i, att := range attestations {
		envelopes[i] = att.Envelope
	}

	var data []byte

	switch config.Format {
	case "json", "":
		if config.Pretty {
			data, err = json.MarshalIndent(envelopes, "", "  ")
		} else {
			data, err = json.Marshal(envelopes)
		}

	case "yaml":
		// Single YAML document (array of envelopes)
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if encodeErr := enc.Encode(envelopes); encodeErr != nil {
			_ = enc.Close()
			return nil, destination.NewDestinationError("file", "serialize_yaml",
				fmt.Errorf("failed to encode YAML: %w", encodeErr), false)
		}
		_ = enc.Close()
		data = buf.Bytes()

	case "yaml-stream":
		// Multiple YAML documents with separators
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)

		for _, env := range envelopes {
			if encodeErr := enc.Encode(env); encodeErr != nil {
				_ = enc.Close()
				return nil, destination.NewDestinationError("file", "serialize_yaml",
					fmt.Errorf("failed to encode YAML stream: %w", encodeErr), false)
			}
		}
		_ = enc.Close()
		data = buf.Bytes()

	default:
		return nil, destination.NewDestinationError("file", "unsupported_format",
			fmt.Errorf("unsupported format: %s", config.Format), false)
	}

	if err != nil {
		return nil, destination.NewDestinationError("file", "serialize_attestations",
			fmt.Errorf("failed to serialize attestations: %w", err), false)
	}

	if config.CreateDirs {
		parentDir := filepath.Dir(outputPath)
		if mkdirErr := os.MkdirAll(parentDir, 0755); mkdirErr != nil {
			return nil, destination.NewDestinationError("file", "create_directory",
				fmt.Errorf("failed to create directory %s: %w", parentDir, mkdirErr), false)
		}
	}

	if !config.Overwrite {
		if _, statErr := os.Stat(outputPath); statErr == nil {
			return nil, destination.NewDestinationError("file", "overwrite_check",
				fmt.Errorf("file exists and overwrite is disabled: %s", outputPath), false)
		}
	}

	actualSize, err := d.writeFile(ctx, outputPath, data, config)
	if err != nil {
		return nil, destination.NewDestinationError("file", "write_file",
			fmt.Errorf("failed to write file %s: %w", outputPath, err), true)
	}

	result := &destination.WriteResult{
		Location:  outputPath,
		ID:        filepath.Base(outputPath),
		Timestamp: time.Now(),
		Size:      int64(actualSize),
		Metadata: map[string]string{
			"format":      config.Format,
			"aggregate":   "true",
			"count":       strconv.Itoa(len(attestations)),
			"compression": config.Compression,
			"duration_ms": strconv.FormatInt(time.Since(start).Milliseconds(), 10),
		},
	}

	return []*destination.WriteResult{result}, nil
}

// writeFile writes data to a file with compression and atomic write support.
func (d *Destination) writeFile(ctx context.Context, outputPath string, data []byte, config *Config) (int, error) {
	fileMode, err := config.GetFileMode()
	if err != nil {
		return 0, fmt.Errorf("invalid file permissions: %w", err)
	}

	var finalPath string
	var tempPath string

	if config.AtomicWrites {
		tempPath = outputPath + ".tmp"
		finalPath = outputPath
	} else {
		finalPath = outputPath
	}

	writeTarget := finalPath
	if config.AtomicWrites {
		writeTarget = tempPath
	}

	file, err := os.OpenFile(writeTarget, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fileMode)
	if err != nil {
		return 0, fmt.Errorf("failed to create file: %w", err)
	}

	// Ensure cleanup on error
	var writeErr error
	defer func() {
		_ = file.Close() // Best effort close in cleanup
		if config.AtomicWrites && tempPath != "" && writeErr != nil {
			_ = os.Remove(tempPath) // Best effort cleanup of temp file
		}
	}()

	var writer io.Writer = file
	var compressor io.WriteCloser

	switch config.Compression {
	case "gzip":
		compressor = gzip.NewWriter(file)
		writer = compressor
	case "zstd":
		encoder, zstdErr := zstd.NewWriter(file)
		if zstdErr != nil {
			writeErr = fmt.Errorf("failed to create zstd encoder: %w", zstdErr)
			return 0, writeErr
		}
		compressor = encoder
		writer = encoder
	case "none", "":
		// No compression
	default:
		writeErr = fmt.Errorf("unsupported compression type: %s", config.Compression)
		return 0, writeErr
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		writeErr = ctxErr
		return 0, writeErr
	}

	bytesWritten, err := writer.Write(data)
	if err != nil {
		writeErr = fmt.Errorf("failed to write data: %w", err)
		return 0, writeErr
	}

	if compressor != nil {
		if err := compressor.Close(); err != nil {
			writeErr = fmt.Errorf("failed to close compressor: %w", err)
			return 0, writeErr
		}
	}

	if err := file.Sync(); err != nil {
		writeErr = fmt.Errorf("failed to sync file: %w", err)
		return 0, writeErr
	}

	if err := file.Close(); err != nil {
		writeErr = fmt.Errorf("failed to close file: %w", err)
		return 0, writeErr
	}

	if config.AtomicWrites {
		if err := os.Rename(tempPath, finalPath); err != nil {
			writeErr = fmt.Errorf("failed to move temporary file: %w", err)
			return 0, writeErr
		}
	}

	return bytesWritten, nil
}

// HealthCheck verifies the destination is accessible and properly configured.
func (d *Destination) HealthCheck(ctx context.Context) error {
	d.mu.RLock()
	config := d.config
	d.mu.RUnlock()

	testAttestation := &destination.Attestation{
		ID:            "health-check-test",
		PredicateType: "https://github.com/thomsonreuters/stamp/predicates/health-check-test/v1",
	}
	testPath, err := config.ResolvePath(testAttestation, "")
	if err != nil {
		return destination.NewDestinationError("file", "health_check",
			fmt.Errorf("failed to resolve health check path: %w", err), false)
	}
	targetDir := filepath.Dir(testPath)

	if config.CreateDirs {
		if err = os.MkdirAll(targetDir, 0755); err != nil {
			return destination.NewDestinationError("file", "health_check",
				fmt.Errorf("cannot create target directory %s: %w", targetDir, err), false)
		}
	} else {
		if _, err = os.Stat(targetDir); os.IsNotExist(err) {
			return destination.NewDestinationError("file", "health_check",
				fmt.Errorf("target directory %s does not exist and create_dirs is disabled", targetDir), false)
		}
	}

	testData := []byte(`{"health":"check","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`)

	file, err := os.CreateTemp(targetDir, ".stamp-health-check-*.json")
	if err != nil {
		return destination.NewDestinationError("file", "health_check",
			fmt.Errorf("cannot write to target directory %s: %w", targetDir, err), false)
	}

	tempFile := file.Name()
	defer func() {
		_ = file.Close()
		_ = os.Remove(tempFile)
	}()

	if _, writeErr := file.Write(testData); writeErr != nil {
		return destination.NewDestinationError("file", "health_check",
			fmt.Errorf("cannot write to target directory %s: %w", targetDir, writeErr), false)
	}

	if syncErr := file.Sync(); syncErr != nil {
		return destination.NewDestinationError("file", "health_check",
			fmt.Errorf("cannot sync file in target directory %s: %w", targetDir, syncErr), false)
	}

	if closeErr := file.Close(); closeErr != nil {
		return destination.NewDestinationError("file", "health_check",
			fmt.Errorf("cannot close test file in target directory %s: %w", targetDir, closeErr), false)
	}

	readData, err := os.ReadFile(tempFile)
	if err != nil {
		return destination.NewDestinationError("file", "health_check",
			fmt.Errorf("cannot read from target directory %s: %w", targetDir, err), false)
	}

	if string(readData) != string(testData) {
		return destination.NewDestinationError("file", "health_check",
			fmt.Errorf("data integrity check failed in directory %s", targetDir), false)
	}

	return nil
}

// Close closes the destination and releases resources.
func (d *Destination) Close(_ context.Context) error {
	// File destination doesn't hold persistent resources
	return nil
}

// SupportsAggregate indicates file destination supports aggregate mode.
func (d *Destination) SupportsAggregate() bool {
	return true
}
