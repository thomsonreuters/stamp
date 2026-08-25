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
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/thomsonreuters/stamp/pkg/destination"
)

// Config holds the configuration for the file destination.
type Config struct {
	// Path is the output file path template
	Path string

	// Permissions is the file permissions in octal format (e.g., "0644")
	Permissions string

	// CreateDirs automatically creates parent directories
	CreateDirs bool

	// Overwrite allows overwriting existing files
	Overwrite bool

	// Compression type: "none", "gzip", "zstd"
	Compression string

	// Pretty enables pretty-printed JSON output
	Pretty bool

	// AtomicWrites uses temporary files for atomic writes
	AtomicWrites bool

	// Format is the output format: "json", "yaml", "yaml-stream"
	Format string

	// Aggregate writes all attestations to a single file
	Aggregate bool

	// Metadata contains custom metadata for template expansion
	Metadata map[string]string
}

// DefaultConfig returns the default file destination configuration.
func DefaultConfig() *Config {
	return &Config{
		Path:         "./attestations/${attestor}/${id}.sigstore.json",
		Permissions:  "0644",
		CreateDirs:   true,
		Overwrite:    false,
		Compression:  "none",
		Pretty:       false,
		AtomicWrites: true,
		Format:       "json",
		Aggregate:    false,
		Metadata:     nil,
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.Path == "" {
		return errors.New("path is required")
	}

	// Validate permissions format
	if c.Permissions != "" {
		if _, err := c.GetFileMode(); err != nil {
			return fmt.Errorf("invalid permissions format: %w", err)
		}
	}

	// Validate compression
	switch c.Compression {
	case "", "none", "gzip", "zstd":
		// Valid
	default:
		return fmt.Errorf("invalid compression type: %s (valid: none, gzip, zstd)", c.Compression)
	}

	// Validate format
	switch c.Format {
	case "", "json", "yaml", "yaml-stream":
		// Valid
	default:
		return fmt.Errorf("invalid format: %s (valid: json, yaml, yaml-stream)", c.Format)
	}

	// Validate aggregate mode constraints
	if c.Aggregate {
		if err := destination.ValidateTemplateForWriteMode(c.Path, true); err != nil {
			return fmt.Errorf("aggregate mode: %w", err)
		}
	}

	return nil
}

// GetFileMode parses the permissions string and returns the file mode.
func (c *Config) GetFileMode() (os.FileMode, error) {
	if c.Permissions == "" {
		return 0644, nil
	}

	// Remove leading "0" if present for octal parsing
	permStr := c.Permissions
	if strings.HasPrefix(permStr, "0") && len(permStr) > 1 {
		permStr = permStr[1:]
	}

	perm, err := strconv.ParseUint(permStr, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid permission string %q: %w", c.Permissions, err)
	}

	return os.FileMode(perm), nil
}

// ResolvePath resolves template variables in the path.
func (c *Config) ResolvePath(attestation *destination.Attestation, workflowName string) string {
	path := destination.ResolveTemplate(c.Path, attestation, workflowName)
	path = destination.ExpandMetadata(path, c.Metadata)
	return path
}

// configFromMap converts a configuration map to a Config struct.
func configFromMap(configMap map[string]any) *Config {
	config := DefaultConfig()

	if path, ok := configMap["path"].(string); ok {
		config.Path = path
	}

	if permissions, ok := configMap["permissions"].(string); ok {
		config.Permissions = permissions
	}

	if createDirs, ok := configMap["create_dirs"].(bool); ok {
		config.CreateDirs = createDirs
	}

	if overwrite, ok := configMap["overwrite"].(bool); ok {
		config.Overwrite = overwrite
	}

	if compression, ok := configMap["compression"].(string); ok {
		config.Compression = compression
	}

	if pretty, ok := configMap["pretty"].(bool); ok {
		config.Pretty = pretty
	}

	if atomicWrites, ok := configMap["atomic_writes"].(bool); ok {
		config.AtomicWrites = atomicWrites
	}

	if format, ok := configMap["format"].(string); ok {
		config.Format = format
	}

	if aggregate, ok := configMap["aggregate"].(bool); ok {
		config.Aggregate = aggregate
	}

	config.Metadata = destination.ParseMetadataConfig(configMap)

	return config
}
