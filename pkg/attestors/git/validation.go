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
	"fmt"
	"os"
	"slices"

	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	gitpredicate "github.com/thomsonreuters/stamp/pkg/predicates/git/v1"
)

// ValidateConfig validates the attestor configuration against the schema and
// performs additional custom validation including working directory existence,
// dirty-behavior values, and hash algorithm validity.
func (a *Attestor) ValidateConfig(config core.Config) error {
	a.logger.Debug("validating Git attestor configuration")

	a.parseConfig(config)

	if err := config.Validate(a.ConfigSchema()); err != nil {
		a.logger.Error("configuration schema validation failed", "error", err.Error())
		return err
	}

	// Validate working directory exists
	if a.config.WorkingDir != "" && a.config.WorkingDir != "." {
		if _, err := os.Stat(a.config.WorkingDir); err != nil {
			return pkgerrors.WrapWithContext(err, id, "validate", fmt.Sprintf("working directory %s does not exist", a.config.WorkingDir))
		}
	}

	// Validate dirty-behavior value
	if a.config.DirtyBehavior != "" && !slices.Contains(validDirtyBehaviors, a.config.DirtyBehavior) {
		err := fmt.Errorf("invalid dirty-behavior '%s': must be one of %v", a.config.DirtyBehavior, validDirtyBehaviors)
		return pkgerrors.WrapWithContext(err, id, "validate", "invalid dirty-behavior configuration")
	}

	// Validate hash-algorithms
	if len(a.config.HashAlgorithms) > 0 {
		for _, alg := range a.config.HashAlgorithms {
			if !slices.Contains(validHashAlgorithms, alg) {
				err := fmt.Errorf("invalid hash algorithm '%s': must be one of %v", alg, validHashAlgorithms)
				return pkgerrors.WrapWithContext(err, id, "validate", "invalid hash algorithm")
			}
		}
	}

	return nil
}

// redactSensitiveFields removes or masks sensitive information from the Git predicate
// based on configuration. Supports fine-grained field-level redaction for PII
// and other sensitive data.
func (a *Attestor) redactSensitiveFields(predicate gitpredicate.Predicate, fields []string) gitpredicate.Predicate {
	for _, fieldStr := range fields {
		switch fieldStr {
		case "author.name", "commit.author.name":
			predicate.Commit.Author.Name = "[REDACTED]"
		case "author.email", "commit.author.email":
			predicate.Commit.Author.Email = "[REDACTED]"
		case "committer.name", "commit.committer.name":
			predicate.Commit.Committer.Name = "[REDACTED]"
		case "committer.email", "commit.committer.email":
			predicate.Commit.Committer.Email = "[REDACTED]"
		case "commit.message", "message":
			predicate.Commit.Message = "[REDACTED]"
		case "commit.signature", "signature":
			predicate.Commit.Signature = "[REDACTED]"
		case "commit.hash", "hash":
			predicate.Commit.Hash = "[REDACTED]"
		case "commit.treehash", "treehash":
			predicate.Commit.TreeHash = "[REDACTED]"
		case "repository", "repository.url", "repoURL":
			predicate.Repository.URL = "[REDACTED]"
		case "ref", "branch", "repository.branch":
			predicate.Repository.Branch = "[REDACTED]"
		case "remotes":
			predicate.Remotes = nil
		case "refs":
			predicate.Refs = nil
		case "tags":
			predicate.Tags = nil
		case "submodules":
			predicate.Submodules = nil
		case "gitBinary", "git-binary":
			predicate.GitBinary = nil
		}
	}

	return predicate
}
