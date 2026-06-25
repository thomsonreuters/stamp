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

package githubworkflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/thomsonreuters/stamp/pkg/crypto/hash"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

var (
	ErrWorkflowRefEmpty          = errors.New("workflow ref is empty")
	ErrInvalidWorkflowRef        = errors.New("workflow ref is invalid")
	ErrInvalidWorkflowFilePath   = errors.New("workflow file path is invalid")
	ErrGitHubEventPathEmpty      = errors.New("github event path is empty")
	ErrGitHubEventFileNotFound   = errors.New("github event file not found")
	ErrInvalidGitHubEventPayload = errors.New("github event payload is not valid JSON")
	ErrBrokenJSONStructure       = errors.New("sanitization broke JSON structure")
)

// Tag name constants.
const (
	tagAttestor = "attestor" // Main struct tag name
	tagEnv      = "env"      // Environment variable name option
	tagRequired = "required" // Required field option
	tagDefault  = "default"  // Default value option
)

// parseAttestorTag parses the attestor tag string into a map of options.
// Supports formats like:
//   - Boolean flags: "required"
//   - Key-value pairs: "env:GITHUB_WORKFLOW", "default:1"
//   - Combined: "env:GITHUB_WORKFLOW;required;default:1"
func parseAttestorTag(tag string) map[string]string {
	if tag == "" {
		return nil
	}

	options := make(map[string]string, 3)

	// Process tag without splitting if single option
	if !strings.Contains(tag, ";") {
		if before, after, ok := strings.Cut(tag, ":"); ok {
			options[strings.TrimSpace(before)] = strings.TrimSpace(after)
		} else {
			options[strings.TrimSpace(tag)] = "true"
		}
		return options
	}

	// Split by semicolon for multiple options
	start := 0
	for i := 0; i <= len(tag); i++ {
		if i == len(tag) || tag[i] == ';' { //nolint:nestif // Tag parsing requires nested conditionals for proper tokenization
			if i > start {
				part := strings.TrimSpace(tag[start:i])
				if part != "" {
					if before, after, ok := strings.Cut(part, ":"); ok {
						options[strings.TrimSpace(before)] = strings.TrimSpace(after)
					} else {
						options[part] = "true"
					}
				}
			}
			start = i + 1
		}
	}

	return options
}

// readGitHubActionInfo reads environment variables using struct tags and populates GitHubActionInfo.
//
//nolint:gocognit // Complex reflection-based environment variable parsing requires conditional logic
func readGitHubActionInfo(ctx context.Context, logger logger.Logger) GitHubActionInfo {
	logger.DebugContext(ctx, "parsing GitHub Actions environment variables using reflection")

	info := GitHubActionInfo{}
	val := reflect.ValueOf(&info).Elem()
	typ := val.Type()
	numFields := val.NumField()

	for i := range numFields {
		field := val.Field(i)
		fieldType := typ.Field(i)
		attestorTag := fieldType.Tag.Get(tagAttestor)

		if attestorTag == "" {
			continue
		}

		// Parse attestor tag options
		options := parseAttestorTag(attestorTag)
		if options == nil {
			continue
		}

		// Get environment variable name
		envVar, hasEnv := options[tagEnv]
		if !hasEnv || envVar == "" {
			continue
		}

		// Read environment variable
		envValue := os.Getenv(envVar)

		// Set field value based on type (only string and int/int64 are supported)
		switch {
		case field.Kind() == reflect.String:
			field.SetString(envValue)
		case field.Kind() == reflect.Int || field.Kind() == reflect.Int64:
			if envValue == "" {
				// Use default value if provided
				if defaultValue, hasDefault := options[tagDefault]; hasDefault {
					if defaultInt, err := strconv.Atoi(defaultValue); err == nil {
						field.SetInt(int64(defaultInt))
					} else {
						logger.WarnContext(ctx, "invalid default value for int field",
							"field", fieldType.Name,
							"default", defaultValue,
							"error", err.Error())
					}
				}
				continue
			}

			// Parse integer
			if intValue, err := strconv.Atoi(envValue); err == nil {
				field.SetInt(int64(intValue))
			} else {
				logger.WarnContext(ctx, "failed to parse environment variable as integer",
					"env_var", envVar,
					"field", fieldType.Name,
					"value", envValue,
					"error", err.Error())

				// Use default value if provided
				if defaultValue, hasDefault := options[tagDefault]; hasDefault {
					if defaultInt, err := strconv.Atoi(defaultValue); err == nil {
						field.SetInt(int64(defaultInt))
						logger.DebugContext(ctx, "using default value",
							"field", fieldType.Name,
							"default", defaultInt)
					}
				}
			}
		default:
			logger.WarnContext(ctx, "unsupported field type for environment variable parsing",
				"field", fieldType.Name,
				"type", field.Kind().String())
		}
	}

	logger.DebugContext(ctx, "GitHub Actions environment variables parsed",
		"workflow_name", info.WorkflowName,
		"run_id", info.WorkflowRunID,
		"repository", info.GithubRepository)

	return info
}

// GitHubActionInfo consolidates all GitHub Actions environment variables being collected.
type GitHubActionInfo struct {
	// Workflow Information (from collectWorkflowInfo)
	WorkflowName       string `attestor:"env:GITHUB_WORKFLOW;required"`
	WorkflowRef        string `attestor:"env:GITHUB_WORKFLOW_REF"`
	WorkflowSHA        string `attestor:"env:GITHUB_WORKFLOW_SHA"`
	WorkflowRunID      string `attestor:"env:GITHUB_RUN_ID;required"`
	WorkflowRunNumber  int    `attestor:"env:GITHUB_RUN_NUMBER"`
	WorkflowRunAttempt int    `attestor:"env:GITHUB_RUN_ATTEMPT;default:1"`
	WorkflowJob        string `attestor:"env:GITHUB_JOB"`
	WorkflowAction     string `attestor:"env:GITHUB_ACTION"`
	WorkflowActionPath string `attestor:"env:GITHUB_ACTION_PATH"`

	// Runner Information (from collectRunnerInfo)
	RunnerName        string `attestor:"env:RUNNER_NAME"`
	RunnerOS          string `attestor:"env:RUNNER_OS"`
	RunnerArch        string `attestor:"env:RUNNER_ARCH"`
	RunnerTempDir     string `attestor:"env:RUNNER_TEMP"`
	RunnerToolCache   string `attestor:"env:RUNNER_TOOL_CACHE"`
	RunnerEnvironment string `attestor:"env:RUNNER_ENVIRONMENT"`

	// Trigger Information (from collectTriggerInfo)
	GithubEventName string `attestor:"env:GITHUB_EVENT_NAME"`
	GithubActor     string `attestor:"env:GITHUB_ACTOR"`
	GithubActorID   string `attestor:"env:GITHUB_ACTOR_ID"`
	GithubHeadRef   string `attestor:"env:GITHUB_HEAD_REF"`
	GithubBaseRef   string `attestor:"env:GITHUB_BASE_REF"`
	GithubEventPath string `attestor:"env:GITHUB_EVENT_PATH"`

	// Repository Information (from collectRepositoryInfo)
	GithubRepository        string `attestor:"env:GITHUB_REPOSITORY;required"`
	GithubRepositoryOwner   string `attestor:"env:GITHUB_REPOSITORY_OWNER"`
	GithubRepositoryOwnerID string `attestor:"env:GITHUB_REPOSITORY_OWNER_ID"`
	GithubRepositoryID      string `attestor:"env:GITHUB_REPOSITORY_ID"`
	GithubSHA               string `attestor:"env:GITHUB_SHA;required"`
	GithubRef               string `attestor:"env:GITHUB_REF"`
	GithubRefName           string `attestor:"env:GITHUB_REF_NAME"`
	GithubRefType           string `attestor:"env:GITHUB_REF_TYPE"`

	// Metadata Information (from collectMetadataInfo)
	GithubServerURL string `attestor:"env:GITHUB_SERVER_URL"`

	// Workspace Information (from getWorkflowFileDigest)
	GithubWorkspace string `attestor:"env:GITHUB_WORKSPACE"`

	// Computed fields
	WorkflowFilePath       string
	WorkflowFileSHA        map[string]string
	GithubEventPayload     json.RawMessage
	GithubEventPayloadSize int64
}

// Validate checks if all required fields are present in the GitHubActionInfo struct.
// It uses reflection to read the `attestor` tag and validates fields marked as `required`.
// Returns an error if any required field is empty.
func (info *GitHubActionInfo) Validate() error {
	val := reflect.ValueOf(info).Elem()
	typ := val.Type()
	numFields := val.NumField()

	missingFields := make([]string, 0, 4)

	for i := range numFields {
		fieldType := typ.Field(i)
		attestorTag := fieldType.Tag.Get(tagAttestor)

		// Skip fields without attestor tag or without "required"
		if attestorTag == "" || !strings.Contains(attestorTag, tagRequired) {
			continue
		}

		field := val.Field(i)

		// Only validate string fields (int fields with 0 are valid)
		if field.Kind() != reflect.String {
			continue
		}

		// Check if string field is empty
		if field.String() == "" {
			// Parse tag to get env var name
			options := parseAttestorTag(attestorTag)
			if options != nil && options[tagRequired] == "true" {
				envVar, hasEnv := options[tagEnv]
				if !hasEnv {
					envVar = "unknown"
				}
				missingFields = append(missingFields, fmt.Sprintf("%s (%s)", fieldType.Name, envVar))
			}
		}
	}

	if len(missingFields) > 0 {
		return pkgerrors.NewWithContext(
			"github-workflow",
			"validate",
			fmt.Sprintf("missing required environment variables: %s", strings.Join(missingFields, ", ")),
		)
	}

	return nil
}

func (info *GitHubActionInfo) parseWorkflowFile(_ context.Context) error {
	const (
		workflowRefSeparator = "@"
		repoPathSeparator    = "/"
		workflowRefParts     = 2
		minPathParts         = 3
	)
	workflowRef := info.WorkflowRef
	if workflowRef == "" {
		return ErrWorkflowRefEmpty
	}

	parts := strings.Split(workflowRef, workflowRefSeparator)
	if len(parts) != workflowRefParts {
		return ErrInvalidWorkflowRef
	}

	pathParts := strings.SplitN(parts[0], repoPathSeparator, minPathParts)
	if len(pathParts) < minPathParts {
		return ErrInvalidWorkflowFilePath
	}

	info.WorkflowFilePath = pathParts[2]
	return nil
}

func (info *GitHubActionInfo) GetWorkflowFileDigest(ctx context.Context) (map[string]string, error) {
	if err := info.parseWorkflowFile(ctx); err != nil {
		return nil, err
	}

	hasher := hash.New(hash.Config{})

	filePath := filepath.Join(info.GithubWorkspace, info.WorkflowFilePath)

	result, err := hasher.HashFile(ctx, filePath)
	if err != nil {
		return nil, err
	}

	return result.Digests, nil
}

func (info *GitHubActionInfo) CaptureEnvironmentVariables(
	ctx context.Context,
	logger logger.Logger,
	includePatterns []string,
	excludePatterns []string,
) map[string]string {
	env := make(map[string]string)
	securityExclusionCount := 0

	matcher := func(patterns []string, key string) (bool, string) {
		for _, pattern := range patterns {
			matched, err := filepath.Match(pattern, key)
			if err != nil {
				logger.Warn("invalid exclude pattern", "pattern", pattern, "error", err.Error())
				continue
			}
			if matched {
				return true, pattern
			}
		}
		return false, ""
	}

	// Read all environment variables as map[string]string
	envVariables := utils.ReadAllEnvVariables()
	for key, value := range envVariables {
		// Check all exclusions (built-in + user-provided) first - deny list takes precedence
		if matched, pattern := matcher(builtinSecurityExclusions, key); matched {
			securityExclusionCount++
			logger.Debug("security exclusion applied", "variable", key, "pattern", pattern)
			continue
		}
		if matched, pattern := matcher(excludePatterns, key); matched {
			logger.Debug("exclude pattern applied", "variable", key, "pattern", pattern)
			continue
		}
		if matched, pattern := matcher(includePatterns, key); matched {
			logger.Debug("include pattern applied", "variable", key, "pattern", pattern)
			env[key] = value
			continue
		}
	}

	if securityExclusionCount > 0 {
		logger.Info("security exclusions applied to environment variables",
			"excluded_count", securityExclusionCount)
	}

	return env
}

func (info *GitHubActionInfo) ReadEventPayload(ctx context.Context, redact bool, redactPatterns []string) (json.RawMessage, int64, error) {
	var (
		payload json.RawMessage
		err     error
	)

	// Built-in redaction patterns
	patterns := []utils.RedactionPattern{
		{
			Pattern: regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
			Replace: "[REDACTED_EMAIL]",
		},
		{
			Pattern: regexp.MustCompile(`gh[pousr]_[a-zA-Z0-9]{36}`),
			Replace: "[REDACTED_TOKEN]",
		},
		{
			Pattern: regexp.MustCompile(`(?i)bearer\s+[^\s"]+`),
			Replace: "bearer [REDACTED]",
		},
		{
			Pattern: regexp.MustCompile(`(https?://[^:]+):([^@]+)@`),
			Replace: "$1:[REDACTED]@",
		},
	}

	// Apply custom patterns from config
	for _, p := range redactPatterns {
		re, compileErr := regexp.Compile(p)
		if compileErr != nil {
			continue
		}
		patterns = append(patterns, utils.RedactionPattern{
			Pattern: re,
			Replace: "[REDACTED]",
		})
	}

	if info.GithubEventPath == "" {
		return nil, 0, ErrGitHubEventPathEmpty
	}

	stat, err := os.Stat(info.GithubEventPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrGitHubEventFileNotFound
		}
		return nil, 0, err
	}

	payload, err = os.ReadFile(info.GithubEventPath)
	if err != nil {
		return nil, 0, err
	}

	if redact {
		result, err := utils.SanitizeJSON(payload, patterns)
		if err != nil {
			return nil, 0, err
		}
		payload = result.Sanitized
	}

	return payload, stat.Size(), nil
}
