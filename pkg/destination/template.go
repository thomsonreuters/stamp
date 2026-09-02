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

package destination

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Template variable names supported in path templates.
const (
	// VarID is the attestation UUID.
	VarID = "id"

	// VarAttestor is the attestor identifier.
	VarAttestor = "attestor"

	// VarDate is the current date (YYYY-MM-DD).
	VarDate = "date"

	// VarTimestamp is the Unix timestamp.
	VarTimestamp = "timestamp"

	// VarYear is the current year (YYYY).
	VarYear = "year"

	// VarMonth is the current month (01-12).
	VarMonth = "month"

	// VarDay is the current day (01-31).
	VarDay = "day"

	// VarSHA256 is the content hash.
	VarSHA256 = "sha256"

	// VarWorkflow is the workflow name (when running in workflow mode).
	VarWorkflow = "workflow"

	// VarPredicateType is the full predicate type URL.
	VarPredicateType = "predicate_type"

	// VarShortPredicateType is the short predicate type name.
	VarShortPredicateType = "short_predicate_type"
)

// PerAttestationVars are template variables that are specific to individual attestations
// and cannot be used in aggregate mode (where multiple attestations are written to a single file).
var PerAttestationVars = []string{
	VarID,
	VarSHA256,
	VarAttestor,
	VarPredicateType,
	VarShortPredicateType,
}

// envVarRegex matches environment variable patterns like ${ENV_VAR} or ${ENV_VAR:default}.
var envVarRegex = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::([^}]*))?\}`)

// templateVarRegex matches template variables like ${var} or {{.var}}.
var templateVarRegex = regexp.MustCompile(`\$\{([a-z_]+)\}|{{\s*\.([a-z_]+)\s*}}`)

// ResolveTemplate resolves template variables in the given template string.
// It supports both ${var} and {{.var}} syntax for compatibility.
//
// Available variables:
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
//
// It returns an error if a placeholder cannot be resolved: a {{.var}} placeholder
// must match a known template variable, and a ${var} placeholder that isn't a known
// template variable falls back to resolving as an environment variable (optionally
// with a ${var:default} default) and errors only if neither resolves.
func ResolveTemplate(template string, attestation *Attestation, workflowName string) (string, error) {
	if template == "" {
		return template, nil
	}

	now := time.Now()
	result := template

	// Build variable map
	vars := buildVariableMap(attestation, workflowName, now)

	// Replace template variables (both ${var} and {{.var}} syntax)
	var unresolvedErr error
	result = templateVarRegex.ReplaceAllStringFunc(result, func(match string) string {
		// Extract variable name from either syntax
		var varName string
		isDotSyntax := false
		if after, found := strings.CutPrefix(match, "${"); found {
			varName = strings.TrimSuffix(after, "}")
		} else {
			// {{.var}} syntax
			isDotSyntax = true
			varName = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(match, "{{."), "}}"))
		}

		if val, ok := vars[varName]; ok {
			return val
		}

		if isDotSyntax {
			// {{.var}} has no environment-variable fallback, so an unknown name is
			// unresolvable outright.
			if unresolvedErr == nil {
				unresolvedErr = fmt.Errorf("unresolved template variable %q", match)
			}
			return match
		}

		return match // ${var}; may still resolve as an environment variable below
	})

	if unresolvedErr != nil {
		return "", unresolvedErr
	}

	// Resolve environment variables
	result, err := resolveEnvVarsOrError(result)
	if err != nil {
		return "", err
	}

	return result, nil
}

// buildVariableMap creates a map of all available template variables.
func buildVariableMap(attestation *Attestation, workflowName string, now time.Time) map[string]string {
	vars := map[string]string{
		VarDate:      now.Format("2006-01-02"),
		VarTimestamp: strconv.FormatInt(now.Unix(), 10),
		VarYear:      now.Format("2006"),
		VarMonth:     now.Format("01"),
		VarDay:       now.Format("02"),
	}

	if workflowName != "" {
		vars[VarWorkflow] = workflowName
	}

	addAttestationVars(vars, attestation, workflowName)

	return vars
}

// addAttestationVars adds attestation-specific variables to the map.
func addAttestationVars(vars map[string]string, attestation *Attestation, workflowName string) {
	if attestation == nil {
		return
	}

	if attestation.ID != "" {
		vars[VarID] = attestation.ID
	}
	if attestation.AttestorID != "" {
		vars[VarAttestor] = attestation.AttestorID
	}
	if attestation.SHA256 != "" {
		vars[VarSHA256] = attestation.SHA256
	}
	if attestation.PredicateType != "" {
		vars[VarPredicateType] = sanitizeForPath(attestation.PredicateType)
		vars[VarShortPredicateType] = extractShortPredicateType(attestation.PredicateType)
	}
	// Use attestation's workflow name if set and workflowName param is empty
	if workflowName == "" && attestation.WorkflowName != "" {
		vars[VarWorkflow] = attestation.WorkflowName
	}
}

// resolveEnvVars resolves environment variables in the string.
// Supports ${ENV_VAR} and ${ENV_VAR:default} syntax.
func resolveEnvVars(s string) string {
	return envVarRegex.ReplaceAllStringFunc(s, func(match string) string {
		submatch := envVarRegex.FindStringSubmatch(match)
		if len(submatch) < 2 {
			return match
		}

		envName := submatch[1]
		defaultVal := ""
		if len(submatch) >= 3 {
			defaultVal = submatch[2]
		}

		if val := os.Getenv(envName); val != "" {
			return val
		}
		return defaultVal
	})
}

// resolveEnvVarsOrError resolves environment variables in the string, like resolveEnvVars,
// but returns an error for a ${var} placeholder whose environment variable is unset (or empty)
// and which has no default value, instead of silently resolving it to an empty string.
func resolveEnvVarsOrError(s string) (string, error) {
	var unresolvedErr error
	result := envVarRegex.ReplaceAllStringFunc(s, func(match string) string {
		submatch := envVarRegex.FindStringSubmatch(match)
		if len(submatch) < 2 {
			return match
		}

		envName := submatch[1]
		hasDefault := strings.Contains(match, ":")
		defaultVal := ""
		if len(submatch) >= 3 {
			defaultVal = submatch[2]
		}

		if val := os.Getenv(envName); val != "" {
			return val
		}
		if hasDefault {
			return defaultVal
		}

		if unresolvedErr == nil {
			unresolvedErr = fmt.Errorf(
				"unresolved template variable %q: environment variable %q is not set and no default was provided",
				match,
				envName,
			)
		}
		return match
	})

	if unresolvedErr != nil {
		return "", unresolvedErr
	}
	return result, nil
}

// sanitizeForPath replaces characters that are invalid in file paths.
func sanitizeForPath(s string) string {
	// Replace URL-unsafe characters with underscores
	replacer := strings.NewReplacer(
		"://", "_",
		"/", "_",
		":", "_",
		"?", "_",
		"&", "_",
		"=", "_",
		"#", "_",
		" ", "_",
	)
	return replacer.Replace(s)
}

// extractShortPredicateType extracts the short name from a predicate type URL.
// For example: "https://slsa.dev/provenance/v1" becomes "provenance_v1".
func extractShortPredicateType(predicateType string) string {
	// Remove common URL prefixes
	s := predicateType
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")

	// Take the last path segments
	parts := strings.Split(s, "/")
	if len(parts) >= 2 {
		// Take last two parts (e.g., "provenance/v1")
		s = strings.Join(parts[len(parts)-2:], "_")
	} else if len(parts) == 1 {
		s = parts[0]
	}

	return sanitizeForPath(s)
}

// ValidateTemplateForWriteMode validates that a template is compatible with the write mode.
// In aggregate mode, per-attestation variables (${id}, ${sha256}, ${attestor}, ${predicate_type})
// cannot be used since multiple attestations are written to a single file.
func ValidateTemplateForWriteMode(template string, isAggregate bool) error {
	if !isAggregate {
		return nil // All variables are valid in non-aggregate mode
	}

	for _, varName := range PerAttestationVars {
		if ContainsTemplateVar(template, varName) {
			return fmt.Errorf("template variable '${%s}' cannot be used in aggregate mode", varName)
		}
	}

	return nil
}

// ValidateTemplateForExecutionContext validates that a template is compatible with the execution context.
// The ${workflow} variable requires workflow context to be set.
func ValidateTemplateForExecutionContext(template string, hasWorkflowContext bool) error {
	if !hasWorkflowContext && ContainsTemplateVar(template, VarWorkflow) {
		return fmt.Errorf("template variable '${%s}' requires workflow context (use 'stamp run --workflow')", VarWorkflow)
	}
	return nil
}

// ContainsTemplateVar checks if a template contains a specific variable.
// Supports both ${var} and {{.var}} syntax.
func ContainsTemplateVar(template, varName string) bool {
	return strings.Contains(template, "${"+varName+"}") ||
		strings.Contains(template, "{{."+varName+"}}") ||
		strings.Contains(template, "{{. "+varName+"}}") ||
		strings.Contains(template, "{{ ."+varName+"}}")
}

// ExpandMetadata expands ${metadata.*} variables in a string using the provided metadata map.
func ExpandMetadata(s string, metadata map[string]string) string {
	if len(metadata) == 0 {
		return s
	}

	result := s
	for key, value := range metadata {
		placeholder := "${metadata." + key + "}"
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}

// ParseMetadataConfig extracts and processes metadata from a configuration map.
// It resolves environment variables in metadata values.
func ParseMetadataConfig(config map[string]any) map[string]string {
	metadataRaw, ok := config["metadata"]
	if !ok {
		return nil
	}

	metadataMap, ok := metadataRaw.(map[string]any)
	if !ok {
		return nil
	}

	result := make(map[string]string)
	for key, val := range metadataMap {
		if strVal, ok := val.(string); ok {
			// Resolve environment variables in metadata values
			result[key] = resolveEnvVars(strVal)
		}
	}

	return result
}

// ListTemplateVariables returns all available template variable names.
func ListTemplateVariables() []string {
	return []string{
		VarID,
		VarAttestor,
		VarDate,
		VarTimestamp,
		VarYear,
		VarMonth,
		VarDay,
		VarSHA256,
		VarWorkflow,
		VarPredicateType,
		VarShortPredicateType,
	}
}
