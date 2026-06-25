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

package validation

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	plugincobra "github.com/thomsonreuters/stamp/plugins/cobra"
)

// ValidateAllConstraints validates flag constraints for the given flag groups.
// It aggregates errors from multiple flag groups into a single validation error.
func ValidateAllConstraints(cfg config.ConfigurationIface, flagGroups ...plugincobra.FlagGroup) error {
	validator := pkgerrors.NewValidator()

	for _, group := range flagGroups {
		if err := ValidateConstraints(cfg, group); err != nil {
			validationErr := &pkgerrors.ValidationError{}
			if errors.As(err, &validationErr) {
				for field, fieldErrors := range validationErr.Fields {
					for _, fieldError := range fieldErrors {
						validator.AddError(field, fieldError)
					}
				}
			} else {
				validator.AddError("constraints", err.Error())
			}
		}
	}

	if validator.HasErrors() {
		_ = validator.Suggest(
			"Check flag values against their constraints",
			"Use --help to see valid options for each flag",
			"Verify integer values are within specified ranges")
		return validator
	}

	return nil
}

// ValidateCommandConstraints validates flag constraints for flag groups that are
// applicable to the given command. A flag group is considered applicable if any
// of its flags are registered on the command (directly or inherited from parents).
// This allows passing all flag groups safely — only groups relevant to the current
// subcommand are validated, preventing false positives from unrelated Required constraints.
func ValidateCommandConstraints(cmd *cobra.Command, cfg config.ConfigurationIface) error {
	var applicable []plugincobra.FlagGroup
	for _, group := range flags.AllGroups() {
		if isGroupApplicable(cmd, group) {
			applicable = append(applicable, group)
		}
	}
	return ValidateAllConstraints(cfg, applicable...)
}

// isGroupApplicable checks whether any flag from the group is registered on the
// command (locally or inherited from parent commands).
func isGroupApplicable(cmd *cobra.Command, group plugincobra.FlagGroup) bool {
	for name := range group {
		if cmd.Flag(name) != nil {
			return true
		}
	}
	return false
}

// ValidateConstraints validates flag constraints within a flag group.
//
//nolint:gocognit // Constraint validation requires checking multiple interdependent conditions
func ValidateConstraints(cfg config.ConfigurationIface, flagGroup plugincobra.FlagGroup) error {
	validator := pkgerrors.NewValidator()

	for flagName, def := range flagGroup {
		if def.Constraints == nil {
			continue
		}

		// Check required constraint first (before checking if set)
		if def.Constraints.Required && !cfg.IsSet(def.ConfigPath) {
			validator.AddError(flagName, "is required but not set")
			continue // Skip other validations for this unset required flag
		}

		// Skip remaining validations if flag is not set (but wasn't required)
		if !cfg.IsSet(def.ConfigPath) {
			continue
		}

		// Check mutual exclusion
		if len(def.Constraints.MutuallyExclusive) > 0 {
			exclusivePaths := resolveFlagNames(def.Constraints.MutuallyExclusive, flagGroup)
			if err := checkMutualExclusion(cfg, exclusivePaths, flagName, flagGroup); err != nil {
				validator.AddError("flags", err.Error())
			}
		}

		// Check required dependencies
		if len(def.Constraints.Requires) > 0 {
			requiredPaths := resolveFlagNames(def.Constraints.Requires, flagGroup)
			if err := checkRequires(cfg, requiredPaths, flagName, flagGroup); err != nil {
				validator.AddError(flagName, err.Error())
			}
		}

		// Check RequiredWhen constraint (this flag becomes required when specified flags are set)
		if len(def.Constraints.RequiredWhen) > 0 {
			triggerPaths := resolveFlagNames(def.Constraints.RequiredWhen, flagGroup)
			if err := checkRequiredWhen(cfg, triggerPaths, flagName, def.ConfigPath, flagGroup); err != nil {
				validator.AddError(flagName, err.Error())
			}
		}

		// Check ValidValues constraint
		if len(def.Constraints.ValidValues) > 0 && def.Type == plugincobra.StringFlag {
			value := cfg.GetString(def.ConfigPath)
			if value != "" {
				found := slices.Contains(def.Constraints.ValidValues, value)
				if !found {
					validator.AddError(flagName, fmt.Sprintf("invalid value '%s' (valid options: %v)", value, def.Constraints.ValidValues))
				}
			}
		}

		// Check MinValue constraint for int flags
		if def.Constraints.MinValue != nil && def.Type == plugincobra.IntFlag {
			value := cfg.GetInt(def.ConfigPath)
			if value < *def.Constraints.MinValue {
				validator.AddError(flagName, fmt.Sprintf("value %d is below minimum %d", value, *def.Constraints.MinValue))
			}
		}

		// Check MaxValue constraint for int flags
		if def.Constraints.MaxValue != nil && def.Type == plugincobra.IntFlag {
			value := cfg.GetInt(def.ConfigPath)
			if value > *def.Constraints.MaxValue {
				validator.AddError(flagName, fmt.Sprintf("value %d is above maximum %d", value, *def.Constraints.MaxValue))
			}
		}

		// Check RequiresTLS constraint - HTTP URLs require --insecure flag
		if def.Constraints.RequiresTLS && def.Type == plugincobra.StringFlag {
			url := cfg.GetString(def.ConfigPath)
			if url != "" && strings.HasPrefix(url, "http://") && !cfg.GetBool(flags.Insecure) {
				validator.AddError(flagName, fmt.Sprintf("HTTP URL '%s' requires --insecure flag", url))
				_ = validator.Suggest(
					"Add --insecure flag to allow HTTP connections (development/testing only)",
					"Or use HTTPS URL for production")
			}
		}
	}

	if validator.HasErrors() {
		_ = validator.Suggest("Check flag combinations, requirements, and value constraints")
		return validator
	}

	return nil
}

// resolveFlagNames converts flag names to config paths within the current flag group.
func resolveFlagNames(flagNames []string, flagGroup plugincobra.FlagGroup) []string {
	paths := make([]string, 0, len(flagNames))
	for _, name := range flagNames {
		if def, exists := flagGroup[name]; exists {
			paths = append(paths, def.ConfigPath)
		}
	}
	return paths
}

// checkMutualExclusion validates that only one flag in a group is set.
func checkMutualExclusion(cfg config.ConfigurationIface, exclusivePaths []string, flagName string, flagGroup plugincobra.FlagGroup) error {
	setFlags := []string{flagName} // Current flag is already set

	for _, path := range exclusivePaths {
		if cfg.IsSet(path) {
			// Find flag name for this path (for error message)
			flagNameForPath := findFlagNameForPath(path, flagGroup)
			if flagNameForPath != "" {
				setFlags = append(setFlags, flagNameForPath)
			}
		}
	}

	if len(setFlags) > 1 {
		return fmt.Errorf("flags %s are mutually exclusive", strings.Join(setFlags, ", "))
	}

	return nil
}

// checkRequires validates that dependent flags are set.
func checkRequires(cfg config.ConfigurationIface, requiredPaths []string, flagName string, flagGroup plugincobra.FlagGroup) error {
	missing := []string{}

	for _, path := range requiredPaths {
		if !cfg.IsSet(path) {
			flagNameForPath := findFlagNameForPath(path, flagGroup)
			if flagNameForPath != "" {
				missing = append(missing, flagNameForPath)
			}
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("%s requires %s to be set", flagName, strings.Join(missing, ", "))
	}

	return nil
}

// checkRequiredWhen validates that this flag is set when specified trigger flags are set.
func checkRequiredWhen(
	cfg config.ConfigurationIface,
	triggerPaths []string,
	flagName, flagConfigPath string,
	flagGroup plugincobra.FlagGroup,
) error {
	// Check if any trigger flags are set
	triggeredBy := []string{}
	for _, path := range triggerPaths {
		if cfg.IsSet(path) {
			flagNameForPath := findFlagNameForPath(path, flagGroup)
			if flagNameForPath != "" {
				triggeredBy = append(triggeredBy, flagNameForPath)
			}
		}
	}

	// If trigger flags are set, this flag must be set
	if len(triggeredBy) > 0 && !cfg.IsSet(flagConfigPath) {
		return fmt.Errorf("--%s is required when %s is set", flagName, strings.Join(triggeredBy, ", "))
	}

	return nil
}

// findFlagNameForPath finds the flag name that corresponds to a config path.
func findFlagNameForPath(configPath string, flagGroup plugincobra.FlagGroup) string {
	for flagName, def := range flagGroup {
		if def.ConfigPath == configPath {
			return flagName
		}
	}
	return ""
}
