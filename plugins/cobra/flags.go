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

// Package cobra provides Cobra CLI framework integration helpers.
package cobra

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// FlagType represents the type of flag supported by the registry.
type FlagType int

const (
	StringFlag FlagType = iota
	BoolFlag
	IntFlag
	DurationFlag
	StringSliceFlag
	StringArrayFlag
)

// String returns the string representation of FlagType.
func (ft FlagType) String() string {
	switch ft {
	case StringFlag:
		return "string"
	case BoolFlag:
		return "bool"
	case IntFlag:
		return "int"
	case DurationFlag:
		return "duration"
	case StringSliceFlag:
		return "[]string"
	case StringArrayFlag:
		return "[]string"
	default:
		return fmt.Sprintf("unknown(%d)", int(ft))
	}
}

// FlagConstraints defines cross-flag validation constraints.
type FlagConstraints struct {
	// MutuallyExclusive specifies flag names that cannot be used together with this flag
	MutuallyExclusive []string

	// Required indicates if this flag is required
	Required bool

	// Requires specifies flag names that must be set if this flag is set
	Requires []string

	// RequiredWhen specifies flag names that, when set, require this flag to be set
	RequiredWhen []string

	// ValidValues restricts the allowed values for string flags
	ValidValues []string

	// MinValue specifies minimum value for int flags
	MinValue *int

	// MaxValue specifies maximum value for int flags
	MaxValue *int

	// RequiresTLS indicates this flag contains a URL that requires TLS (HTTPS)
	RequiresTLS bool
}

// FlagDefinition defines a complete flag specification.
type FlagDefinition struct {
	// Name is the flag name used with --
	Name string

	// ShortName is the single-character flag used with -
	ShortName string

	// ConfigPath is the configuration path this flag maps to
	ConfigPath string

	// Type specifies the flag type
	Type FlagType

	// Default is the default value for the flag
	Default any

	// Help is the help text displayed for this flag
	Help string

	// Hidden indicates if this flag should be hidden from help
	Hidden bool

	// Deprecated message if this flag is deprecated
	Deprecated string

	// Persistent indicates if this flag should be persistent
	Persistent bool

	// EnvironmentVariable specifies custom environment variable name (without STAMP_ prefix)
	EnvironmentVariable string `json:",omitempty"`

	// Constraints defines optional cross-flag validation constraints
	Constraints *FlagConstraints
}

// Validate validates the flag definition.
//
//nolint:gocognit // Flag validation requires checking many interdependent field constraints
func (fd *FlagDefinition) Validate() error {
	if fd.Name == "" {
		return ErrEmptyFlagName
	}

	if fd.ConfigPath == "" {
		return fmt.Errorf("%w for flag %s", ErrEmptyConfigPath, fd.Name)
	}

	if fd.Help == "" {
		return fmt.Errorf("%w for flag %s", ErrEmptyHelp, fd.Name)
	}

	switch fd.Type {
	case StringFlag:
		if fd.Default != nil {
			if _, ok := fd.Default.(string); !ok {
				return fmt.Errorf("%w: flag %s expects string, got %T", ErrInvalidDefaultType, fd.Name, fd.Default)
			}
		}
	case BoolFlag:
		if fd.Default != nil {
			if _, ok := fd.Default.(bool); !ok {
				return fmt.Errorf("%w: flag %s expects bool, got %T", ErrInvalidDefaultType, fd.Name, fd.Default)
			}
		}
	case IntFlag:
		if fd.Default != nil {
			if _, ok := fd.Default.(int); !ok {
				return fmt.Errorf("%w: flag %s expects int, got %T", ErrInvalidDefaultType, fd.Name, fd.Default)
			}
		}
	case DurationFlag:
		if fd.Default != nil {
			if _, ok := fd.Default.(time.Duration); !ok {
				return fmt.Errorf("%w: flag %s expects time.Duration, got %T", ErrInvalidDefaultType, fd.Name, fd.Default)
			}
		}
	case StringSliceFlag:
		if fd.Default != nil {
			if _, ok := fd.Default.([]string); !ok {
				return fmt.Errorf("%w: flag %s expects []string, got %T", ErrInvalidDefaultType, fd.Name, fd.Default)
			}
		}
	case StringArrayFlag:
		if fd.Default != nil {
			if _, ok := fd.Default.([]string); !ok {
				return fmt.Errorf("%w: flag %s expects []string, got %T", ErrInvalidDefaultType, fd.Name, fd.Default)
			}
		}
	default:
		return fmt.Errorf("%w: %s for flag %s", ErrUnsupportedFlagType, fd.Type, fd.Name)
	}

	return nil
}

// FlagGroup represents a collection of related flags.
type FlagGroup map[string]FlagDefinition

// Validate validates all flag definitions in the group.
func (fg FlagGroup) Validate() error {
	for name, def := range fg {
		if name != def.Name {
			return fmt.Errorf("%w: key %s, flag name %s", ErrFlagNameMismatch, name, def.Name)
		}

		if err := def.Validate(); err != nil {
			return fmt.Errorf("%w: flag %s: %w", ErrFlagValidation, name, err)
		}
	}
	return nil
}

// ApplyFlagGroups applies multiple flag groups to a command.
func ApplyFlagGroups(cmd *cobra.Command, groups []FlagGroup) error {
	for i, group := range groups {
		if err := ApplyFlagGroup(cmd, group); err != nil {
			return fmt.Errorf("failed to apply flag group %d: %w", i, err)
		}
	}
	return nil
}

// ApplyFlagGroup applies all flags from a flag group to a command.
func ApplyFlagGroup(cmd *cobra.Command, group FlagGroup) error {
	for _, def := range group {
		if err := ApplyFlag(cmd, def); err != nil {
			return fmt.Errorf("failed to apply flag %s: %w", def.Name, err)
		}
	}
	return nil
}

// ApplyFlag applies a single flag definition to a command.
func ApplyFlag(cmd *cobra.Command, def FlagDefinition) error {
	if err := def.Validate(); err != nil {
		return fmt.Errorf("invalid flag definition: %w", err)
	}

	flags := cmd.Flags()
	if def.Persistent {
		flags = cmd.PersistentFlags()
	}

	if err := addFlag(flags, def); err != nil {
		return err
	}

	return applyFlagMetadata(cmd, def)
}

func addFlag(flags *pflag.FlagSet, def FlagDefinition) error {
	switch def.Type {
	case StringFlag:
		return addStringFlag(flags, def)
	case BoolFlag:
		return addBoolFlag(flags, def)
	case IntFlag:
		return addIntFlag(flags, def)
	case DurationFlag:
		return addDurationFlag(flags, def)
	case StringSliceFlag:
		return addStringSliceFlag(flags, def)
	case StringArrayFlag:
		return addStringArrayFlag(flags, def)
	default:
		return fmt.Errorf("unsupported flag type: %s", def.Type)
	}
}

func addStringFlag(flags *pflag.FlagSet, def FlagDefinition) error {
	defaultVal := ""
	if def.Default != nil {
		val, ok := def.Default.(string)
		if !ok {
			return fmt.Errorf("flag %q: expected string default value, got %T", def.Name, def.Default)
		}
		defaultVal = val
	}
	if def.ShortName != "" {
		flags.StringP(def.Name, def.ShortName, defaultVal, def.Help)
	} else {
		flags.String(def.Name, defaultVal, def.Help)
	}
	return nil
}

func addBoolFlag(flags *pflag.FlagSet, def FlagDefinition) error {
	defaultVal := false
	if def.Default != nil {
		val, ok := def.Default.(bool)
		if !ok {
			return fmt.Errorf("flag %q: expected bool default value, got %T", def.Name, def.Default)
		}
		defaultVal = val
	}
	if def.ShortName != "" {
		flags.BoolP(def.Name, def.ShortName, defaultVal, def.Help)
	} else {
		flags.Bool(def.Name, defaultVal, def.Help)
	}
	return nil
}

func addIntFlag(flags *pflag.FlagSet, def FlagDefinition) error {
	defaultVal := 0
	if def.Default != nil {
		val, ok := def.Default.(int)
		if !ok {
			return fmt.Errorf("flag %q: expected int default value, got %T", def.Name, def.Default)
		}
		defaultVal = val
	}
	if def.ShortName != "" {
		flags.IntP(def.Name, def.ShortName, defaultVal, def.Help)
	} else {
		flags.Int(def.Name, defaultVal, def.Help)
	}
	return nil
}

func addDurationFlag(flags *pflag.FlagSet, def FlagDefinition) error {
	defaultVal := time.Duration(0)
	if def.Default != nil {
		val, ok := def.Default.(time.Duration)
		if !ok {
			return fmt.Errorf("flag %q: expected time.Duration default value, got %T", def.Name, def.Default)
		}
		defaultVal = val
	}
	if def.ShortName != "" {
		flags.DurationP(def.Name, def.ShortName, defaultVal, def.Help)
	} else {
		flags.Duration(def.Name, defaultVal, def.Help)
	}
	return nil
}

func addStringSliceFlag(flags *pflag.FlagSet, def FlagDefinition) error {
	var defaultVal []string
	if def.Default != nil {
		val, ok := def.Default.([]string)
		if !ok {
			return fmt.Errorf("flag %q: expected []string default value, got %T", def.Name, def.Default)
		}
		defaultVal = val
	}
	if def.ShortName != "" {
		flags.StringSliceP(def.Name, def.ShortName, defaultVal, def.Help)
	} else {
		flags.StringSlice(def.Name, defaultVal, def.Help)
	}
	return nil
}

func addStringArrayFlag(flags *pflag.FlagSet, def FlagDefinition) error {
	var defaultVal []string
	if def.Default != nil {
		val, ok := def.Default.([]string)
		if !ok {
			return fmt.Errorf("flag %q: expected []string default value, got %T", def.Name, def.Default)
		}
		defaultVal = val
	}
	if def.ShortName != "" {
		flags.StringArrayP(def.Name, def.ShortName, defaultVal, def.Help)
	} else {
		flags.StringArray(def.Name, defaultVal, def.Help)
	}
	return nil
}

func applyFlagMetadata(cmd *cobra.Command, def FlagDefinition) error {
	if def.ConfigPath != "" && def.ConfigPath != NoConfig {
		flags := cmd.Flags()
		if def.Persistent {
			flags = cmd.PersistentFlags()
		}

		flag := flags.Lookup(def.Name)
		if flag == nil {
			return fmt.Errorf("flag %q not found after creation", def.Name)
		}

		if flag.Annotations == nil {
			flag.Annotations = make(map[string][]string)
		}
		flag.Annotations[AnnotationConfigPath] = []string{def.ConfigPath}
		flag.Annotations[AnnotationEnvironmentVariable] = []string{getFullEnvironmentVariableName(def)}
	}

	if def.Hidden {
		if def.Persistent {
			_ = cmd.PersistentFlags().MarkHidden(def.Name)
		} else {
			_ = cmd.Flags().MarkHidden(def.Name)
		}
	}

	if def.Deprecated != "" {
		if def.Persistent {
			_ = cmd.PersistentFlags().MarkDeprecated(def.Name, def.Deprecated)
		} else {
			_ = cmd.Flags().MarkDeprecated(def.Name, def.Deprecated)
		}
	}

	return nil
}

func getFullEnvironmentVariableName(def FlagDefinition) string {
	var envVarSuffix string
	if def.EnvironmentVariable != "" {
		envVarSuffix = def.EnvironmentVariable
	} else {
		envVarSuffix = strings.ToUpper(strings.ReplaceAll(def.Name, "-", "_"))
	}
	return EnvironmentVariablePrefix + "_" + envVarSuffix
}
