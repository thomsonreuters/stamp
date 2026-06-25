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

package cobra

import (
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAddStringFlag_TypeSafety tests type safety for string flags.
func TestAddStringFlag_TypeSafety(t *testing.T) {
	tests := []struct {
		name        string
		def         FlagDefinition
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid string default",
			def: FlagDefinition{
				Name:       "test-string",
				Type:       StringFlag,
				Default:    "default-value",
				Help:       "Test string flag",
				ConfigPath: "test.string",
			},
			expectError: false,
		},
		{
			name: "nil default (valid)",
			def: FlagDefinition{
				Name:       "test-string-nil",
				Type:       StringFlag,
				Default:    nil,
				Help:       "Test string flag with nil default",
				ConfigPath: "test.string.nil",
			},
			expectError: false,
		},
		{
			name: "invalid type - int instead of string",
			def: FlagDefinition{
				Name:       "test-string-invalid",
				Type:       StringFlag,
				Default:    123, // Wrong type!
				Help:       "Test string flag with invalid default",
				ConfigPath: "test.string.invalid",
			},
			expectError: true,
			errorMsg:    "expected string default value, got int",
		},
		{
			name: "invalid type - bool instead of string",
			def: FlagDefinition{
				Name:       "test-string-bool",
				Type:       StringFlag,
				Default:    true, // Wrong type!
				Help:       "Test string flag with bool default",
				ConfigPath: "test.string.bool",
			},
			expectError: true,
			errorMsg:    "expected string default value, got bool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			err := addStringFlag(flags, tt.def)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
				flag := flags.Lookup(tt.def.Name)
				require.NotNil(t, flag)
			}
		})
	}
}

// TestAddBoolFlag_TypeSafety tests type safety for bool flags.
func TestAddBoolFlag_TypeSafety(t *testing.T) {
	tests := []struct {
		name        string
		def         FlagDefinition
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid bool default",
			def: FlagDefinition{
				Name:       "test-bool",
				Type:       BoolFlag,
				Default:    true,
				Help:       "Test bool flag",
				ConfigPath: "test.bool",
			},
			expectError: false,
		},
		{
			name: "nil default (valid)",
			def: FlagDefinition{
				Name:       "test-bool-nil",
				Type:       BoolFlag,
				Default:    nil,
				Help:       "Test bool flag with nil default",
				ConfigPath: "test.bool.nil",
			},
			expectError: false,
		},
		{
			name: "invalid type - string instead of bool",
			def: FlagDefinition{
				Name:       "test-bool-invalid",
				Type:       BoolFlag,
				Default:    "true", // Wrong type!
				Help:       "Test bool flag with invalid default",
				ConfigPath: "test.bool.invalid",
			},
			expectError: true,
			errorMsg:    "expected bool default value, got string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			err := addBoolFlag(flags, tt.def)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
				flag := flags.Lookup(tt.def.Name)
				require.NotNil(t, flag)
			}
		})
	}
}

// TestAddIntFlag_TypeSafety tests type safety for int flags.
func TestAddIntFlag_TypeSafety(t *testing.T) {
	tests := []struct {
		name        string
		def         FlagDefinition
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid int default",
			def: FlagDefinition{
				Name:       "test-int",
				Type:       IntFlag,
				Default:    42,
				Help:       "Test int flag",
				ConfigPath: "test.int",
			},
			expectError: false,
		},
		{
			name: "nil default (valid)",
			def: FlagDefinition{
				Name:       "test-int-nil",
				Type:       IntFlag,
				Default:    nil,
				Help:       "Test int flag with nil default",
				ConfigPath: "test.int.nil",
			},
			expectError: false,
		},
		{
			name: "invalid type - string instead of int",
			def: FlagDefinition{
				Name:       "test-int-invalid",
				Type:       IntFlag,
				Default:    "42", // Wrong type!
				Help:       "Test int flag with invalid default",
				ConfigPath: "test.int.invalid",
			},
			expectError: true,
			errorMsg:    "expected int default value, got string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			err := addIntFlag(flags, tt.def)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
				flag := flags.Lookup(tt.def.Name)
				require.NotNil(t, flag)
			}
		})
	}
}

// TestAddDurationFlag_TypeSafety tests type safety for duration flags.
func TestAddDurationFlag_TypeSafety(t *testing.T) {
	tests := []struct {
		name        string
		def         FlagDefinition
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid duration default",
			def: FlagDefinition{
				Name:       "test-duration",
				Type:       DurationFlag,
				Default:    5 * time.Second,
				Help:       "Test duration flag",
				ConfigPath: "test.duration",
			},
			expectError: false,
		},
		{
			name: "nil default (valid)",
			def: FlagDefinition{
				Name:       "test-duration-nil",
				Type:       DurationFlag,
				Default:    nil,
				Help:       "Test duration flag with nil default",
				ConfigPath: "test.duration.nil",
			},
			expectError: false,
		},
		{
			name: "invalid type - string instead of duration",
			def: FlagDefinition{
				Name:       "test-duration-invalid",
				Type:       DurationFlag,
				Default:    "5s", // Wrong type!
				Help:       "Test duration flag with invalid default",
				ConfigPath: "test.duration.invalid",
			},
			expectError: true,
			errorMsg:    "expected time.Duration default value, got string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			err := addDurationFlag(flags, tt.def)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
				flag := flags.Lookup(tt.def.Name)
				require.NotNil(t, flag)
			}
		})
	}
}

// TestAddStringSliceFlag_TypeSafety tests type safety for string slice flags.
func TestAddStringSliceFlag_TypeSafety(t *testing.T) {
	tests := []struct {
		name        string
		def         FlagDefinition
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid string slice default",
			def: FlagDefinition{
				Name:       "test-slice",
				Type:       StringSliceFlag,
				Default:    []string{"a", "b", "c"},
				Help:       "Test string slice flag",
				ConfigPath: "test.slice",
			},
			expectError: false,
		},
		{
			name: "nil default (valid)",
			def: FlagDefinition{
				Name:       "test-slice-nil",
				Type:       StringSliceFlag,
				Default:    nil,
				Help:       "Test string slice flag with nil default",
				ConfigPath: "test.slice.nil",
			},
			expectError: false,
		},
		{
			name: "invalid type - string instead of slice",
			def: FlagDefinition{
				Name:       "test-slice-invalid",
				Type:       StringSliceFlag,
				Default:    "a,b,c", // Wrong type!
				Help:       "Test string slice flag with invalid default",
				ConfigPath: "test.slice.invalid",
			},
			expectError: true,
			errorMsg:    "expected []string default value, got string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			err := addStringSliceFlag(flags, tt.def)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
				flag := flags.Lookup(tt.def.Name)
				require.NotNil(t, flag)
			}
		})
	}
}

// TestAddStringArrayFlag_TypeSafety tests type safety for string array flags.
func TestAddStringArrayFlag_TypeSafety(t *testing.T) {
	tests := []struct {
		name        string
		def         FlagDefinition
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid string array default",
			def: FlagDefinition{
				Name:       "test-array",
				Type:       StringArrayFlag,
				Default:    []string{"x", "y", "z"},
				Help:       "Test string array flag",
				ConfigPath: "test.array",
			},
			expectError: false,
		},
		{
			name: "nil default (valid)",
			def: FlagDefinition{
				Name:       "test-array-nil",
				Type:       StringArrayFlag,
				Default:    nil,
				Help:       "Test string array flag with nil default",
				ConfigPath: "test.array.nil",
			},
			expectError: false,
		},
		{
			name: "invalid type - int slice instead of string slice",
			def: FlagDefinition{
				Name:       "test-array-invalid",
				Type:       StringArrayFlag,
				Default:    []int{1, 2, 3}, // Wrong type!
				Help:       "Test string array flag with invalid default",
				ConfigPath: "test.array.invalid",
			},
			expectError: true,
			errorMsg:    "expected []string default value, got []int",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			err := addStringArrayFlag(flags, tt.def)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
				flag := flags.Lookup(tt.def.Name)
				require.NotNil(t, flag)
			}
		})
	}
}

// TestApplyFlag_TypeSafetyIntegration tests the full flag application flow.
func TestApplyFlag_TypeSafetyIntegration(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
	}

	// Valid flag definition
	validDef := FlagDefinition{
		Name:       "valid-flag",
		Type:       StringFlag,
		Default:    "default",
		Help:       "A valid flag",
		ConfigPath: "test.valid",
	}

	err := ApplyFlag(cmd, validDef)
	require.NoError(t, err)

	// Invalid flag definition (wrong type)
	invalidDef := FlagDefinition{
		Name:       "invalid-flag",
		Type:       StringFlag,
		Default:    123, // Wrong type!
		Help:       "An invalid flag",
		ConfigPath: "test.invalid",
	}

	err = ApplyFlag(cmd, invalidDef)
	require.Error(t, err)
	// Error caught by FlagDefinition.Validate() first (defense in depth)
	assert.Contains(t, err.Error(), "default value type mismatch")
	assert.Contains(t, err.Error(), "expects string, got int")
}

// TestApplyFlagGroup_TypeSafetyPropagation tests error propagation in flag groups.
func TestApplyFlagGroup_TypeSafetyPropagation(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
	}

	// Flag group with one invalid flag
	flagGroup := FlagGroup{
		"valid": {
			Name:       "valid",
			Type:       StringFlag,
			Default:    "ok",
			Help:       "Valid flag",
			ConfigPath: "test.valid",
		},
		"invalid": {
			Name:       "invalid",
			Type:       BoolFlag,
			Default:    "not-a-bool", // Wrong type!
			Help:       "Invalid flag",
			ConfigPath: "test.invalid",
		},
	}

	err := ApplyFlagGroup(cmd, flagGroup)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply flag")
	// Error caught by FlagDefinition.Validate() first (defense in depth)
	assert.Contains(t, err.Error(), "default value type mismatch")
	assert.Contains(t, err.Error(), "expects bool, got string")
}

// TestApplyFlagGroups_MultipleGroupsTypeSafety tests multiple flag groups.
func TestApplyFlagGroups_MultipleGroupsTypeSafety(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
	}

	group1 := FlagGroup{
		"flag1": {
			Name:       "flag1",
			Type:       StringFlag,
			Default:    "value1",
			Help:       "Flag 1",
			ConfigPath: "test.flag1",
		},
	}

	group2 := FlagGroup{
		"flag2": {
			Name:       "flag2",
			Type:       IntFlag,
			Default:    "not-an-int", // Wrong type!
			Help:       "Flag 2",
			ConfigPath: "test.flag2",
		},
	}

	err := ApplyFlagGroups(cmd, []FlagGroup{group1, group2})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply flag group")
	// Error caught by FlagDefinition.Validate() first (defense in depth)
	assert.Contains(t, err.Error(), "default value type mismatch")
	assert.Contains(t, err.Error(), "expects int, got string")
}
