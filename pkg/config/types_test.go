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

package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/types"
	plugincobra "github.com/thomsonreuters/stamp/plugins/cobra"
)

func TestFlagType_String(t *testing.T) {
	tests := []struct {
		ft       plugincobra.FlagType
		expected string
	}{
		{plugincobra.StringFlag, "string"},
		{plugincobra.BoolFlag, "bool"},
		{plugincobra.IntFlag, "int"},
		{plugincobra.DurationFlag, "duration"},
		{plugincobra.StringSliceFlag, "[]string"},
		{plugincobra.StringArrayFlag, "[]string"},
		{plugincobra.FlagType(999), "unknown(999)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ft.String())
		})
	}
}

func TestFlagDefinition_Validate(t *testing.T) {
	t.Run("valid string flag", func(t *testing.T) {
		fd := plugincobra.FlagDefinition{
			Name:       "test-flag",
			ConfigPath: "test.path",
			Type:       plugincobra.StringFlag,
			Help:       "Test help",
			Default:    "default",
		}
		assert.NoError(t, fd.Validate())
	})

	t.Run("valid bool flag", func(t *testing.T) {
		fd := plugincobra.FlagDefinition{
			Name:       "test-flag",
			ConfigPath: "test.path",
			Type:       plugincobra.BoolFlag,
			Help:       "Test help",
			Default:    true,
		}
		assert.NoError(t, fd.Validate())
	})

	t.Run("valid int flag", func(t *testing.T) {
		fd := plugincobra.FlagDefinition{
			Name:       "test-flag",
			ConfigPath: "test.path",
			Type:       plugincobra.IntFlag,
			Help:       "Test help",
			Default:    42,
		}
		assert.NoError(t, fd.Validate())
	})

	t.Run("valid duration flag", func(t *testing.T) {
		fd := plugincobra.FlagDefinition{
			Name:       "test-flag",
			ConfigPath: "test.path",
			Type:       plugincobra.DurationFlag,
			Help:       "Test help",
			Default:    5 * time.Second,
		}
		assert.NoError(t, fd.Validate())
	})

	t.Run("valid string slice flag", func(t *testing.T) {
		fd := plugincobra.FlagDefinition{
			Name:       "test-flag",
			ConfigPath: "test.path",
			Type:       plugincobra.StringSliceFlag,
			Help:       "Test help",
			Default:    []string{"a", "b"},
		}
		assert.NoError(t, fd.Validate())
	})

	t.Run("valid string array flag", func(t *testing.T) {
		fd := plugincobra.FlagDefinition{
			Name:       "test-flag",
			ConfigPath: "test.path",
			Type:       plugincobra.StringArrayFlag,
			Help:       "Test help",
			Default:    []string{"a", "b"},
		}
		assert.NoError(t, fd.Validate())
	})

	t.Run("valid flag with nil default", func(t *testing.T) {
		fd := plugincobra.FlagDefinition{
			Name:       "test-flag",
			ConfigPath: "test.path",
			Type:       plugincobra.StringFlag,
			Help:       "Test help",
			Default:    nil,
		}
		assert.NoError(t, fd.Validate())
	})

	t.Run("empty name", func(t *testing.T) {
		fd := plugincobra.FlagDefinition{
			Name:       "",
			ConfigPath: "test.path",
			Type:       plugincobra.StringFlag,
			Help:       "Test help",
		}
		err := fd.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, plugincobra.ErrEmptyFlagName)
	})

	t.Run("empty config path", func(t *testing.T) {
		fd := plugincobra.FlagDefinition{
			Name:       "test-flag",
			ConfigPath: "",
			Type:       plugincobra.StringFlag,
			Help:       "Test help",
		}
		err := fd.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, plugincobra.ErrEmptyConfigPath)
	})

	t.Run("empty help", func(t *testing.T) {
		fd := plugincobra.FlagDefinition{
			Name:       "test-flag",
			ConfigPath: "test.path",
			Type:       plugincobra.StringFlag,
			Help:       "",
		}
		err := fd.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, plugincobra.ErrEmptyHelp)
	})

	t.Run("invalid default type for string flag", func(t *testing.T) {
		fd := plugincobra.FlagDefinition{
			Name:       "test-flag",
			ConfigPath: "test.path",
			Type:       plugincobra.StringFlag,
			Help:       "Test help",
			Default:    123,
		}
		err := fd.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, plugincobra.ErrInvalidDefaultType)
	})

	t.Run("invalid default type for bool flag", func(t *testing.T) {
		fd := plugincobra.FlagDefinition{
			Name:       "test-flag",
			ConfigPath: "test.path",
			Type:       plugincobra.BoolFlag,
			Help:       "Test help",
			Default:    "true",
		}
		err := fd.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, plugincobra.ErrInvalidDefaultType)
	})

	t.Run("invalid default type for int flag", func(t *testing.T) {
		fd := plugincobra.FlagDefinition{
			Name:       "test-flag",
			ConfigPath: "test.path",
			Type:       plugincobra.IntFlag,
			Help:       "Test help",
			Default:    "42",
		}
		err := fd.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, plugincobra.ErrInvalidDefaultType)
	})

	t.Run("invalid default type for duration flag", func(t *testing.T) {
		fd := plugincobra.FlagDefinition{
			Name:       "test-flag",
			ConfigPath: "test.path",
			Type:       plugincobra.DurationFlag,
			Help:       "Test help",
			Default:    "5s",
		}
		err := fd.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, plugincobra.ErrInvalidDefaultType)
	})

	t.Run("invalid default type for string slice flag", func(t *testing.T) {
		fd := plugincobra.FlagDefinition{
			Name:       "test-flag",
			ConfigPath: "test.path",
			Type:       plugincobra.StringSliceFlag,
			Help:       "Test help",
			Default:    "a,b,c",
		}
		err := fd.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, plugincobra.ErrInvalidDefaultType)
	})

	t.Run("unsupported flag type", func(t *testing.T) {
		fd := plugincobra.FlagDefinition{
			Name:       "test-flag",
			ConfigPath: "test.path",
			Type:       plugincobra.FlagType(999),
			Help:       "Test help",
		}
		err := fd.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, plugincobra.ErrUnsupportedFlagType)
	})
}

func TestWorkflow_Validate(t *testing.T) {
	validWorkflow := func() Workflow {
		return Workflow{
			Name:       "test-workflow",
			OutputMode: types.OutputModeIndividual.String(),
			Attestors: []Attestor{
				{Name: "att1", Type: "file"},
			},
		}
	}

	t.Run("valid workflow", func(t *testing.T) {
		s := validWorkflow()
		assert.NoError(t, s.Validate())
	})

	t.Run("valid with collection output mode", func(t *testing.T) {
		s := Workflow{
			Name:       "test-workflow",
			OutputMode: types.OutputModeCollection.String(),
			Attestors: []Attestor{
				{Name: "att1", Type: "file"},
			},
		}
		assert.NoError(t, s.Validate())
	})

	t.Run("valid with both output mode", func(t *testing.T) {
		s := Workflow{
			Name:       "test-workflow",
			OutputMode: types.OutputModeBoth.String(),
			Attestors: []Attestor{
				{Name: "att1", Type: "file"},
			},
		}
		assert.NoError(t, s.Validate())
	})

	t.Run("valid with failure policy", func(t *testing.T) {
		s := validWorkflow()
		s.FailurePolicy = types.FailurePolicyContinue.String()
		assert.NoError(t, s.Validate())
	})

	t.Run("empty name", func(t *testing.T) {
		s := validWorkflow()
		s.Name = ""
		err := s.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyWorkflowName)
	})

	t.Run("no attestors", func(t *testing.T) {
		s := validWorkflow()
		s.Attestors = nil
		err := s.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNoAttestors)
	})

	t.Run("empty attestors", func(t *testing.T) {
		s := validWorkflow()
		s.Attestors = []Attestor{}
		err := s.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNoAttestors)
	})

	t.Run("invalid failure policy", func(t *testing.T) {
		s := validWorkflow()
		s.FailurePolicy = "invalid"
		err := s.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidFailurePolicy)
	})

	t.Run("invalid output mode", func(t *testing.T) {
		s := validWorkflow()
		s.OutputMode = "invalid"
		err := s.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidOutputMode)
	})

	t.Run("empty attestor name", func(t *testing.T) {
		s := validWorkflow()
		s.Attestors[0].Name = ""
		err := s.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyAttestorName)
	})

	t.Run("empty attestor type", func(t *testing.T) {
		s := validWorkflow()
		s.Attestors[0].Type = ""
		err := s.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyAttestorType)
	})

	t.Run("duplicate attestor name", func(t *testing.T) {
		s := validWorkflow()
		s.Attestors = append(s.Attestors, Attestor{Name: "att1", Type: "git"})
		err := s.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDuplicateAttestor)
	})

	t.Run("default output mode is valid", func(t *testing.T) {
		s := Workflow{
			Name:       "test-workflow",
			OutputMode: "", // defaults to individual
			Attestors:  []Attestor{{Name: "att1", Type: "file"}},
		}
		assert.NoError(t, s.Validate())
	})
}

func TestAttestor_ToAttestorConfig(t *testing.T) {
	a := Attestor{
		Name: "test",
		Type: "file",
		Config: map[string]any{
			"key1": "value1",
			"key2": 42,
		},
	}

	config := a.ToAttestorConfig()

	assert.Equal(t, "value1", config["key1"])
	assert.Equal(t, 42, config["key2"])

	// Ensure it's a copy
	config["key1"] = "modified"
	assert.Equal(t, "value1", a.Config["key1"])
}

func TestAttestor_ToAttestorConfig_Nil(t *testing.T) {
	a := Attestor{
		Name:   "test",
		Type:   "file",
		Config: nil,
	}

	config := a.ToAttestorConfig()
	assert.NotNil(t, config)
	assert.Empty(t, config)
}
