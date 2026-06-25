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
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	plugincobra "github.com/thomsonreuters/stamp/plugins/cobra"
)

func TestValidateConstraints_Required(t *testing.T) {
	tests := []struct {
		name      string
		flagGroup plugincobra.FlagGroup
		setup     func(*viper.Viper)
		wantErr   bool
	}{
		{
			name: "required flag set",
			flagGroup: plugincobra.FlagGroup{
				"test-flag": {
					ConfigPath: "test.flag",
					Type:       plugincobra.StringFlag,
					Constraints: &plugincobra.FlagConstraints{
						Required: true,
					},
				},
			},
			setup: func(v *viper.Viper) {
				v.Set("test.flag", "value")
			},
			wantErr: false,
		},
		{
			name: "required flag not set",
			flagGroup: plugincobra.FlagGroup{
				"test-flag": {
					ConfigPath: "test.flag",
					Type:       plugincobra.StringFlag,
					Constraints: &plugincobra.FlagConstraints{
						Required: true,
					},
				},
			},
			setup:   func(v *viper.Viper) {},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			tt.setup(v)
			cfg := config.NewConfiguration(v)

			err := ValidateConstraints(cfg, tt.flagGroup)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateConstraints_MutuallyExclusive(t *testing.T) {
	tests := []struct {
		name      string
		flagGroup plugincobra.FlagGroup
		setup     func(*viper.Viper)
		wantErr   bool
	}{
		{
			name: "only one flag set",
			flagGroup: plugincobra.FlagGroup{
				"flag-a": {
					ConfigPath: "test.flag.a",
					Type:       plugincobra.StringFlag,
					Constraints: &plugincobra.FlagConstraints{
						MutuallyExclusive: []string{"flag-b", "flag-c"},
					},
				},
				"flag-b": {
					ConfigPath: "test.flag.b",
					Type:       plugincobra.StringFlag,
				},
				"flag-c": {
					ConfigPath: "test.flag.c",
					Type:       plugincobra.StringFlag,
				},
			},
			setup: func(v *viper.Viper) {
				v.Set("test.flag.a", "value")
			},
			wantErr: false,
		},
		{
			name: "multiple mutually exclusive flags set",
			flagGroup: plugincobra.FlagGroup{
				"flag-a": {
					ConfigPath: "test.flag.a",
					Type:       plugincobra.StringFlag,
					Constraints: &plugincobra.FlagConstraints{
						MutuallyExclusive: []string{"flag-b"},
					},
				},
				"flag-b": {
					ConfigPath: "test.flag.b",
					Type:       plugincobra.StringFlag,
				},
			},
			setup: func(v *viper.Viper) {
				v.Set("test.flag.a", "value1")
				v.Set("test.flag.b", "value2")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			tt.setup(v)
			cfg := config.NewConfiguration(v)

			err := ValidateConstraints(cfg, tt.flagGroup)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateConstraints_Requires(t *testing.T) {
	tests := []struct {
		name      string
		flagGroup plugincobra.FlagGroup
		setup     func(*viper.Viper)
		wantErr   bool
	}{
		{
			name: "flag and its dependency both set",
			flagGroup: plugincobra.FlagGroup{
				"flag-a": {
					ConfigPath: "test.flag.a",
					Type:       plugincobra.StringFlag,
					Constraints: &plugincobra.FlagConstraints{
						Requires: []string{"flag-b"},
					},
				},
				"flag-b": {
					ConfigPath: "test.flag.b",
					Type:       plugincobra.StringFlag,
				},
			},
			setup: func(v *viper.Viper) {
				v.Set("test.flag.a", "value1")
				v.Set("test.flag.b", "value2")
			},
			wantErr: false,
		},
		{
			name: "flag set but dependency missing",
			flagGroup: plugincobra.FlagGroup{
				"flag-a": {
					ConfigPath: "test.flag.a",
					Type:       plugincobra.StringFlag,
					Constraints: &plugincobra.FlagConstraints{
						Requires: []string{"flag-b"},
					},
				},
				"flag-b": {
					ConfigPath: "test.flag.b",
					Type:       plugincobra.StringFlag,
				},
			},
			setup: func(v *viper.Viper) {
				v.Set("test.flag.a", "value1")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			tt.setup(v)
			cfg := config.NewConfiguration(v)

			err := ValidateConstraints(cfg, tt.flagGroup)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateConstraints_RequiredWhen(t *testing.T) {
	// Note: Current implementation only checks RequiredWhen if the flag is already set
	// This means RequiredWhen behaves more like "validate this relationship when flag is set"
	// rather than "flag becomes required when triggers are set"
	tests := []struct {
		name      string
		flagGroup plugincobra.FlagGroup
		setup     func(*viper.Viper)
		wantErr   bool
	}{
		{
			name: "both flags set - validates relationship",
			flagGroup: plugincobra.FlagGroup{
				"flag-a": {
					ConfigPath: "test.flag.a",
					Type:       plugincobra.StringFlag,
					Constraints: &plugincobra.FlagConstraints{
						RequiredWhen: []string{"flag-b"},
					},
				},
				"flag-b": {
					ConfigPath: "test.flag.b",
					Type:       plugincobra.StringFlag,
				},
			},
			setup: func(v *viper.Viper) {
				v.Set("test.flag.a", "value1")
				v.Set("test.flag.b", "value2")
			},
			wantErr: false,
		},
		{
			name: "trigger flag not set",
			flagGroup: plugincobra.FlagGroup{
				"flag-a": {
					ConfigPath: "test.flag.a",
					Type:       plugincobra.StringFlag,
					Constraints: &plugincobra.FlagConstraints{
						RequiredWhen: []string{"flag-b"},
					},
				},
				"flag-b": {
					ConfigPath: "test.flag.b",
					Type:       plugincobra.StringFlag,
				},
			},
			setup:   func(v *viper.Viper) {},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			tt.setup(v)
			cfg := config.NewConfiguration(v)

			err := ValidateConstraints(cfg, tt.flagGroup)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateConstraints_ValidValues(t *testing.T) {
	tests := []struct {
		name      string
		flagGroup plugincobra.FlagGroup
		setup     func(*viper.Viper)
		wantErr   bool
	}{
		{
			name: "valid value from list",
			flagGroup: plugincobra.FlagGroup{
				"log-level": {
					ConfigPath: "log.level",
					Type:       plugincobra.StringFlag,
					Constraints: &plugincobra.FlagConstraints{
						ValidValues: []string{"debug", "info", "warn", "error"},
					},
				},
			},
			setup: func(v *viper.Viper) {
				v.Set("log.level", "info")
			},
			wantErr: false,
		},
		{
			name: "invalid value not in list",
			flagGroup: plugincobra.FlagGroup{
				"log-level": {
					ConfigPath: "log.level",
					Type:       plugincobra.StringFlag,
					Constraints: &plugincobra.FlagConstraints{
						ValidValues: []string{"debug", "info", "warn", "error"},
					},
				},
			},
			setup: func(v *viper.Viper) {
				v.Set("log.level", "trace")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			tt.setup(v)
			cfg := config.NewConfiguration(v)

			err := ValidateConstraints(cfg, tt.flagGroup)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateConstraints_MinMaxValue(t *testing.T) {
	minVal := 1
	maxVal := 100

	tests := []struct {
		name      string
		flagGroup plugincobra.FlagGroup
		setup     func(*viper.Viper)
		wantErr   bool
	}{
		{
			name: "value within range",
			flagGroup: plugincobra.FlagGroup{
				"port": {
					ConfigPath: "server.port",
					Type:       plugincobra.IntFlag,
					Constraints: &plugincobra.FlagConstraints{
						MinValue: &minVal,
						MaxValue: &maxVal,
					},
				},
			},
			setup: func(v *viper.Viper) {
				v.Set("server.port", 50)
			},
			wantErr: false,
		},
		{
			name: "value below minimum",
			flagGroup: plugincobra.FlagGroup{
				"port": {
					ConfigPath: "server.port",
					Type:       plugincobra.IntFlag,
					Constraints: &plugincobra.FlagConstraints{
						MinValue: &minVal,
					},
				},
			},
			setup: func(v *viper.Viper) {
				v.Set("server.port", 0)
			},
			wantErr: true,
		},
		{
			name: "value above maximum",
			flagGroup: plugincobra.FlagGroup{
				"port": {
					ConfigPath: "server.port",
					Type:       plugincobra.IntFlag,
					Constraints: &plugincobra.FlagConstraints{
						MaxValue: &maxVal,
					},
				},
			},
			setup: func(v *viper.Viper) {
				v.Set("server.port", 101)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			tt.setup(v)
			cfg := config.NewConfiguration(v)

			err := ValidateConstraints(cfg, tt.flagGroup)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateConstraints_RequiresTLS(t *testing.T) {
	tests := []struct {
		name      string
		flagGroup plugincobra.FlagGroup
		setup     func(*viper.Viper)
		wantErr   bool
	}{
		{
			name: "https url without insecure flag",
			flagGroup: plugincobra.FlagGroup{
				"server-url": {
					ConfigPath: "server.url",
					Type:       plugincobra.StringFlag,
					Constraints: &plugincobra.FlagConstraints{
						RequiresTLS: true,
					},
				},
			},
			setup: func(v *viper.Viper) {
				v.Set("server.url", "https://example.com")
				v.Set(flags.Insecure, false)
			},
			wantErr: false,
		},
		{
			name: "http url with insecure flag",
			flagGroup: plugincobra.FlagGroup{
				"server-url": {
					ConfigPath: "server.url",
					Type:       plugincobra.StringFlag,
					Constraints: &plugincobra.FlagConstraints{
						RequiresTLS: true,
					},
				},
			},
			setup: func(v *viper.Viper) {
				v.Set("server.url", "http://localhost:8080")
				v.Set(flags.Insecure, true)
			},
			wantErr: false,
		},
		{
			name: "http url without insecure flag",
			flagGroup: plugincobra.FlagGroup{
				"server-url": {
					ConfigPath: "server.url",
					Type:       plugincobra.StringFlag,
					Constraints: &plugincobra.FlagConstraints{
						RequiresTLS: true,
					},
				},
			},
			setup: func(v *viper.Viper) {
				v.Set("server.url", "http://localhost:8080")
				v.Set(flags.Insecure, false)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			tt.setup(v)
			cfg := config.NewConfiguration(v)

			err := ValidateConstraints(cfg, tt.flagGroup)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestResolveFlagNames(t *testing.T) {
	flagGroup := plugincobra.FlagGroup{
		"flag-a": {ConfigPath: "test.flag.a"},
		"flag-b": {ConfigPath: "test.flag.b"},
		"flag-c": {ConfigPath: "test.flag.c"},
	}

	tests := []struct {
		name      string
		flagNames []string
		want      []string
	}{
		{
			name:      "all flags exist",
			flagNames: []string{"flag-a", "flag-b"},
			want:      []string{"test.flag.a", "test.flag.b"},
		},
		{
			name:      "some flags don't exist",
			flagNames: []string{"flag-a", "unknown-flag"},
			want:      []string{"test.flag.a"},
		},
		{
			name:      "no flags exist",
			flagNames: []string{"unknown-1", "unknown-2"},
			want:      []string{},
		},
		{
			name:      "empty input",
			flagNames: []string{},
			want:      []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveFlagNames(tt.flagNames, flagGroup)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFindFlagNameForPath(t *testing.T) {
	flagGroup := plugincobra.FlagGroup{
		"flag-a": {ConfigPath: "test.flag.a"},
		"flag-b": {ConfigPath: "test.flag.b"},
	}

	tests := []struct {
		name       string
		configPath string
		want       string
	}{
		{
			name:       "existing path",
			configPath: "test.flag.a",
			want:       "flag-a",
		},
		{
			name:       "non-existent path",
			configPath: "test.flag.unknown",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findFlagNameForPath(tt.configPath, flagGroup)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateAllConstraints_NoConstraints(t *testing.T) {
	cfg := config.NewMockConfiguration()

	// Empty flag groups should pass
	err := ValidateAllConstraints(cfg)
	assert.NoError(t, err)
}

func TestValidateAllConstraints_WithEmptyFlagGroup(t *testing.T) {
	cfg := config.NewMockConfiguration()

	emptyGroup := plugincobra.FlagGroup{}

	err := ValidateAllConstraints(cfg, emptyGroup)
	assert.NoError(t, err)
}

func TestValidateAllConstraints_MultipleFlagGroups(t *testing.T) {
	cfg := config.NewMockConfiguration()

	group1 := plugincobra.FlagGroup{
		"flag1": {Name: "flag1", Type: plugincobra.StringFlag, ConfigPath: "flag1", Help: "Flag 1"},
	}
	group2 := plugincobra.FlagGroup{
		"flag2": {Name: "flag2", Type: plugincobra.StringFlag, ConfigPath: "flag2", Help: "Flag 2"},
	}

	err := ValidateAllConstraints(cfg, group1, group2)
	assert.NoError(t, err)
}
