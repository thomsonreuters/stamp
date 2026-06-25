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

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	base := NewMockConfiguration()
	base.On("GetString", "key1").Return("value1")

	overrides := map[string]any{"key2": "value2"}
	cfg := New(base, overrides)

	require.NotNil(t, cfg)
	assert.Equal(t, "value1", cfg.GetString("key1"))
	assert.Equal(t, "value2", cfg.GetString("key2"))
	base.AssertExpectations(t)
}

func TestConfiguration_GetString(t *testing.T) {
	t.Run("from base", func(t *testing.T) {
		base := NewMockConfiguration()
		base.On("GetString", "key").Return("base_value")

		cfg := New(base, nil)
		assert.Equal(t, "base_value", cfg.GetString("key"))
		base.AssertExpectations(t)
	})

	t.Run("from override string", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": "override_value"})
		assert.Equal(t, "override_value", cfg.GetString("key"))
	})

	t.Run("from override int", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": 123})
		assert.Equal(t, "123", cfg.GetString("key"))
	})
}

func TestConfiguration_GetInt(t *testing.T) {
	t.Run("from base", func(t *testing.T) {
		base := NewMockConfiguration()
		base.On("GetInt", "key").Return(42)

		cfg := New(base, nil)
		assert.Equal(t, 42, cfg.GetInt("key"))
		base.AssertExpectations(t)
	})

	t.Run("from override int", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": 100})
		assert.Equal(t, 100, cfg.GetInt("key"))
	})

	t.Run("from override float64", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": float64(100)})
		assert.Equal(t, 100, cfg.GetInt("key"))
	})

	t.Run("from override string", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": "100"})
		assert.Equal(t, 100, cfg.GetInt("key"))
	})

	t.Run("from override invalid string falls back to base", func(t *testing.T) {
		base := NewMockConfiguration()
		base.On("GetInt", "key").Return(42)

		cfg := New(base, map[string]any{"key": "invalid"})
		assert.Equal(t, 42, cfg.GetInt("key"))
		base.AssertExpectations(t)
	})
}

func TestConfiguration_GetBool(t *testing.T) {
	t.Run("from base true", func(t *testing.T) {
		base := NewMockConfiguration()
		base.On("GetBool", "key").Return(true)

		cfg := New(base, nil)
		assert.True(t, cfg.GetBool("key"))
		base.AssertExpectations(t)
	})

	t.Run("from base false", func(t *testing.T) {
		base := NewMockConfiguration()
		base.On("GetBool", "key").Return(false)

		cfg := New(base, nil)
		assert.False(t, cfg.GetBool("key"))
		base.AssertExpectations(t)
	})

	t.Run("from override bool true", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": true})
		assert.True(t, cfg.GetBool("key"))
	})

	t.Run("from override bool false", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": false})
		assert.False(t, cfg.GetBool("key"))
	})

	t.Run("from override string true", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": "true"})
		assert.True(t, cfg.GetBool("key"))
	})

	t.Run("from override string false", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": "false"})
		assert.False(t, cfg.GetBool("key"))
	})

	t.Run("from override invalid string falls back to base", func(t *testing.T) {
		base := NewMockConfiguration()
		base.On("GetBool", "key").Return(true)

		cfg := New(base, map[string]any{"key": "invalid"})
		assert.True(t, cfg.GetBool("key"))
		base.AssertExpectations(t)
	})
}

func TestConfiguration_GetDuration(t *testing.T) {
	t.Run("from base", func(t *testing.T) {
		base := NewMockConfiguration()
		base.On("GetDuration", "key").Return(5 * time.Second)

		cfg := New(base, nil)
		assert.Equal(t, 5*time.Second, cfg.GetDuration("key"))
		base.AssertExpectations(t)
	})

	t.Run("from override duration", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": 10 * time.Second})
		assert.Equal(t, 10*time.Second, cfg.GetDuration("key"))
	})

	t.Run("from override string", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": "10s"})
		assert.Equal(t, 10*time.Second, cfg.GetDuration("key"))
	})

	t.Run("from override int", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": int(1000000000)})
		assert.Equal(t, time.Second, cfg.GetDuration("key"))
	})

	t.Run("from override float64", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": float64(1000000000)})
		assert.Equal(t, time.Second, cfg.GetDuration("key"))
	})

	t.Run("from override invalid string falls back to base", func(t *testing.T) {
		base := NewMockConfiguration()
		base.On("GetDuration", "key").Return(5 * time.Second)

		cfg := New(base, map[string]any{"key": "invalid"})
		assert.Equal(t, 5*time.Second, cfg.GetDuration("key"))
		base.AssertExpectations(t)
	})
}

func TestConfiguration_GetStringSlice(t *testing.T) {
	t.Run("from base", func(t *testing.T) {
		base := NewMockConfiguration()
		base.On("GetStringSlice", "key").Return([]string{"a", "b"})

		cfg := New(base, nil)
		assert.Equal(t, []string{"a", "b"}, cfg.GetStringSlice("key"))
		base.AssertExpectations(t)
	})

	t.Run("from override slice", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": []string{"c", "d"}})
		assert.Equal(t, []string{"c", "d"}, cfg.GetStringSlice("key"))
	})

	t.Run("from override any slice", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": []any{"x", "y"}})
		assert.Equal(t, []string{"x", "y"}, cfg.GetStringSlice("key"))
	})

	t.Run("from override csv string", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": "x,y,z"})
		assert.Equal(t, []string{"x", "y", "z"}, cfg.GetStringSlice("key"))
	})
}

func TestConfiguration_GetStringMapString(t *testing.T) {
	t.Run("from base", func(t *testing.T) {
		base := NewMockConfiguration()
		base.On("GetStringMapString", "key").Return(map[string]string{"a": "1"})

		cfg := New(base, nil)
		assert.Equal(t, map[string]string{"a": "1"}, cfg.GetStringMapString("key"))
		base.AssertExpectations(t)
	})

	t.Run("from override map[string]string", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": map[string]string{"b": "2"}})
		assert.Equal(t, map[string]string{"b": "2"}, cfg.GetStringMapString("key"))
	})

	t.Run("from override map[string]any", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": map[string]any{"c": 3}})
		assert.Equal(t, map[string]string{"c": "3"}, cfg.GetStringMapString("key"))
	})
}

func TestConfiguration_IsSet(t *testing.T) {
	t.Run("from base", func(t *testing.T) {
		base := NewMockConfiguration()
		base.On("IsSet", "base_key").Return(true)

		cfg := New(base, map[string]any{"override_key": "value"})

		assert.True(t, cfg.IsSet("base_key"))
		base.AssertExpectations(t)
	})

	t.Run("from override", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"override_key": "value"})

		assert.True(t, cfg.IsSet("override_key"))
	})

	t.Run("not set", func(t *testing.T) {
		base := NewMockConfiguration()
		base.On("IsSet", "nonexistent").Return(false)

		cfg := New(base, nil)
		assert.False(t, cfg.IsSet("nonexistent"))
		base.AssertExpectations(t)
	})
}

func TestConfiguration_Set_Panics(t *testing.T) {
	base := NewMockConfiguration()
	cfg := New(base, nil)

	assert.Panics(t, func() {
		cfg.Set("key", "value")
	})
}

func TestConfiguration_AllSettings(t *testing.T) {
	base := NewMockConfiguration()
	base.On("AllSettings").Return(map[string]any{
		"key1": "value1",
		"key2": "value2",
	})

	cfg := New(base, map[string]any{"key2": "override2", "key3": "value3"})

	settings := cfg.AllSettings()
	assert.Equal(t, "value1", settings["key1"])
	assert.Equal(t, "override2", settings["key2"])
	assert.Equal(t, "value3", settings["key3"])
	base.AssertExpectations(t)
}

func TestConfiguration_UnmarshalKey(t *testing.T) {
	t.Run("string from override", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": "test"})

		var result string
		err := cfg.UnmarshalKey("key", &result)
		require.NoError(t, err)
		assert.Equal(t, "test", result)
	})

	t.Run("int from override", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": 42})

		var result int
		err := cfg.UnmarshalKey("key", &result)
		require.NoError(t, err)
		assert.Equal(t, 42, result)
	})

	t.Run("bool from override", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": true})

		var result bool
		err := cfg.UnmarshalKey("key", &result)
		require.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("complex type from override", func(t *testing.T) {
		base := NewMockConfiguration()
		cfg := New(base, map[string]any{"key": map[string]any{"nested": "value"}})

		var result map[string]any
		err := cfg.UnmarshalKey("key", &result)
		require.NoError(t, err)
		assert.Equal(t, "value", result["nested"])
	})

	t.Run("from base", func(t *testing.T) {
		base := NewMockConfiguration()
		base.On("UnmarshalKey", "key", mock.Anything).Return(nil)

		cfg := New(base, nil)
		var result map[string]any
		err := cfg.UnmarshalKey("key", &result)
		require.NoError(t, err)
		base.AssertExpectations(t)
	})
}

func TestNewConfiguration(t *testing.T) {
	v := viper.New()
	v.Set("test.key", "value")

	cfg := NewConfiguration(v)
	require.NotNil(t, cfg)
	assert.Equal(t, "value", cfg.GetString("test.key"))
}

func TestNewConfiguration_NilPanics(t *testing.T) {
	assert.Panics(t, func() {
		NewConfiguration(nil)
	})
}

func TestViperAdapter(t *testing.T) {
	v := viper.New()
	v.Set("string_key", "string_value")
	v.Set("int_key", 42)
	v.Set("bool_key", true)
	v.Set("duration_key", "5s")
	v.Set("slice_key", []string{"a", "b"})
	v.Set("map_key", map[string]string{"k": "v"})

	cfg := NewConfiguration(v)

	t.Run("GetString", func(t *testing.T) {
		assert.Equal(t, "string_value", cfg.GetString("string_key"))
	})

	t.Run("GetInt", func(t *testing.T) {
		assert.Equal(t, 42, cfg.GetInt("int_key"))
	})

	t.Run("GetBool", func(t *testing.T) {
		assert.True(t, cfg.GetBool("bool_key"))
	})

	t.Run("GetDuration", func(t *testing.T) {
		assert.Equal(t, 5*time.Second, cfg.GetDuration("duration_key"))
	})

	t.Run("GetStringSlice", func(t *testing.T) {
		assert.Equal(t, []string{"a", "b"}, cfg.GetStringSlice("slice_key"))
	})

	t.Run("GetStringMapString", func(t *testing.T) {
		assert.Equal(t, map[string]string{"k": "v"}, cfg.GetStringMapString("map_key"))
	})

	t.Run("IsSet", func(t *testing.T) {
		assert.True(t, cfg.IsSet("string_key"))
		assert.False(t, cfg.IsSet("nonexistent"))
	})

	t.Run("Set", func(t *testing.T) {
		cfg.Set("new_key", "new_value")
		assert.Equal(t, "new_value", cfg.GetString("new_key"))
	})

	t.Run("AllSettings", func(t *testing.T) {
		settings := cfg.AllSettings()
		assert.NotEmpty(t, settings)
	})
}

func TestMockConfiguration_Interface(t *testing.T) {
	var _ ConfigurationIface = (*MockConfiguration)(nil)
}
