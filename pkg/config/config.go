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

// Package config provides configuration interfaces and implementations for the attestation framework.
// It offers a clean abstraction over configuration providers, enabling testability and loose coupling.
package config

import (
	"encoding/json"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// ConfigurationIface provides access to configuration values.
// Implementations must be safe for concurrent use.
type ConfigurationIface interface {
	// Core value getters
	GetString(key string) string
	GetInt(key string) int
	GetBool(key string) bool
	GetDuration(key string) time.Duration
	GetStringSlice(key string) []string
	GetStringMapString(key string) map[string]string

	// Configuration management
	IsSet(key string) bool
	Set(key string, value any)
	UnmarshalKey(key string, rawVal any) error
	AllSettings() map[string]any
}

// Configuration provides attestor-specific configuration overrides without
// mutating the underlying base configuration. It implements the Configuration
// interface and is safe for concurrent use.
type Configuration struct {
	base      ConfigurationIface // Base configuration (read-only)
	overrides map[string]any     // Attestor-specific overrides
}

func (o *Configuration) GetString(key string) string {
	if val, ok := o.overrides[key]; ok {
		return fmt.Sprint(val)
	}
	return o.base.GetString(key)
}

func (o *Configuration) GetInt(key string) int {
	if val, ok := o.overrides[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case string:
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
		}
	}
	return o.base.GetInt(key)
}

func (o *Configuration) GetBool(key string) bool {
	if val, ok := o.overrides[key]; ok {
		switch v := val.(type) {
		case bool:
			return v
		case string:
			if b, err := strconv.ParseBool(v); err == nil {
				return b
			}
		}
	}
	return o.base.GetBool(key)
}

func (o *Configuration) GetDuration(key string) time.Duration {
	if val, ok := o.overrides[key]; ok {
		switch v := val.(type) {
		case time.Duration:
			return v
		case string:
			if d, err := time.ParseDuration(v); err == nil {
				return d
			}
		case int:
			return time.Duration(v)
		case float64:
			return time.Duration(v)
		}
	}
	return o.base.GetDuration(key)
}

func (o *Configuration) GetStringSlice(key string) []string {
	if val, ok := o.overrides[key]; ok {
		switch v := val.(type) {
		case []string:
			return v
		case []any:
			result := make([]string, len(v))
			for i, item := range v {
				result[i] = fmt.Sprint(item)
			}
			return result
		case string:
			return strings.Split(v, ",")
		}
	}
	return o.base.GetStringSlice(key)
}

func (o *Configuration) GetStringMapString(key string) map[string]string {
	if val, exists := o.overrides[key]; exists {
		if m, isStringMap := val.(map[string]string); isStringMap {
			return m
		}
		if m, isAnyMap := val.(map[string]any); isAnyMap {
			result := make(map[string]string)
			for k, v := range m {
				result[k] = fmt.Sprint(v)
			}
			return result
		}
	}
	return o.base.GetStringMapString(key)
}

func (o *Configuration) IsSet(key string) bool {
	_, exists := o.overrides[key]
	return exists || o.base.IsSet(key)
}

func (o *Configuration) Set(key string, value any) {
	// Configuration is immutable - panic to prevent misuse
	panic("Configuration is immutable - use base configuration for mutations or create new configuration")
}

func (o *Configuration) UnmarshalKey(key string, rawVal any) error {
	if val, exists := o.overrides[key]; exists {
		switch rv := rawVal.(type) {
		case *string:
			*rv = fmt.Sprint(val)
		case *int:
			if i, isInt := val.(int); isInt {
				*rv = i
			}
		case *bool:
			if b, isBool := val.(bool); isBool {
				*rv = b
			}
		default:
			jsonBytes, err := json.Marshal(val)
			if err != nil {
				return err
			}
			return json.Unmarshal(jsonBytes, rawVal)
		}
		return nil
	}
	return o.base.UnmarshalKey(key, rawVal)
}

func (o *Configuration) AllSettings() map[string]any {
	// Merge base settings with overrides
	merged := make(map[string]any)
	maps.Copy(merged, o.base.AllSettings())
	maps.Copy(merged, o.overrides)
	return merged
}

func newOverlay(base ConfigurationIface, overrides map[string]any) ConfigurationIface {
	return &Configuration{
		base:      base,
		overrides: overrides,
	}
}

// New creates a configuration overlay that provides attestor-specific
// overrides on top of a base configuration.
var New = newOverlay

// ViperAdapter adapts a viper instance to the Configuration interface.
// It provides a thin wrapper around viper's functionality.
type ViperAdapter struct {
	viper *viper.Viper
}

// GetString returns the value associated with the key as a string.
func (a *ViperAdapter) GetString(key string) string {
	return a.viper.GetString(key)
}

// GetInt returns the value associated with the key as an integer.
func (a *ViperAdapter) GetInt(key string) int {
	return a.viper.GetInt(key)
}

// GetBool returns the value associated with the key as a boolean.
func (a *ViperAdapter) GetBool(key string) bool {
	return a.viper.GetBool(key)
}

// GetDuration returns the value associated with the key as a duration.
func (a *ViperAdapter) GetDuration(key string) time.Duration {
	return a.viper.GetDuration(key)
}

// GetStringSlice returns the value associated with the key as a slice of strings.
func (a *ViperAdapter) GetStringSlice(key string) []string {
	return a.viper.GetStringSlice(key)
}

// GetStringMapString returns the value associated with the key as a map of strings.
func (a *ViperAdapter) GetStringMapString(key string) map[string]string {
	return a.viper.GetStringMapString(key)
}

// IsSet checks if a key is present in the configuration.
func (a *ViperAdapter) IsSet(key string) bool {
	return a.viper.IsSet(key)
}

// Set sets the value for the given key.
func (a *ViperAdapter) Set(key string, value any) {
	a.viper.Set(key, value)
}

// UnmarshalKey unmarshals a specific key into a custom struct.
func (a *ViperAdapter) UnmarshalKey(key string, rawVal any) error {
	return a.viper.UnmarshalKey(key, rawVal)
}

// AllSettings returns all settings as a map.
func (a *ViperAdapter) AllSettings() map[string]any {
	return a.viper.AllSettings()
}

// NewConfiguration creates a new Configuration backed by a viper instance.
// The provided viper instance should be properly configured before passing.
// This should be called once per command execution and the returned
// Configuration should be passed to components via dependency injection.
func NewConfiguration(v *viper.Viper) ConfigurationIface {
	if v == nil {
		panic("viper instance cannot be nil")
	}
	return &ViperAdapter{viper: v}
}
