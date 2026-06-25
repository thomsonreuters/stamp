// Copyright 2026 Thomson Reuters
// Licensed under the Apache License, Version 2.0

package config

import (
	"fmt"
	"maps"
	"time"

	"github.com/thomsonreuters/stamp/pkg/types"
)

// RetryPolicy defines the retry parameters for a specific component.
type RetryPolicy struct {
	MaxAttempts    int           `yaml:"max_attempts"              mapstructure:"max_attempts"`
	InitialDelay   time.Duration `yaml:"initial_delay"             mapstructure:"initial_delay"`
	MaxDelay       time.Duration `yaml:"max_delay"                 mapstructure:"max_delay"`
	Multiplier     float64       `yaml:"multiplier"                mapstructure:"multiplier"`
	MaxParallel    int           `yaml:"max_parallel,omitempty"    mapstructure:"max_parallel,omitempty"`
	DefaultTimeout time.Duration `yaml:"default_timeout,omitempty" mapstructure:"default_timeout,omitempty"`
}

// Workflow defines a named set of attestors to run with their output configuration.
type Workflow struct {
	Name          string      `yaml:"name"                     mapstructure:"name"`
	Tags          []string    `yaml:"tags,omitempty"           mapstructure:"tags,omitempty"`
	FailurePolicy string      `yaml:"failure_policy,omitempty" mapstructure:"failure_policy,omitempty"`
	OutputMode    string      `yaml:"output_mode,omitempty"    mapstructure:"output_mode,omitempty"`
	Rekor         RekorConfig `yaml:"rekor"                    mapstructure:"rekor"`
	Attestors     []Attestor  `yaml:"attestors"                mapstructure:"attestors"`
}

// Validate checks that the workflow is valid.
func (w *Workflow) Validate() error {
	if w.Name == "" {
		return ErrEmptyWorkflowName
	}

	if len(w.Attestors) == 0 {
		return fmt.Errorf("%w: workflow %q", ErrNoAttestors, w.Name)
	}

	// Validate failure policy if specified
	if w.FailurePolicy != "" && !types.IsValidFailurePolicy(w.FailurePolicy) {
		return fmt.Errorf("%w: workflow %q has %q (valid: %v)", ErrInvalidFailurePolicy, w.Name, w.FailurePolicy, types.ValidFailurePolicies)
	}

	// Validate output_mode if specified
	if w.OutputMode != "" && !types.IsValidOutputMode(w.OutputMode) {
		return fmt.Errorf("%w: workflow %q has %q (valid: %v)", ErrInvalidOutputMode, w.Name, w.OutputMode, types.ValidOutputModes)
	}

	// Check attestor names are unique within workflow
	names := make(map[string]bool)
	for i, attestor := range w.Attestors {
		if attestor.Name == "" {
			return fmt.Errorf("%w: attestor at index %d in workflow %q", ErrEmptyAttestorName, i, w.Name)
		}

		if attestor.Type == "" {
			return fmt.Errorf("%w: attestor %q at index %d in workflow %q", ErrEmptyAttestorType, attestor.Name, i, w.Name)
		}

		if names[attestor.Name] {
			return fmt.Errorf("%w: %q in workflow %q", ErrDuplicateAttestor, attestor.Name, w.Name)
		}
		names[attestor.Name] = true
	}

	return nil
}

// RekorConfig controls transparency log upload behavior for a workflow.
type RekorConfig struct {
	Upload       bool   `yaml:"upload"        mapstructure:"upload"`
	UploadTarget string `yaml:"upload_target" mapstructure:"upload_target"`
}

// Attestor identifies an attestor and its configuration within a workflow.
type Attestor struct {
	Name   string         `yaml:"name"   mapstructure:"name"`
	Type   string         `yaml:"type"   mapstructure:"type"`
	Config map[string]any `yaml:"config" mapstructure:"config"`
}

// ToAttestorConfig returns a copy of the attestor's configuration map.
func (a *Attestor) ToAttestorConfig() map[string]any {
	result := make(map[string]any, len(a.Config))
	maps.Copy(result, a.Config)
	return result
}
