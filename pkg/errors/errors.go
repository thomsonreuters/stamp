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

// Package errors provides a simplified, production-ready error handling system.
package errors

import (
	"errors"
	"fmt"
	"strings"
)

// Exit codes for different error scenarios.
const (
	ExitSuccess         = 0
	ExitGeneralError    = 1
	ExitUsageError      = 2
	ExitValidationError = 3
	ExitConfigError     = 4
	ExitRuntimeError    = 5
)

// BaseError is our standard error with structured context.
type BaseError struct {
	Message     string   // What went wrong
	Component   string   // Where it happened (e.g., "pipeline", "command", "attestor")
	Operation   string   // What was being done (e.g., "validate", "execute", "sign")
	Cause       error    // Underlying error if any
	Suggestions []string // User-friendly suggestions (only shown in human output)
	ExitCode    int      // CLI exit code
}

// Error implements the error interface.
func (e *BaseError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *BaseError) Unwrap() error {
	return e.Cause
}

// Suggest adds user-friendly suggestions to an error.
func (e *BaseError) Suggest(suggestions ...string) *BaseError {
	e.Suggestions = append(e.Suggestions, suggestions...)
	return e
}

// WithExitCode sets the exit code.
func (e *BaseError) WithExitCode(code int) *BaseError {
	e.ExitCode = code
	return e
}

// ValidationError aggregates field-level validation issues.
type ValidationError struct {
	BaseError
	Fields map[string][]string // field -> list of error messages
}

// Error returns the formatted error message.
func (v *ValidationError) Error() string {
	if !v.HasErrors() {
		return ""
	}

	var msg strings.Builder
	msg.WriteString("validation failed:")
	for field, errors := range v.Fields {
		for _, err := range errors {
			fmt.Fprintf(&msg, "\n  - %s: %s", field, err)
		}
	}
	return msg.String()
}

// HasErrors checks if there are any validation errors.
func (v *ValidationError) HasErrors() bool {
	return len(v.Fields) > 0
}

// AddError adds a field validation error.
func (v *ValidationError) AddError(field, message string) {
	v.Fields[field] = append(v.Fields[field], message)
}

// New creates a basic error.
func New(message string) *BaseError {
	return &BaseError{
		Message:  message,
		ExitCode: ExitGeneralError,
	}
}

// NewWithContext creates an error with context.
func NewWithContext(component, operation, message string) *BaseError {
	return &BaseError{
		Component: component,
		Operation: operation,
		Message:   message,
		ExitCode:  ExitGeneralError,
	}
}

// Wrap adds a simple message context to any error.
func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

// WrapWithContext adds component/operation context to an error.
func WrapWithContext(err error, component, operation, message string) *BaseError {
	if err == nil {
		return nil
	}

	// If it's already our BaseError type, preserve its properties
	e := &BaseError{}
	if errors.As(err, &e) {
		// Create new error preserving original context
		return &BaseError{
			Component:   component,
			Operation:   operation,
			Message:     message,
			Cause:       e,
			Suggestions: e.Suggestions,
			ExitCode:    e.ExitCode,
		}
	}

	return &BaseError{
		Component: component,
		Operation: operation,
		Message:   message,
		Cause:     err,
		ExitCode:  ExitGeneralError,
	}
}

// NewValidator creates a validation error collector.
func NewValidator() *ValidationError {
	return &ValidationError{
		BaseError: BaseError{
			Component: "validation",
			Message:   "validation failed",
			ExitCode:  ExitValidationError,
		},
		Fields: make(map[string][]string),
	}
}

// NewValidatorFor creates a validation error collector for a specific component.
func NewValidatorFor(component string) *ValidationError {
	return &ValidationError{
		BaseError: BaseError{
			Component: component,
			Operation: "validate",
			Message:   "validation failed",
			ExitCode:  ExitValidationError,
		},
		Fields: make(map[string][]string),
	}
}

// GetExitCode extracts the exit code from any error.
func GetExitCode(err error) int {
	if err == nil {
		return ExitSuccess
	}

	e := &BaseError{}
	if errors.As(err, &e) {
		return e.ExitCode
	}

	v := &ValidationError{}
	if errors.As(err, &v) {
		return v.ExitCode
	}

	return ExitGeneralError
}

// NewUsageError creates a usage error with suggestions.
func NewUsageError(message string, suggestions ...string) *BaseError {
	return &BaseError{
		Component:   "cli",
		Operation:   "parse",
		Message:     message,
		Suggestions: suggestions,
		ExitCode:    ExitUsageError,
	}
}

// WrapPipeline wraps an error with pipeline context.
func WrapPipeline(err error, phase, attestorID string) *BaseError {
	if err == nil {
		return nil
	}
	message := fmt.Sprintf("pipeline error in phase '%s'", phase)
	if attestorID != "" {
		message = fmt.Sprintf("pipeline error in phase '%s' for attestor '%s'", phase, attestorID)
	}
	return WrapWithContext(err, "pipeline", phase, message).
		WithExitCode(ExitRuntimeError)
}

// WrapAttestor wraps an error with attestor context.
func WrapAttestor(err error, attestorID, phase string) *BaseError {
	if err == nil {
		return nil
	}
	return WrapWithContext(err, attestorID, phase,
		fmt.Sprintf("attestor '%s' failed during %s", attestorID, phase)).
		WithExitCode(ExitRuntimeError)
}
