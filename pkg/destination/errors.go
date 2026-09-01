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
	"context"
	"errors"
	"fmt"
	"time"
)

// Common sentinel errors for destination operations.
var (
	// ErrDestinationNotFound is returned when a requested destination type is not registered.
	ErrDestinationNotFound = errors.New("destination type not found")

	// ErrDestinationAlreadyRegistered is returned when attempting to register a duplicate destination.
	ErrDestinationAlreadyRegistered = errors.New("destination type already registered")

	// ErrNoDestinationsConfigured is returned when no destinations are available for writing.
	ErrNoDestinationsConfigured = errors.New("no destinations configured")

	// ErrInvalidConfiguration is returned when destination configuration is invalid.
	ErrInvalidConfiguration = errors.New("invalid destination configuration")

	// ErrWriteFailed is returned when a write operation fails.
	ErrWriteFailed = errors.New("write operation failed")

	// ErrDestinationUnavailable is returned when a destination is not accessible.
	ErrDestinationUnavailable = errors.New("destination unavailable")
)

// DestinationError represents an error from a destination operation.
type DestinationError struct {
	Type      string    // Destination type
	Operation string    // Operation that failed
	Err       error     // Underlying error
	Retryable bool      // Whether the operation can be retried
	Timestamp time.Time // When the error occurred
}

// Error implements the error interface.
func (e *DestinationError) Error() string {
	return fmt.Sprintf("destination %s: %s failed: %v", e.Type, e.Operation, e.Err)
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *DestinationError) Unwrap() error {
	return e.Err
}

// NewDestinationError creates a new DestinationError with the current timestamp.
// The destType should be the destination's Type() identifier, operation should
// describe what was being attempted, err is the underlying cause, and retryable
// indicates whether the operation can be safely retried.
func NewDestinationError(destType, operation string, err error, retryable bool) *DestinationError {
	return &DestinationError{
		Type:      destType,
		Operation: operation,
		Err:       err,
		Retryable: retryable,
		Timestamp: time.Now(),
	}
}

// IsRetryable checks if an error is retryable by examining if it's a DestinationError
// with the Retryable flag set. Context errors (timeout, cancellation) are considered
// non-retryable as they indicate the operation should be abandoned.
// Unknown error types are considered retryable by default for safety.
func IsRetryable(err error) bool {
	if destErr, ok := errors.AsType[*DestinationError](err); ok {
		return destErr.Retryable
	}

	// Context errors are generally not retryable
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	return true
}

// ErrConfigurationInvalid creates a configuration validation error.
func ErrConfigurationInvalid(field string, cause error) error {
	return NewDestinationError("config", "validate_"+field, cause, false)
}

// ErrConfigurationMissing creates an error for a missing required configuration field.
func ErrConfigurationMissing(field string) error {
	return NewDestinationError("config", "validate",
		fmt.Errorf("required field '%s' is missing", field), false)
}

// WrapDestinationError wraps an error with destination context.
func WrapDestinationError(destType, operation string, err error) *DestinationError {
	if err == nil {
		return nil
	}

	// Check if already a DestinationError
	if destErr, ok := errors.AsType[*DestinationError](err); ok {
		return &DestinationError{
			Type:      destType,
			Operation: operation,
			Err:       destErr,
			Retryable: destErr.Retryable,
			Timestamp: time.Now(),
		}
	}

	return NewDestinationError(destType, operation, err, true)
}
