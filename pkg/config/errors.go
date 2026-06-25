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

import "errors"

// FlagDefinition validation errors.
var (
	ErrEmptyFlagName       = errors.New("flag name cannot be empty")
	ErrEmptyConfigPath     = errors.New("config path cannot be empty")
	ErrEmptyHelp           = errors.New("help text cannot be empty")
	ErrInvalidDefaultType  = errors.New("default value type mismatch")
	ErrUnsupportedFlagType = errors.New("unsupported flag type")
)

// FlagGroup validation errors.
var (
	ErrFlagNameMismatch    = errors.New("flag group key does not match flag name")
	ErrFlagValidation      = errors.New("flag validation failed")
	ErrFlagGroupValidation = errors.New("flag group validation failed")
)

// Workflow validation errors.
var (
	ErrEmptyWorkflowName    = errors.New("workflow name is required")
	ErrNoAttestors          = errors.New("workflow must have at least one attestor")
	ErrInvalidFailurePolicy = errors.New("invalid failure policy")
	ErrInvalidOutputMode    = errors.New("invalid output mode")
	ErrDuplicateAttestor    = errors.New("duplicate attestor name")
	ErrEmptyAttestorName    = errors.New("attestor name is required")
	ErrEmptyAttestorType    = errors.New("attestor type is required")
)
