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

package ec2

import "errors"

// Validation errors.
var (
	// ErrInvalidIMDSVersion is returned when an invalid IMDS version is specified.
	ErrInvalidIMDSVersion = errors.New("invalid IMDS version: must be auto, v1, or v2")

	// ErrInvalidTimeout is returned when timeout is negative.
	ErrInvalidTimeout = errors.New("invalid timeout: must be positive")

	// ErrInvalidMaxRetries is returned when max retries is negative.
	ErrInvalidMaxRetries = errors.New("invalid max retries: must be non-negative")

	// ErrInvalidRetryDelay is returned when retry delay is negative.
	ErrInvalidRetryDelay = errors.New("invalid retry delay: must be non-negative")

	// ErrInvalidTokenTTL is returned when token TTL is out of valid range.
	ErrInvalidTokenTTL = errors.New("invalid token TTL: must be between 1 and 21600 seconds")
)
