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

import (
	"time"
)

// IMDSOptions represents the configuration options for IMDS requests.
type IMDSOptions struct {
	// Endpoint is the IMDS endpoint URL.
	Endpoint string

	// Version is the IMDS protocol version to use.
	Version IMDSVersion

	// Timeout is the IMDS request timeout.
	Timeout time.Duration

	// MaxRetries is the maximum number of IMDS retry attempts.
	MaxRetries int

	// RetryDelay is the delay between IMDS retry attempts.
	RetryDelay time.Duration

	// TokenTTL is the IMDSv2 token TTL in seconds.
	TokenTTL int
}

// Validate validates the IMDS options and applies defaults for unset values.
func (o *IMDSOptions) Validate() error {
	// Apply defaults
	if o.Endpoint == "" {
		o.Endpoint = DefaultIMDSEndpoint
	}

	if o.Version == "" {
		o.Version = IMDSVersionAuto
	}

	if o.Timeout == 0 {
		o.Timeout = DefaultIMDSTimeout
	}

	if o.MaxRetries == 0 {
		o.MaxRetries = DefaultIMDSMaxRetries
	}

	if o.RetryDelay == 0 {
		o.RetryDelay = DefaultIMDSRetryDelay
	}

	if o.TokenTTL == 0 {
		o.TokenTTL = DefaultIMDSv2TokenTTL
	}

	// Validate values
	if o.Version != IMDSVersionAuto && o.Version != IMDSVersionV1 && o.Version != IMDSVersionV2 {
		return ErrInvalidIMDSVersion
	}

	if o.Timeout < 0 {
		return ErrInvalidTimeout
	}

	if o.MaxRetries < 0 {
		return ErrInvalidMaxRetries
	}

	if o.RetryDelay < 0 {
		return ErrInvalidRetryDelay
	}

	if o.TokenTTL < 1 || o.TokenTTL > 21600 {
		return ErrInvalidTokenTTL
	}

	return nil
}

// DefaultIMDSOptions returns IMDSOptions with all default values.
func DefaultIMDSOptions() *IMDSOptions {
	return &IMDSOptions{
		Endpoint:   DefaultIMDSEndpoint,
		Version:    IMDSVersionAuto,
		Timeout:    DefaultIMDSTimeout,
		MaxRetries: DefaultIMDSMaxRetries,
		RetryDelay: DefaultIMDSRetryDelay,
		TokenTTL:   DefaultIMDSv2TokenTTL,
	}
}
