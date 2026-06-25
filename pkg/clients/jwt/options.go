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

package jwt

import (
	"time"

	"github.com/thomsonreuters/stamp/pkg/logger"
)

// Options configures the JWT client.
type Options struct {
	Logger logger.Logger

	// Key source options (priority order: PublicKeyFile > JWKSURL > OIDCDiscoveryURL > auto-discovery)
	JWKSURL          string
	OIDCDiscoveryURL string
	PublicKeyFile    string
	CACertFile       string

	// HTTP options
	HTTPTimeout   time.Duration
	AllowInsecure bool

	// Algorithm options
	AllowedAlgorithms []string
	DeniedAlgorithms  []string

	// JWKS caching options
	JWKSRefreshInterval    time.Duration
	JWKSMinRefreshInterval time.Duration
}

// DefaultOptions returns sensible defaults for the JWT client.
func DefaultOptions() Options {
	return Options{
		HTTPTimeout: 30 * time.Second,
		AllowedAlgorithms: []string{
			"RS256", "RS384", "RS512",
			"ES256", "ES384", "ES512",
			"PS256", "PS384", "PS512",
			"EdDSA",
		},
		DeniedAlgorithms: []string{
			"none",
			"HS256", "HS384", "HS512",
		},
		JWKSRefreshInterval:    15 * time.Minute,
		JWKSMinRefreshInterval: 5 * time.Minute,
	}
}

// Option is a functional option for configuring the JWT client.
type Option func(*Options)

// WithLogger sets the logger for the client.
func WithLogger(l logger.Logger) Option {
	return func(o *Options) { o.Logger = l }
}

// WithJWKSURL sets the explicit JWKS URL.
func WithJWKSURL(url string) Option {
	return func(o *Options) { o.JWKSURL = url }
}

// WithOIDCDiscoveryURL sets the OIDC discovery URL.
func WithOIDCDiscoveryURL(url string) Option {
	return func(o *Options) { o.OIDCDiscoveryURL = url }
}

// WithPublicKeyFile sets the static public key file path.
func WithPublicKeyFile(path string) Option {
	return func(o *Options) { o.PublicKeyFile = path }
}

// WithCACertFile sets the CA certificate file for TLS verification.
func WithCACertFile(path string) Option {
	return func(o *Options) { o.CACertFile = path }
}

// WithHTTPTimeout sets the HTTP timeout for JWKS/OIDC requests.
func WithHTTPTimeout(d time.Duration) Option {
	return func(o *Options) { o.HTTPTimeout = d }
}

// WithAllowInsecure allows insecure TLS connections.
func WithAllowInsecure(allow bool) Option {
	return func(o *Options) { o.AllowInsecure = allow }
}

// WithAllowedAlgorithms sets the allowed JWT algorithms.
func WithAllowedAlgorithms(algorithms []string) Option {
	return func(o *Options) { o.AllowedAlgorithms = algorithms }
}

// WithDeniedAlgorithms sets the denied JWT algorithms.
func WithDeniedAlgorithms(algorithms []string) Option {
	return func(o *Options) { o.DeniedAlgorithms = algorithms }
}

// WithJWKSRefreshInterval sets the JWKS cache refresh interval.
func WithJWKSRefreshInterval(d time.Duration) Option {
	return func(o *Options) { o.JWKSRefreshInterval = d }
}

// WithJWKSMinRefreshInterval sets the minimum JWKS cache refresh interval.
func WithJWKSMinRefreshInterval(d time.Duration) Option {
	return func(o *Options) { o.JWKSMinRefreshInterval = d }
}
