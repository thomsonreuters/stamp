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

// Package transport provides configurable HTTP client construction with TLS support.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Options configures the HTTP client.
type Options struct {
	Timeout       time.Duration
	AllowInsecure bool
	CACertFile    string
}

// NewHTTPClient creates an *http.Client with the given TLS and timeout settings.
// If CACertFile is empty, the system root CA pool is used.
// If AllowInsecure is true, TLS certificate verification is skipped.
func NewHTTPClient(opts Options) (*http.Client, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: opts.AllowInsecure, //nolint:gosec // User-configured option
	}

	if opts.CACertFile != "" {
		caCert, err := os.ReadFile(opts.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert file %s: %w", opts.CACertFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert from %s", opts.CACertFile)
		}
		tlsConfig.RootCAs = pool
	}

	return &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}
