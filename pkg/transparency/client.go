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

// Package transparency provides higher-level transparency log operations built on top of the Rekor client.
package transparency

import (
	rekor "github.com/thomsonreuters/stamp/pkg/clients/rekor/v1"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// Client provides transparency log operations.
type Client struct {
	client  rekor.ClientIface
	baseURL string
}

// NewClient creates a new transparency client with logging.
func NewClient(baseURL string, insecure bool, log logger.Logger) (*Client, error) {
	if baseURL == "" {
		baseURL = rekor.DefaultRekorURL
	}
	client, err := rekor.New(rekor.Options{
		URL:      baseURL,
		Insecure: insecure,
		Logger:   log,
	})
	if err != nil {
		return nil, err
	}
	return &Client{client: client, baseURL: baseURL}, nil
}
