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

// Package k8s provides a client for reading Kubernetes service account tokens.
package k8s

import (
	"context"
	"os"
	"strings"

	"github.com/thomsonreuters/stamp/pkg/logger"
)

const (
	DefaultTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // G101: This is a well-known path, not a credential
)

type ClientIface interface {
	FetchToken(ctx context.Context) (string, error)
	IsServiceAccountAvailable() bool
	GetTokenPath() string
}

type Client struct {
	logger    logger.Logger
	tokenPath string
}

type Options struct {
	Logger    logger.Logger
	TokenPath string
}

func (c *Client) FetchToken(ctx context.Context) (string, error) {
	if _, err := os.Stat(c.tokenPath); os.IsNotExist(err) {
		return "", ErrTokenFileNotFound
	}

	tokenBytes, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return "", ErrTokenReadFailed
	}

	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return "", ErrTokenFileEmpty
	}

	return token, nil
}

func (c *Client) IsServiceAccountAvailable() bool {
	return IsServiceAccountEnvAvailable()
}

func (c *Client) GetTokenPath() string {
	return c.tokenPath
}

func IsServiceAccountEnvAvailable() bool {
	if _, err := os.Stat(DefaultTokenPath); err == nil {
		return true
	}
	return false
}

func GetTokenFilePath() string {
	return DefaultTokenPath
}

func newClient(ctx context.Context, opts Options) (ClientIface, error) {
	if opts.Logger == nil {
		opts.Logger = logger.NewNoop()
	}

	tokenPath := opts.TokenPath
	if tokenPath == "" {
		tokenPath = GetTokenFilePath()
	}

	return &Client{
		logger:    opts.Logger.With("client", "k8s"),
		tokenPath: tokenPath,
	}, nil
}

var New = newClient
