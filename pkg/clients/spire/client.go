// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package spire

import (
	"context"
	"os"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

// SocketPathEnvVar is the environment variable name for the SPIRE agent socket path.
const SocketPathEnvVar = workloadapi.SocketEnv

// WorkloadAPIClient abstracts the go-spiffe workloadapi.Client for testing.
type WorkloadAPIClient interface {
	FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error)
	Close() error
}

// ClientIface defines the interface for the SPIRE client.
type ClientIface interface {
	FetchJWTToken(ctx context.Context, audience string) (string, error)
	Close() error
}

// Client is the SPIRE client that fetches JWT tokens.
type Client struct {
	workloadAPIClient WorkloadAPIClient
	opts              Options
}

// GetSocketPath returns the SPIRE agent socket path.
// It checks the SPIFFE_ENDPOINT_SOCKET environment variable first,
// falling back to the OS-specific default if not set.
func GetSocketPath() string {
	if path := os.Getenv(SocketPathEnvVar); path != "" {
		return path
	}
	return defaultSocketPath
}

func (c *Client) initWorkloadAPIClient(ctx context.Context) error {
	if c.workloadAPIClient != nil {
		return nil
	}

	var err error
	c.workloadAPIClient, err = workloadapi.New(ctx, workloadapi.WithAddr(c.opts.SocketPath))
	return err
}

// FetchJWTToken fetches a JWT token for the specified audience.
func (c *Client) FetchJWTToken(ctx context.Context, audience string) (string, error) {
	if err := c.initWorkloadAPIClient(ctx); err != nil {
		return "", err
	}

	svid, err := c.workloadAPIClient.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: audience,
	})
	if err != nil {
		return "", err
	}
	return svid.Marshal(), nil
}

// Close closes the SPIRE client and releases resources.
func (c *Client) Close() error {
	if c.workloadAPIClient == nil {
		return nil
	}
	return c.workloadAPIClient.Close()
}

type Options struct {
	SocketPath string
}

func (o Options) Validate() error {
	return utils.ValidateSocketPath(o.SocketPath)
}

func newClient(ctx context.Context, options Options) (ClientIface, error) {
	if options.SocketPath == "" {
		options.SocketPath = GetSocketPath()
	}

	if err := options.Validate(); err != nil {
		return nil, err
	}

	return &Client{
		opts: options,
	}, nil
}

var New = newClient
