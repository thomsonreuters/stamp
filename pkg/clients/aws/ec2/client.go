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

// Package ec2 provides a comprehensive AWS EC2 metadata client.
// This client retrieves EC2 instance metadata using the Instance Metadata Service (IMDS),
// supporting both IMDSv1 (legacy) and IMDSv2 (token-based) with automatic version detection,
// retry logic, and comprehensive error handling.
package ec2

import (
	"context"
	"time"

	"github.com/thomsonreuters/stamp/pkg/logger"
)

const (
	// DefaultIMDSEndpoint is the standard AWS IMDS endpoint.
	DefaultIMDSEndpoint = "http://169.254.169.254"

	// DefaultIMDSTimeout is the default IMDS request timeout.
	DefaultIMDSTimeout = 10 * time.Second

	// DefaultIMDSMaxRetries is the default number of IMDS retry attempts.
	DefaultIMDSMaxRetries = 3

	// DefaultIMDSRetryDelay is the default delay between IMDS retries.
	DefaultIMDSRetryDelay = 1 * time.Second

	// DefaultIMDSv2TokenTTL is the default IMDSv2 token TTL in seconds.
	DefaultIMDSv2TokenTTL = 60

	// IMDSAccessibilityCheckTimeout is the timeout for quick IMDS accessibility checks.
	IMDSAccessibilityCheckTimeout = 5 * time.Second

	// IMDSAPIVersion is the IMDS API version to use.
	IMDSAPIVersion = "latest"

	// IMDSv2TokenHeader is the IMDSv2 token header name.
	IMDSv2TokenHeader = "X-aws-ec2-metadata-token" //nolint:gosec // G101: This is a well-known AWS header name, not a credential

	// IMDSv2TokenTTLHeader is the IMDSv2 token TTL header name.
	IMDSv2TokenTTLHeader = "X-aws-ec2-metadata-token-ttl-seconds" //nolint:gosec // G101: Well-known AWS header name, not a credential
)

// IMDSVersion represents the IMDS protocol version.
type IMDSVersion string

func (v IMDSVersion) String() string {
	return string(v)
}

const (
	// IMDSVersionAuto automatically detects and uses the appropriate IMDS version.
	IMDSVersionAuto IMDSVersion = "auto"

	// IMDSVersionV1 uses IMDSv1 (legacy, no token required).
	IMDSVersionV1 IMDSVersion = "v1"

	// IMDSVersionV2 uses IMDSv2 (token-based, recommended).
	IMDSVersionV2 IMDSVersion = "v2"
)

// ClientInterface defines the interface for EC2 client operations.
// This interface allows for easy mocking and testing of components that depend on the EC2 client.
type ClientInterface interface {
	// GetIMDSMetadata retrieves metadata from the specified IMDS path.
	GetIMDSMetadata(ctx context.Context, path string, opts *IMDSOptions) (string, error)

	// CheckIMDSAccessibility verifies that the IMDS endpoint is accessible.
	CheckIMDSAccessibility(ctx context.Context, opts *IMDSOptions) error

	// GetInstanceIdentityDocument retrieves and parses the instance identity document.
	GetInstanceIdentityDocument(ctx context.Context, opts *IMDSOptions) (*InstanceIdentityDocument, error)

	// GetMACAddress retrieves the primary network interface MAC address.
	GetMACAddress(ctx context.Context, opts *IMDSOptions) (string, error)

	// GetNetworkInfo retrieves comprehensive network information.
	GetNetworkInfo(ctx context.Context, opts *IMDSOptions) (*NetworkInfo, error)

	// GetIAMInfo retrieves IAM role information.
	GetIAMInfo(ctx context.Context, opts *IMDSOptions) (*IAMInfo, error)

	// GetInstanceLifecycle retrieves the instance lifecycle (e.g., "on-demand", "spot").
	GetInstanceLifecycle(ctx context.Context, opts *IMDSOptions) (string, error)

	// GetTagKeys retrieves the list of tag keys for the instance.
	GetTagKeys(ctx context.Context, opts *IMDSOptions) ([]string, error)

	// GetTag retrieves a specific tag value by key.
	GetTag(ctx context.Context, key string, opts *IMDSOptions) (string, error)

	// GetAllTags retrieves all tags for the instance.
	GetAllTags(ctx context.Context, opts *IMDSOptions) (map[string]string, error)

	// GetInstanceID retrieves the instance ID.
	GetInstanceID(ctx context.Context, opts *IMDSOptions) (string, error)

	// GetInstanceType retrieves the instance type.
	GetInstanceType(ctx context.Context, opts *IMDSOptions) (string, error)

	// GetRegion retrieves the region.
	GetRegion(ctx context.Context, opts *IMDSOptions) (string, error)

	// GetAvailabilityZone retrieves the availability zone.
	GetAvailabilityZone(ctx context.Context, opts *IMDSOptions) (string, error)
}

// Client represents an EC2 client that provides access to EC2 instance
// metadata and other EC2-related functionality. It supports retrieving
// instance metadata via IMDS (Instance Metadata Service) with both IMDSv1
// and IMDSv2 protocols.
type Client struct {
	logger            logger.Logger
	imdsv2Token       string
	imdsv2TokenExpiry time.Time
}

func newClient(log logger.Logger) ClientInterface {
	return &Client{
		logger: log.With("client", "aws:ec2"),
	}
}

// New creates a new EC2 client.
var New = newClient
