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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	httpclient "github.com/thomsonreuters/stamp/pkg/http/client"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

// InstanceIdentityDocument represents the EC2 instance identity document.
type InstanceIdentityDocument struct {
	AccountID        string    `json:"accountId"`
	Architecture     string    `json:"architecture"`
	AvailabilityZone string    `json:"availabilityZone"`
	ImageID          string    `json:"imageId"`
	InstanceID       string    `json:"instanceId"`
	InstanceType     string    `json:"instanceType"`
	KernelID         string    `json:"kernelId"`
	PendingTime      time.Time `json:"pendingTime"`
	PrivateIP        string    `json:"privateIp"`
	RamdiskID        string    `json:"ramdiskId"`
	Region           string    `json:"region"`
	Version          string    `json:"version"`
}

// NetworkInfo contains network-related metadata.
type NetworkInfo struct {
	MACAddress     string
	VPCID          string
	SubnetID       string
	SecurityGroups []string
	PrivateIPv4    string
	PublicIPv4     string
	PublicIPv6     string
	LocalHostname  string
	PublicHostname string
}

// IAMInfo contains IAM role information.
type IAMInfo struct {
	Code            string
	LastUpdated     time.Time
	InstanceProfile string
}

func (c *Client) validateIMDSOptions(opts *IMDSOptions) (*IMDSOptions, error) {
	if opts == nil {
		opts = DefaultIMDSOptions()
	}

	if err := opts.Validate(); err != nil {
		return nil, err
	}

	opts.Endpoint = strings.TrimRight(opts.Endpoint, "/")

	return opts, nil
}

// GetIMDSMetadata retrieves metadata from the specified IMDS path.
// This is a low-level method for direct IMDS access. For common metadata,
// use the high-level methods like GetInstanceIdentityDocument(), GetNetworkInfo(), etc.
// If opts is nil, default options will be used.
func (c *Client) GetIMDSMetadata(ctx context.Context, path string, opts *IMDSOptions) (string, error) {
	validatedOpts, err := c.validateIMDSOptions(opts)
	if err != nil {
		return "", fmt.Errorf("invalid IMDS options: %w", err)
	}

	version := validatedOpts.Version
	if version == IMDSVersionAuto {
		version = IMDSVersionV2
	}

	switch version { //nolint:exhaustive // Default case handles all other versions including IMDSVersionAuto
	case IMDSVersionV2:
		return c.getIMDSv2(ctx, path, validatedOpts)
	case IMDSVersionV1:
		return c.getIMDSv1(ctx, path, validatedOpts)
	default:
		return "", fmt.Errorf("invalid IMDS version: %s", version)
	}
}

// CheckIMDSAccessibility verifies that the IMDS endpoint is accessible.
// This is useful for determining if the code is running on an EC2 instance.
// If opts is nil, default options will be used.
func (c *Client) CheckIMDSAccessibility(ctx context.Context, opts *IMDSOptions) error {
	validatedOpts, err := c.validateIMDSOptions(opts)
	if err != nil {
		return fmt.Errorf("invalid IMDS options: %w", err)
	}

	c.logger.DebugContext(ctx, "checking IMDS accessibility",
		"endpoint", validatedOpts.Endpoint)

	checkCtx, cancel := context.WithTimeout(ctx, IMDSAccessibilityCheckTimeout)
	defer cancel()

	httpClient := httpclient.New(c.logger).
		SetTimeout(validatedOpts.Timeout).
		SetBaseURL(validatedOpts.Endpoint)
	defer httpClient.Close()

	url := fmt.Sprintf("/%s/meta-data/instance-id", IMDSAPIVersion)

	resp, err := httpClient.R().
		SetContext(checkCtx).
		Head(url)

	if err != nil {
		c.logger.WarnContext(ctx, "IMDS endpoint not accessible",
			"error", err.Error())
		return fmt.Errorf("IMDS endpoint not accessible: %w", err)
	}

	defer func() { _ = resp.Close() }()

	c.logger.InfoContext(ctx, "IMDS endpoint accessible",
		"status_code", resp.StatusCode())

	return nil
}

// getIMDSv1 performs an IMDSv1 request.
func (c *Client) getIMDSv1(ctx context.Context, path string, opts *IMDSOptions) (string, error) {
	c.logger.DebugContext(ctx, "executing IMDSv1 request",
		"path", path)

	c.logger.WarnContext(ctx, "using legacy IMDSv1 (consider enabling IMDSv2 for enhanced security)",
		"path", path)

	url := fmt.Sprintf("/%s/meta-data/%s", IMDSAPIVersion, path)

	return c.executeIMDSRequest(ctx, url, opts, func(req *httpclient.Request) error {
		return nil
	})
}

// getIMDSv2 performs an IMDSv2 request.
func (c *Client) getIMDSv2(ctx context.Context, path string, opts *IMDSOptions) (string, error) {
	c.logger.DebugContext(ctx, "executing IMDSv2 request",
		"path", path)

	token, err := c.getIMDSv2Token(ctx, opts)
	if err != nil {
		if opts.Version == IMDSVersionAuto {
			c.logger.WarnContext(ctx, "IMDSv2 token acquisition failed, attempting fallback to IMDSv1",
				"error", err.Error())
			opts.Version = IMDSVersionV1
			return c.getIMDSv1(ctx, path, opts)
		}
		c.logger.ErrorContext(ctx, "IMDSv2 token acquisition failed",
			"error", err.Error())
		return "", fmt.Errorf("IMDSv2 token acquisition failed: %w", err)
	}

	url := fmt.Sprintf("/%s/meta-data/%s", IMDSAPIVersion, path)

	return c.executeIMDSRequest(ctx, url, opts, func(req *httpclient.Request) error {
		req.SetHeader(IMDSv2TokenHeader, token)
		return nil
	})
}

// getIMDSv2Token retrieves or refreshes the IMDSv2 session token.
func (c *Client) getIMDSv2Token(ctx context.Context, opts *IMDSOptions) (string, error) {
	// Return cached token if still valid
	if c.imdsv2Token != "" && time.Now().Before(c.imdsv2TokenExpiry) {
		return c.imdsv2Token, nil
	}

	c.logger.DebugContext(ctx, "acquiring IMDSv2 session token")

	httpClient := httpclient.New(c.logger).
		SetTimeout(opts.Timeout).
		SetBaseURL(opts.Endpoint)
	defer httpClient.Close()

	tokenURL := fmt.Sprintf("/%s/api/token", IMDSAPIVersion)

	resp, err := httpClient.R().
		SetContext(ctx).
		SetHeader(IMDSv2TokenTTLHeader, strconv.Itoa(opts.TokenTTL)).
		Put(tokenURL)

	if err != nil {
		c.logger.ErrorContext(ctx, "IMDSv2 token request failed",
			"error", err.Error())
		return "", fmt.Errorf("IMDSv2 token request failed: %w", err)
	}

	defer func() { _ = resp.Close() }()

	if !resp.IsSuccess() {
		body, _ := resp.String()
		c.logger.ErrorContext(ctx, "IMDSv2 token request returned error",
			"status_code", resp.StatusCode(),
			"response", body)
		return "", fmt.Errorf("IMDSv2 token request returned status %d: %s",
			resp.StatusCode(), body)
	}

	token, err := resp.String()
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to read token response",
			"error", err.Error())
		return "", fmt.Errorf("failed to read IMDSv2 token response: %w", err)
	}

	c.imdsv2Token = strings.TrimSpace(token)
	c.imdsv2TokenExpiry = time.Now().Add(time.Duration(opts.TokenTTL) * time.Second)

	c.logger.InfoContext(ctx, "IMDSv2 session token acquired successfully",
		"ttl", opts.TokenTTL)

	return c.imdsv2Token, nil
}

// executeIMDSRequest performs an IMDS HTTP request with retry logic.
func (c *Client) executeIMDSRequest(
	ctx context.Context,
	url string,
	opts *IMDSOptions,
	setupRequest func(*httpclient.Request) error,
) (string, error) {
	httpClient := httpclient.New(c.logger).
		SetTimeout(opts.Timeout).
		SetBaseURL(opts.Endpoint)
	defer httpClient.Close()

	var lastErr error

	for attempt := 0; attempt <= opts.MaxRetries; attempt++ {
		if attempt > 0 {
			c.logger.DebugContext(ctx, "retrying IMDS request",
				"attempt", attempt,
				"max_retries", opts.MaxRetries)
			time.Sleep(opts.RetryDelay)
		}

		req := httpClient.R().SetContext(ctx)

		if err := setupRequest(req); err != nil {
			lastErr = fmt.Errorf("failed to setup IMDS request: %w", err)
			continue
		}

		resp, err := req.Get(url)
		if err != nil {
			lastErr = fmt.Errorf("IMDS request failed: %w", err)
			continue
		}

		// Handle token expiration for IMDSv2
		if resp.StatusCode() == http.StatusUnauthorized && opts.Version == IMDSVersionV2 {
			_ = resp.Close()
			c.logger.WarnContext(ctx, "IMDSv2 token expired, refreshing token")
			c.imdsv2Token = ""
			c.imdsv2TokenExpiry = time.Time{}
			token, tokenErr := c.getIMDSv2Token(ctx, opts)
			if tokenErr != nil {
				lastErr = tokenErr
				continue
			}
			req.SetHeader(IMDSv2TokenHeader, token)
			continue
		}

		if !resp.IsSuccess() {
			body, _ := resp.String()
			_ = resp.Close()
			lastErr = fmt.Errorf("IMDS request returned status %d: %s",
				resp.StatusCode(), body)
			continue
		}

		body, err := resp.String()
		_ = resp.Close()

		if err != nil {
			lastErr = fmt.Errorf("failed to read IMDS response body: %w", err)
			continue
		}

		result := strings.TrimSpace(body)
		c.logger.DebugContext(ctx, "IMDS request completed successfully",
			"response_length", len(result))
		return result, nil
	}

	c.logger.ErrorContext(ctx, "IMDS request failed after retries",
		"attempts", opts.MaxRetries+1,
		"error", lastErr.Error())

	return "", lastErr
}

// GetInstanceIdentityDocument retrieves and parses the instance identity document.
// If opts is nil, default IMDS options will be used.
func (c *Client) GetInstanceIdentityDocument(ctx context.Context, opts *IMDSOptions) (*InstanceIdentityDocument, error) {
	validatedOpts, err := c.validateIMDSOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("invalid IMDS options: %w", err)
	}

	c.logger.DebugContext(ctx, "retrieving instance identity document")

	// For dynamic paths, use a different URL structure
	url := fmt.Sprintf("/%s/dynamic/instance-identity/document", IMDSAPIVersion)

	// Temporarily use direct request for dynamic path
	var result string
	var reqErr error

	version := validatedOpts.Version
	if version == IMDSVersionAuto {
		version = IMDSVersionV2
	}

	if version == IMDSVersionV2 { //nolint:nestif // IMDSv2 token handling requires nested error checks for proper fallback
		token, tokenErr := c.getIMDSv2Token(ctx, validatedOpts)
		if tokenErr != nil {
			if validatedOpts.Version == IMDSVersionAuto {
				c.logger.WarnContext(ctx, "IMDSv2 token acquisition failed, attempting fallback to IMDSv1",
					"error", tokenErr.Error())
				validatedOpts.Version = IMDSVersionV1
				version = IMDSVersionV1
			} else {
				return nil, fmt.Errorf("IMDSv2 token acquisition failed: %w", tokenErr)
			}
		} else {
			result, reqErr = c.executeIMDSRequest(ctx, url, validatedOpts, func(req *httpclient.Request) error {
				req.SetHeader(IMDSv2TokenHeader, token)
				return nil
			})
			if reqErr != nil {
				return nil, fmt.Errorf("failed to retrieve instance identity document: %w", reqErr)
			}
		}
	}

	if version == IMDSVersionV1 {
		result, reqErr = c.executeIMDSRequest(ctx, url, validatedOpts, func(req *httpclient.Request) error {
			return nil
		})
		if reqErr != nil {
			return nil, fmt.Errorf("failed to retrieve instance identity document: %w", reqErr)
		}
	}

	var doc InstanceIdentityDocument
	if err := json.Unmarshal([]byte(result), &doc); err != nil {
		return nil, fmt.Errorf("failed to parse instance identity document: %w", err)
	}

	c.logger.InfoContext(ctx, "instance identity document retrieved",
		"instance_id", doc.InstanceID,
		"region", doc.Region)

	return &doc, nil
}

// GetMACAddress retrieves the primary network interface MAC address.
// If opts is nil, default IMDS options will be used.
func (c *Client) GetMACAddress(ctx context.Context, opts *IMDSOptions) (string, error) {
	validatedOpts, err := c.validateIMDSOptions(opts)
	if err != nil {
		return "", fmt.Errorf("invalid IMDS options: %w", err)
	}

	c.logger.DebugContext(ctx, "retrieving MAC address")

	mac, err := c.GetIMDSMetadata(ctx, "mac", validatedOpts)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve MAC address: %w", err)
	}

	return strings.TrimSpace(mac), nil
}

// GetNetworkInfo retrieves comprehensive network information.
// If opts is nil, default IMDS options will be used.
func (c *Client) GetNetworkInfo(ctx context.Context, opts *IMDSOptions) (*NetworkInfo, error) {
	validatedOpts, err := c.validateIMDSOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("invalid IMDS options: %w", err)
	}

	c.logger.DebugContext(ctx, "retrieving network information")

	network := &NetworkInfo{}

	// Get MAC address first
	mac, err := c.GetMACAddress(ctx, validatedOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to get MAC address: %w", err)
	}
	network.MACAddress = mac

	// Get VPC ID
	if vpcID, err := c.GetIMDSMetadata(ctx, fmt.Sprintf("network/interfaces/macs/%s/vpc-id", mac), validatedOpts); err == nil {
		network.VPCID = strings.TrimSpace(vpcID)
	}

	// Get Subnet ID
	if subnetID, err := c.GetIMDSMetadata(ctx, fmt.Sprintf("network/interfaces/macs/%s/subnet-id", mac), validatedOpts); err == nil {
		network.SubnetID = strings.TrimSpace(subnetID)
	}

	// Get Security Groups
	if sgList, err := c.GetIMDSMetadata(ctx, fmt.Sprintf("network/interfaces/macs/%s/security-group-ids", mac), validatedOpts); err == nil {
		network.SecurityGroups = utils.ParseMultilineResponse(sgList)
	}

	// Get Private IPv4
	if privateIP, err := c.GetIMDSMetadata(ctx, "local-ipv4", validatedOpts); err == nil {
		network.PrivateIPv4 = strings.TrimSpace(privateIP)
	}

	// Get Public IPv4 (may not exist)
	if publicIP, err := c.GetIMDSMetadata(ctx, "public-ipv4", validatedOpts); err == nil {
		network.PublicIPv4 = strings.TrimSpace(publicIP)
	}

	// Get Public IPv6 (may not exist)
	if publicIPv6, err := c.GetIMDSMetadata(ctx, fmt.Sprintf("network/interfaces/macs/%s/ipv6s", mac), validatedOpts); err == nil {
		network.PublicIPv6 = strings.TrimSpace(publicIPv6)
	}

	// Get Local Hostname
	if localHostname, err := c.GetIMDSMetadata(ctx, "local-hostname", validatedOpts); err == nil {
		network.LocalHostname = strings.TrimSpace(localHostname)
	}

	// Get Public Hostname
	if publicHostname, err := c.GetIMDSMetadata(ctx, "public-hostname", validatedOpts); err == nil {
		network.PublicHostname = strings.TrimSpace(publicHostname)
	}

	c.logger.InfoContext(ctx, "network information retrieved",
		"vpc_id", network.VPCID,
		"subnet_id", network.SubnetID,
		"security_groups_count", len(network.SecurityGroups))

	return network, nil
}

// GetIAMInfo retrieves IAM role information.
// If opts is nil, default IMDS options will be used.
func (c *Client) GetIAMInfo(ctx context.Context, opts *IMDSOptions) (*IAMInfo, error) {
	validatedOpts, err := c.validateIMDSOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("invalid IMDS options: %w", err)
	}

	c.logger.DebugContext(ctx, "retrieving IAM information")

	iamJSON, err := c.GetIMDSMetadata(ctx, "iam/info", validatedOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve IAM info: %w", err)
	}

	var iamData struct {
		Code               string    `json:"Code"`
		LastUpdated        time.Time `json:"LastUpdated"`
		InstanceProfileArn string    `json:"InstanceProfileArn"`
	}

	if err := json.Unmarshal([]byte(iamJSON), &iamData); err != nil {
		return nil, fmt.Errorf("failed to parse IAM info: %w", err)
	}

	iam := &IAMInfo{
		Code:            iamData.Code,
		LastUpdated:     iamData.LastUpdated,
		InstanceProfile: iamData.InstanceProfileArn,
	}

	c.logger.InfoContext(ctx, "IAM information retrieved",
		"instance_profile", iam.InstanceProfile,
		"code", iam.Code)

	return iam, nil
}

// GetInstanceLifecycle retrieves the instance lifecycle (e.g., "on-demand", "spot").
// If opts is nil, default IMDS options will be used.
func (c *Client) GetInstanceLifecycle(ctx context.Context, opts *IMDSOptions) (string, error) {
	validatedOpts, err := c.validateIMDSOptions(opts)
	if err != nil {
		return "", fmt.Errorf("invalid IMDS options: %w", err)
	}

	c.logger.DebugContext(ctx, "retrieving instance lifecycle")

	lifecycle, err := c.GetIMDSMetadata(ctx, "instance-life-cycle", validatedOpts)
	if err != nil {
		// Default to on-demand if not available
		c.logger.DebugContext(ctx, "lifecycle not available, assuming on-demand",
			"error", err.Error())
		return "on-demand", nil
	}

	result := strings.TrimSpace(lifecycle)
	c.logger.InfoContext(ctx, "instance lifecycle retrieved",
		"lifecycle", result)

	return result, nil
}

// GetTagKeys retrieves the list of tag keys for the instance.
// If opts is nil, default IMDS options will be used.
func (c *Client) GetTagKeys(ctx context.Context, opts *IMDSOptions) ([]string, error) {
	validatedOpts, err := c.validateIMDSOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("invalid IMDS options: %w", err)
	}

	c.logger.DebugContext(ctx, "retrieving tag keys")

	tagsJSON, err := c.GetIMDSMetadata(ctx, "tags/instance", validatedOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve tag keys: %w", err)
	}

	keys := utils.ParseMultilineResponse(tagsJSON)

	c.logger.InfoContext(ctx, "tag keys retrieved",
		"count", len(keys))

	return keys, nil
}

// GetTag retrieves a specific tag value by key.
// If opts is nil, default IMDS options will be used.
func (c *Client) GetTag(ctx context.Context, key string, opts *IMDSOptions) (string, error) {
	validatedOpts, err := c.validateIMDSOptions(opts)
	if err != nil {
		return "", fmt.Errorf("invalid IMDS options: %w", err)
	}

	c.logger.DebugContext(ctx, "retrieving tag value",
		"key", key)

	value, err := c.GetIMDSMetadata(ctx, fmt.Sprintf("tags/instance/%s", key), validatedOpts)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve tag %s: %w", key, err)
	}

	result := strings.TrimSpace(value)
	c.logger.DebugContext(ctx, "tag value retrieved",
		"key", key,
		"value_length", len(result))

	return result, nil
}

// GetAllTags retrieves all tags for the instance.
// If opts is nil, default IMDS options will be used.
func (c *Client) GetAllTags(ctx context.Context, opts *IMDSOptions) (map[string]string, error) {
	validatedOpts, err := c.validateIMDSOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("invalid IMDS options: %w", err)
	}

	c.logger.DebugContext(ctx, "retrieving all tags")

	keys, err := c.GetTagKeys(ctx, validatedOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve tag keys: %w", err)
	}

	tags := make(map[string]string)
	for _, key := range keys {
		value, err := c.GetTag(ctx, key, validatedOpts)
		if err != nil {
			c.logger.WarnContext(ctx, "failed to retrieve tag value",
				"key", key,
				"error", err.Error())
			continue
		}
		tags[key] = value
	}

	c.logger.InfoContext(ctx, "all tags retrieved",
		"count", len(tags))

	return tags, nil
}

// GetInstanceID retrieves the instance ID.
// If opts is nil, default IMDS options will be used.
func (c *Client) GetInstanceID(ctx context.Context, opts *IMDSOptions) (string, error) {
	validatedOpts, err := c.validateIMDSOptions(opts)
	if err != nil {
		return "", fmt.Errorf("invalid IMDS options: %w", err)
	}

	instanceID, err := c.GetIMDSMetadata(ctx, "instance-id", validatedOpts)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve instance ID: %w", err)
	}
	return strings.TrimSpace(instanceID), nil
}

// GetInstanceType retrieves the instance type.
// If opts is nil, default IMDS options will be used.
func (c *Client) GetInstanceType(ctx context.Context, opts *IMDSOptions) (string, error) {
	validatedOpts, err := c.validateIMDSOptions(opts)
	if err != nil {
		return "", fmt.Errorf("invalid IMDS options: %w", err)
	}

	instanceType, err := c.GetIMDSMetadata(ctx, "instance-type", validatedOpts)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve instance type: %w", err)
	}
	return strings.TrimSpace(instanceType), nil
}

// GetRegion retrieves the region.
// If opts is nil, default IMDS options will be used.
func (c *Client) GetRegion(ctx context.Context, opts *IMDSOptions) (string, error) {
	validatedOpts, err := c.validateIMDSOptions(opts)
	if err != nil {
		return "", fmt.Errorf("invalid IMDS options: %w", err)
	}

	region, err := c.GetIMDSMetadata(ctx, "placement/region", validatedOpts)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve region: %w", err)
	}
	return strings.TrimSpace(region), nil
}

// GetAvailabilityZone retrieves the availability zone.
// If opts is nil, default IMDS options will be used.
func (c *Client) GetAvailabilityZone(ctx context.Context, opts *IMDSOptions) (string, error) {
	validatedOpts, err := c.validateIMDSOptions(opts)
	if err != nil {
		return "", fmt.Errorf("invalid IMDS options: %w", err)
	}

	az, err := c.GetIMDSMetadata(ctx, "placement/availability-zone", validatedOpts)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve availability zone: %w", err)
	}
	return strings.TrimSpace(az), nil
}
