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

// Package ec2 provides validation and redaction utilities for EC2 instance attestation.
package ec2

import (
	"fmt"
	"strings"
	"time"

	awsec2 "github.com/thomsonreuters/stamp/pkg/clients/aws/ec2"
	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	ec2predicate "github.com/thomsonreuters/stamp/pkg/predicates/ec2/v1"
)

func (a *Attestor) ValidateConfig(config core.Config) error {
	a.logger.Debug("validating EC2 attestor configuration")

	if err := config.Validate(a.ConfigSchema()); err != nil {
		a.logger.Error("configuration schema validation failed", "error", err.Error())
		return err
	}

	if version, ok := config["imds-version"].(string); ok && version != "" {
		validVersions := map[string]bool{"v1": true, "v2": true, "auto": true}
		if !validVersions[version] {
			err := fmt.Errorf("invalid imds-version '%s': must be 'v1', 'v2', or 'auto'", version)
			a.logger.Error("invalid imds-version configuration", "imds_version", version)
			return pkgerrors.NewWithContext("ec2_attestor", "validate", err.Error())
		}
		a.logger.Debug("imds-version validation passed", "imds_version", version)
	}

	if behavior, ok := config["not-ec2-behavior"].(string); ok && behavior != "" {
		validBehaviors := map[string]bool{"fail": true, "warn": true, "skip": true}
		if !validBehaviors[behavior] {
			err := fmt.Errorf("invalid not-ec2-behavior '%s': must be 'fail', 'warn', or 'skip'", behavior)
			a.logger.Error("invalid not-ec2-behavior configuration", "not_ec2_behavior", behavior)
			return pkgerrors.NewWithContext("ec2_attestor", "validate", err.Error())
		}
		a.logger.Debug("not-ec2-behavior validation passed", "not_ec2_behavior", behavior)
	}

	if behavior, ok := config["imds-unavailable-behavior"].(string); ok && behavior != "" {
		validBehaviors := map[string]bool{"fail": true, "warn": true}
		if !validBehaviors[behavior] {
			err := fmt.Errorf("invalid imds-unavailable-behavior '%s': must be 'fail' or 'warn'", behavior)
			a.logger.Error("invalid imds-unavailable-behavior configuration", "imds_unavailable_behavior", behavior)
			return pkgerrors.NewWithContext("ec2_attestor", "validate", err.Error())
		}
		a.logger.Debug("imds-unavailable-behavior validation passed", "imds_unavailable_behavior", behavior)
	}

	tokenTTL := config.GetInt("token-ttl", awsec2.DefaultIMDSv2TokenTTL)
	if tokenTTL < 1 || tokenTTL > 21600 {
		err := fmt.Errorf("invalid token-ttl %d: must be between 1 and 21600 seconds", tokenTTL)
		a.logger.Error("invalid token-ttl configuration", "token_ttl", tokenTTL)
		return pkgerrors.NewWithContext("ec2_attestor", "validate", err.Error())
	}
	a.logger.Debug("token-ttl validation passed", "token_ttl", tokenTTL)

	maxRetries := config.GetInt("max-retries", awsec2.DefaultIMDSMaxRetries)
	if maxRetries < 0 {
		err := fmt.Errorf("invalid max-retries %d: must be >= 0", maxRetries)
		a.logger.Error("invalid max-retries configuration", "max_retries", maxRetries)
		return pkgerrors.NewWithContext("ec2_attestor", "validate", err.Error())
	}
	a.logger.Debug("max-retries validation passed", "max_retries", maxRetries)

	if timeoutStr, ok := config["timeout"].(string); ok && timeoutStr != "" {
		if _, err := time.ParseDuration(timeoutStr); err != nil {
			a.logger.Error("invalid timeout duration format", "timeout", timeoutStr, "error", err.Error())
			return pkgerrors.WrapWithContext(err, "ec2_attestor", "validate",
				fmt.Sprintf("invalid timeout duration '%s': must be valid Go duration (e.g., '10s', '1m')", timeoutStr))
		}
		a.logger.Debug("timeout validation passed", "timeout", timeoutStr)
	}

	if retryDelayStr, ok := config["retry-delay"].(string); ok && retryDelayStr != "" {
		if _, err := time.ParseDuration(retryDelayStr); err != nil {
			a.logger.Error("invalid retry-delay duration format", "retry_delay", retryDelayStr, "error", err.Error())
			return pkgerrors.WrapWithContext(err, "ec2_attestor", "validate",
				fmt.Sprintf("invalid retry-delay duration '%s': must be valid Go duration (e.g., '1s', '500ms')", retryDelayStr))
		}
		a.logger.Debug("retry-delay validation passed", "retry_delay", retryDelayStr)
	}

	if endpoint, ok := config["imds-endpoint"].(string); ok && endpoint != "" {
		// Basic URL validation - must start with http:// or https://
		if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
			err := fmt.Errorf("invalid imds-endpoint '%s': must be a valid HTTP(S) URL", endpoint)
			a.logger.Error("invalid imds-endpoint URL format", "imds_endpoint", endpoint)
			return pkgerrors.NewWithContext("ec2_attestor", "validate", err.Error())
		}
		a.logger.Debug("imds-endpoint validation passed", "imds_endpoint", endpoint)
	}

	a.logger.Debug("EC2 attestor configuration validation completed")
	return nil
}

// redactSensitiveFields applies granular field-level redaction to the EC2 predicate
// based on the configured sensitive-fields list. See package documentation for
// supported field paths.
func (a *Attestor) redactSensitiveFields(predicate ec2predicate.Predicate, fields []string) ec2predicate.Predicate {
	for _, fieldStr := range fields {
		switch fieldStr {
		// Account ID redaction
		case "accountId", "identityDocument.accountId":
			predicate.Environment.IdentityDocument.AccountID = "[REDACTED]"

		// Private IP redaction
		case "privateIp", "identityDocument.privateIp":
			predicate.Environment.IdentityDocument.PrivateIP = "[REDACTED]"

		// Network - Private IPv4
		case "network.privateIpv4", "privateIpv4":
			predicate.Environment.Network.PrivateIPv4 = "[REDACTED]"

		// Network - Public IPv4
		case "network.publicIpv4", "publicIpv4":
			predicate.Environment.Network.PublicIPv4 = "[REDACTED]"

		// Network - Public IPv6
		case "network.publicIpv6", "publicIpv6":
			predicate.Environment.Network.PublicIPv6 = "[REDACTED]"

		// Network - VPC ID
		case "network.vpcId", "vpcId":
			predicate.Environment.Network.VPCID = "[REDACTED]"

		// Network - Subnet ID
		case "network.subnetId", "subnetId":
			predicate.Environment.Network.SubnetID = "[REDACTED]"

		// Network - Security Groups
		case "network.securityGroups", "securityGroups":
			predicate.Environment.Network.SecurityGroups = []string{"[REDACTED]"}

		// Network - MAC Address
		case "network.macAddress", "macAddress":
			predicate.Environment.Network.MACAddress = "[REDACTED]"

		// Network - Local Hostname
		case "network.localHostname", "localHostname":
			predicate.Environment.Network.LocalHostname = "[REDACTED]"

		// Network - Public Hostname
		case "network.publicHostname", "publicHostname":
			predicate.Environment.Network.PublicHostname = "[REDACTED]"

		// IAM - Complete information
		case "iam":
			predicate.Environment.IAM = &ec2predicate.IAMInfo{
				Code:            "[REDACTED]",
				InstanceProfile: "[REDACTED]",
			}

		// IAM - Instance Profile
		case "iam.instanceProfile", "instanceProfile":
			if predicate.Environment.IAM != nil {
				predicate.Environment.IAM.InstanceProfile = "[REDACTED]"
			}

		// Tags - All instance tags
		case "tags":
			predicate.Environment.Tags = map[string]string{"redacted": "[REDACTED]"}

		// Instance ID
		case "instanceId", "identityDocument.instanceId":
			predicate.Environment.IdentityDocument.InstanceID = "[REDACTED]"

		// Image ID
		case "imageId", "identityDocument.imageId":
			predicate.Environment.IdentityDocument.ImageID = "[REDACTED]"

		// Instance Type
		case "instanceType", "identityDocument.instanceType":
			predicate.Environment.IdentityDocument.InstanceType = "[REDACTED]"

		// Availability Zone
		case "availabilityZone", "identityDocument.availabilityZone":
			predicate.Environment.IdentityDocument.AvailabilityZone = "[REDACTED]"

		// Region
		case "region", "identityDocument.region":
			predicate.Environment.IdentityDocument.Region = "[REDACTED]"

		// Architecture
		case "architecture", "identityDocument.architecture":
			predicate.Environment.IdentityDocument.Architecture = "[REDACTED]"

		// Kernel ID
		case "kernelId", "identityDocument.kernelId":
			predicate.Environment.IdentityDocument.KernelID = "[REDACTED]"

		// Ramdisk ID
		case "ramdiskId", "identityDocument.ramdiskId":
			predicate.Environment.IdentityDocument.RamdiskID = "[REDACTED]"

		// Instance Lifecycle
		case "instanceLifecycle", "lifecycle":
			predicate.Environment.InstanceLifecycle = "[REDACTED]"

		// IMDS endpoint
		case "imds.endpoint", "imdsEndpoint":
			predicate.Verification.IMDS.Endpoint = "[REDACTED]"
		}
	}

	return predicate
}
