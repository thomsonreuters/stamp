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

// Package ec2 provides AWS EC2 instance attestation for generating EC2-specific
// attestation predicates. It collects instance identity metadata from the AWS
// Instance Metadata Service (IMDS) including instance ID, type, AMI, region,
// network configuration, and optional IAM role information.
//
// The attestor uses a custom predicate type (https://github.com/thomsonreuters/stamp/ec2/v1)
// specifically designed for runtime environment attestations, NOT SLSA build provenance.
//
// The attestor supports both IMDSv1 and IMDSv2 with automatic version detection
// and fallback capabilities. IMDSv2 is recommended for enhanced security against
// SSRF attacks through token-based authentication.
//
// Key features:
//   - Instance identity document collection with cryptographic verification
//   - Support for both IMDSv1 (legacy) and IMDSv2 (token-based, recommended)
//   - Automatic IMDS version detection with configurable fallback behavior
//   - Network metadata including VPC, subnet, and security group information
//   - Optional IAM role and instance tag collection
//   - Configurable timeout and retry logic for reliability
//   - Fine-grained redaction for sensitive data (account ID, IPs, VPC details)
//   - Graceful handling of non-EC2 environments and IMDS unavailability
package ec2

import (
	"context"
	"time"

	"github.com/invopop/jsonschema"
	awsec2 "github.com/thomsonreuters/stamp/pkg/clients/aws/ec2"
	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/logger"
	ec2predicate "github.com/thomsonreuters/stamp/pkg/predicates/ec2/v1"
)

const (
	id          = "ec2"
	name        = "EC2 Attestor"
	description = "Generates EC2 runtime environment attestation from AWS EC2 instance metadata"
)

func init() {
	// Auto-register this attestor with custom EC2 predicate URI
	_ = core.RegisterAttestor(func(log logger.Logger) core.Attestor {
		logger := log.With("attestor_id", id)
		return &Attestor{
			logger: logger,
		}
	})
}

// Config holds parsed configuration values for the EC2 attestor.
type Config struct {
	// IMDS Configuration
	IMDSEndpoint string
	IMDSVersion  string
	Timeout      time.Duration
	TokenTTL     int
	MaxRetries   int
	RetryDelay   time.Duration
	IMDSOptions  *awsec2.IMDSOptions // Built from the above IMDS config fields

	// Collection Configuration
	IncludeNetwork bool
	IncludeIAM     bool
	IncludeTags    bool

	// Redaction Configuration
	RedactAccountID  bool
	RedactPrivateIPs bool
	SensitiveFields  []string

	// Behavior Configuration
	NotEC2Behavior          string
	IMDSUnavailableBehavior string
}

// Attestor implements the core.Attestor interface for AWS EC2 instance attestation.
// It collects instance metadata from the Instance Metadata Service (IMDS) and
// generates EC2 runtime environment attestations with instance identity information.
type Attestor struct {
	config   Config
	metadata ec2predicate.InstanceMetadata
	imdsInfo ec2predicate.IMDSInfo
	client   awsec2.ClientInterface
	logger   logger.Logger
}

func (a *Attestor) ID() string {
	return id
}

func (a *Attestor) PredicateURI() string {
	return ec2predicate.PredicateURI
}

func (a *Attestor) Name() string {
	return name
}

func (a *Attestor) Description() string {
	return description
}

func (a *Attestor) ConfigSchema() []core.ConfigField {
	return []core.ConfigField{
		{
			Name:        "imds-version",
			Type:        "string",
			Default:     "v2",
			Required:    false,
			Description: "IMDS version to use: 'v2' (token-based, recommended), 'v1' (legacy), 'auto' (try v2 first, fallback to v1)",
			Example:     "v2",
		},
		{
			Name:        "imds-endpoint",
			Type:        "string",
			Default:     "http://169.254.169.254",
			Required:    false,
			Description: "IMDS endpoint URL (useful for testing or custom setups)",
			Example:     "http://169.254.169.254",
		},
		{
			Name:        "timeout",
			Type:        "duration",
			Default:     "10s",
			Required:    false,
			Description: "Timeout for IMDS requests (increase for slow networks)",
			Example:     "30s",
		},
		{
			Name:        "token-ttl",
			Type:        "int",
			Default:     awsec2.DefaultIMDSv2TokenTTL,
			Required:    false,
			Description: "IMDSv2 token TTL in seconds (1-21600)",
			Example:     120,
		},
		{
			Name:        "include-network-details",
			Type:        "bool",
			Default:     true,
			Required:    false,
			Description: "Collect additional network information (public IP, VPC ID, subnet, etc.)",
			Example:     false,
		},
		{
			Name:        "include-iam-info",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Collect IAM role information (may be sensitive)",
			Example:     true,
		},
		{
			Name:        "include-tags",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Collect instance tags (requires IAM permissions)",
			Example:     true,
		},
		{
			Name:        "not-ec2-behavior",
			Type:        "string",
			Default:     "fail",
			Required:    false,
			Description: "How to handle non-EC2 environment: 'fail' (error), 'warn' (log warning and skip), 'skip' (silently skip)",
			Example:     "warn",
		},
		{
			Name:        "imds-unavailable-behavior",
			Type:        "string",
			Default:     "fail",
			Required:    false,
			Description: "How to handle IMDS unavailable: 'fail' (error), 'warn' (log warning and use partial data)",
			Example:     "warn",
		},
		{
			Name:        "redact-account-id",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Redact AWS account ID from attestation",
			Example:     true,
		},
		{
			Name:        "redact-private-ips",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Redact private IP addresses from attestation",
			Example:     true,
		},
		{
			Name:        "sensitive-fields",
			Type:        "[]string",
			Default:     []string{},
			Required:    false,
			Description: "Additional fields to redact (e.g., 'accountId', 'privateIp', 'vpcId', 'tags')",
			Example:     []string{"accountId", "vpcId"},
		},
		{
			Name:        "max-retries",
			Type:        "int",
			Default:     awsec2.DefaultIMDSMaxRetries,
			Required:    false,
			Description: "Maximum retry attempts for IMDS requests",
			Example:     5,
		},
		{
			Name:        "retry-delay",
			Type:        "duration",
			Default:     "1s",
			Required:    false,
			Description: "Delay between retry attempts",
			Example:     "2s",
		},
	}
}

func (a *Attestor) PreAttest(ctx context.Context, config core.Config) error {
	start := time.Now()
	a.logger.InfoContext(ctx, "starting EC2 attestor pre-attestation setup")

	a.client = awsec2.New(a.logger)
	a.logger.DebugContext(ctx, "EC2 client initialized")

	a.parseConfig(config)
	a.logger.DebugContext(ctx, "IMDS options configured",
		"endpoint", a.config.IMDSOptions.Endpoint,
		"version", a.config.IMDSOptions.Version)

	a.logger.DebugContext(ctx, "checking IMDS accessibility")
	if err := a.client.CheckIMDSAccessibility(ctx, a.config.IMDSOptions); err != nil {
		a.logger.WarnContext(ctx, "IMDS not accessible", "error", err.Error())
		a.imdsInfo.Accessible = false

		switch a.config.NotEC2Behavior {
		case "fail":
			a.logger.ErrorContext(ctx, "IMDS accessibility check failed", "error", err.Error())
			return pkgerrors.WrapWithContext(err, "ec2_attestor", "validate",
				"IMDS endpoint not accessible - not running on EC2 instance")
		case "warn":
			a.logger.WarnContext(ctx, "IMDS endpoint not accessible (non-EC2 environment)", "behavior", "warn")
		case "skip":
			a.logger.DebugContext(ctx, "IMDS not accessible, silently skipping")
		}
	} else {
		a.imdsInfo.Accessible = true
		a.imdsInfo.Endpoint = a.config.IMDSOptions.Endpoint
		a.imdsInfo.Version = a.config.IMDSOptions.Version.String()
	}

	if !a.imdsInfo.Accessible {
		a.logger.WarnContext(ctx, "IMDS not accessible, continuing with limited data")
	}

	a.logger.InfoContext(ctx, "EC2 attestor pre-attestation setup completed",
		"imds_endpoint", a.config.IMDSOptions.Endpoint,
		"imds_version", a.config.IMDSOptions.Version,
		"imds_accessible", a.imdsInfo.Accessible,
		"duration_ms", time.Since(start).Milliseconds())
	return nil
}

func (a *Attestor) parseConfig(config core.Config) {
	// Parse IMDS configuration with defaults
	defaults := awsec2.DefaultIMDSOptions()

	// Parse all config fields including both individual IMDS fields and built options
	a.config = Config{
		// IMDS Configuration
		IMDSEndpoint: config.GetString("imds-endpoint", defaults.Endpoint),
		IMDSVersion:  config.GetString("imds-version", defaults.Version.String()),
		Timeout:      config.GetDuration("timeout", defaults.Timeout),
		TokenTTL:     config.GetInt("token-ttl", defaults.TokenTTL),
		MaxRetries:   config.GetInt("max-retries", defaults.MaxRetries),
		RetryDelay:   config.GetDuration("retry-delay", defaults.RetryDelay),

		// Collection Configuration
		IncludeNetwork: config.GetBool("include-network-details", true),
		IncludeIAM:     config.GetBool("include-iam-info", false),
		IncludeTags:    config.GetBool("include-tags", false),

		// Redaction Configuration
		RedactAccountID:  config.GetBool("redact-account-id", false),
		RedactPrivateIPs: config.GetBool("redact-private-ips", false),
		SensitiveFields:  config.GetStringSlice("sensitive-fields"),

		// Behavior Configuration
		NotEC2Behavior:          config.GetString("not-ec2-behavior", "fail"),
		IMDSUnavailableBehavior: config.GetString("imds-unavailable-behavior", "fail"),
	}

	a.config.IMDSOptions = &awsec2.IMDSOptions{
		Endpoint:   a.config.IMDSEndpoint,
		Version:    awsec2.IMDSVersion(a.config.IMDSVersion),
		Timeout:    a.config.Timeout,
		TokenTTL:   a.config.TokenTTL,
		MaxRetries: a.config.MaxRetries,
		RetryDelay: a.config.RetryDelay,
	}
}

func (a *Attestor) Attest(ctx context.Context, config core.Config) error {
	start := time.Now()
	a.logger.InfoContext(ctx, "starting EC2 attestation collection")

	// Ensure config is parsed (may not be if PreAttest wasn't called)
	if a.config.IMDSOptions == nil {
		a.parseConfig(config)
	}

	if !a.imdsInfo.Accessible {
		if a.config.NotEC2Behavior == "skip" {
			a.logger.DebugContext(ctx, "IMDS not accessible and not-ec2-behavior=skip, skipping attestation collection")
			return nil
		}

		if a.config.IMDSUnavailableBehavior == "fail" {
			err := pkgerrors.NewWithContext("ec2_attestor", "collect", "IMDS not accessible, cannot collect instance metadata")
			a.logger.ErrorContext(ctx, "IMDS unavailable", "behavior", a.config.IMDSUnavailableBehavior)
			return err
		}

		a.logger.WarnContext(ctx, "IMDS unavailable, generating partial attestation", "behavior", a.config.IMDSUnavailableBehavior)
		return nil
	}

	if err := a.collectInstanceMetadata(ctx); err != nil {
		a.logger.ErrorContext(ctx, "failed to collect instance metadata", "error", err.Error())
		return err
	}

	a.logger.InfoContext(ctx, "EC2 attestation collection completed",
		"instance_id", a.metadata.IdentityDocument.InstanceID,
		"instance_type", a.metadata.IdentityDocument.InstanceType,
		"region", a.metadata.IdentityDocument.Region,
		"account_id", a.metadata.IdentityDocument.AccountID,
		"availability_zone", a.metadata.IdentityDocument.AvailabilityZone,
		"duration_ms", time.Since(start).Milliseconds())
	return nil
}

func (a *Attestor) PostAttest(ctx context.Context, config core.Config) error {
	return nil
}

func (a *Attestor) Schema() *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		AllowAdditionalProperties:  false,
		RequiredFromJSONSchemaTags: true,
	}

	schema := reflector.Reflect(&ec2predicate.Predicate{})
	schema.Title = "EC2 Runtime Environment Attestation"
	schema.Description = "AWS EC2 instance metadata collected from IMDS for runtime attestation"

	return schema
}

func (a *Attestor) collectInstanceMetadata(ctx context.Context) error {
	start := time.Now()
	a.logger.InfoContext(ctx, "collecting EC2 instance metadata")

	// Collect instance identity document
	a.logger.DebugContext(ctx, "collecting instance identity document")

	doc, err := a.client.GetInstanceIdentityDocument(ctx, a.config.IMDSOptions)
	if err != nil {
		a.logger.ErrorContext(ctx, "failed to retrieve instance identity document", "error", err.Error())
		return pkgerrors.WrapWithContext(err, "ec2_attestor", "collect",
			"failed to retrieve instance identity document from IMDS")
	}

	a.metadata.IdentityDocument = ec2predicate.InstanceIdentityDocument{
		AccountID:        doc.AccountID,
		Architecture:     doc.Architecture,
		AvailabilityZone: doc.AvailabilityZone,
		ImageID:          doc.ImageID,
		InstanceID:       doc.InstanceID,
		InstanceType:     doc.InstanceType,
		KernelID:         doc.KernelID,
		PendingTime:      doc.PendingTime,
		PrivateIP:        doc.PrivateIP,
		RamdiskID:        doc.RamdiskID,
		Region:           doc.Region,
		Version:          doc.Version,
	}

	a.logger.InfoContext(ctx, "instance identity document collected",
		"instance_id", doc.InstanceID,
		"instance_type", doc.InstanceType,
		"image_id", doc.ImageID,
		"region", doc.Region,
		"availability_zone", doc.AvailabilityZone,
		"account_id", doc.AccountID,
		"architecture", doc.Architecture)

	// Collect additional metadata based on configuration
	if a.config.IncludeNetwork {
		if err := a.collectNetworkInfo(ctx, a.config.IMDSOptions); err != nil {
			a.logger.WarnContext(ctx, "failed to collect network info", "error", err.Error())
		}
	} else {
		a.logger.InfoContext(ctx, "network information collection skipped (include-network-details=false)")
	}

	if a.config.IncludeIAM {
		if err := a.collectIAMInfo(ctx, a.config.IMDSOptions); err != nil {
			a.logger.WarnContext(ctx, "failed to collect IAM info", "error", err.Error())
		}
	} else {
		a.logger.InfoContext(ctx, "IAM information collection skipped (include-iam-info=false)")
	}

	// Lifecycle detection is optional and handles its own defaults
	_ = a.collectInstanceLifecycle(ctx, a.config.IMDSOptions)

	if a.config.IncludeTags {
		if err := a.collectTags(ctx, a.config.IMDSOptions); err != nil {
			a.logger.WarnContext(ctx, "failed to collect instance tags", "error", err.Error())
		}
	} else {
		a.logger.InfoContext(ctx, "instance tags collection skipped (include-tags=false)")
	}

	a.logger.InfoContext(ctx, "EC2 instance metadata collection completed",
		"instance_id", a.metadata.IdentityDocument.InstanceID,
		"instance_type", a.metadata.IdentityDocument.InstanceType,
		"region", a.metadata.IdentityDocument.Region,
		"duration_ms", time.Since(start).Milliseconds())

	return nil
}

func (a *Attestor) collectNetworkInfo(ctx context.Context, imdsOpts *awsec2.IMDSOptions) error {
	a.logger.InfoContext(ctx, "collecting network information")

	networkInfo, err := a.client.GetNetworkInfo(ctx, imdsOpts)
	if err != nil {
		return err
	}

	a.metadata.Network = ec2predicate.NetworkInfo{
		MACAddress:     networkInfo.MACAddress,
		VPCID:          networkInfo.VPCID,
		SubnetID:       networkInfo.SubnetID,
		SecurityGroups: networkInfo.SecurityGroups,
		PrivateIPv4:    networkInfo.PrivateIPv4,
		PublicIPv4:     networkInfo.PublicIPv4,
		PublicIPv6:     networkInfo.PublicIPv6,
		LocalHostname:  networkInfo.LocalHostname,
		PublicHostname: networkInfo.PublicHostname,
	}

	a.logger.InfoContext(ctx, "network information collected",
		"vpc_id", a.metadata.Network.VPCID,
		"subnet_id", a.metadata.Network.SubnetID,
		"has_public_ip", a.metadata.Network.PublicIPv4 != "")

	return nil
}

func (a *Attestor) collectIAMInfo(ctx context.Context, imdsOpts *awsec2.IMDSOptions) error {
	a.logger.InfoContext(ctx, "collecting IAM information")

	iamInfo, err := a.client.GetIAMInfo(ctx, imdsOpts)
	if err != nil {
		return err
	}

	a.metadata.IAM = &ec2predicate.IAMInfo{
		Code:            iamInfo.Code,
		LastUpdated:     iamInfo.LastUpdated,
		InstanceProfile: iamInfo.InstanceProfile,
	}

	a.logger.InfoContext(ctx, "IAM information collected",
		"instance_profile", iamInfo.InstanceProfile,
		"code", iamInfo.Code)

	return nil
}

// collectInstanceLifecycle determines if the instance is spot, on-demand, or scheduled.
// Lifecycle detection is optional - if it fails, we default to "on-demand" without error.
//
//nolint:unparam // Returns error for consistency with other collector methods, though currently always returns nil
func (a *Attestor) collectInstanceLifecycle(ctx context.Context, imdsOpts *awsec2.IMDSOptions) error {
	a.logger.DebugContext(ctx, "detecting instance lifecycle")

	lifecycle, err := a.client.GetInstanceLifecycle(ctx, imdsOpts)
	if err != nil {
		// Lifecycle is optional - default to on-demand and don't propagate error
		a.metadata.InstanceLifecycle = "on-demand"
		a.logger.DebugContext(ctx, "lifecycle detection failed, defaulting to on-demand", "error", err.Error())
		return nil
	}

	a.metadata.InstanceLifecycle = lifecycle
	a.logger.DebugContext(ctx, "instance lifecycle detected", "lifecycle", lifecycle)

	return nil
}

// collectTags collects instance tags if configured and IAM permissions allow.
// Requires ec2:DescribeTags permission on the instance IAM role.
func (a *Attestor) collectTags(ctx context.Context, imdsOpts *awsec2.IMDSOptions) error {
	a.logger.InfoContext(ctx, "collecting instance tags")

	tags, err := a.client.GetAllTags(ctx, imdsOpts)
	if err != nil {
		return err
	}

	a.metadata.Tags = tags

	a.logger.InfoContext(ctx, "instance tags collected", "tag_count", len(a.metadata.Tags))

	return nil
}
