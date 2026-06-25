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

// Package v1 provides version 1 predicate definitions for AWS EC2 instance attestations.
package v1

import "time"

const (
	// PredicateURI is the custom predicate type URI for EC2 instance attestations.
	// Following in-toto specification for custom predicate types.
	PredicateURI = "https://github.com/thomsonreuters/stamp/ec2/v1"
)

type Predicate struct {
	Environment  InstanceMetadata `json:"environment"`
	Verification VerificationInfo `json:"verification"`
}

// InstanceMetadata holds comprehensive EC2 instance metadata collected from IMDS.
// This is the primary data structure representing the EC2 instance identity.
type InstanceMetadata struct {
	IdentityDocument  InstanceIdentityDocument `json:"identity_document"`
	Network           NetworkInfo              `json:"network"`
	IAM               *IAMInfo                 `json:"iam,omitempty"`
	InstanceLifecycle string                   `json:"instance_lifecycle,omitempty"`
	Tags              map[string]string        `json:"tags,omitempty"`
}

// InstanceIdentityDocument represents the core AWS EC2 instance identity metadata
// retrieved from the IMDS endpoint /latest/dynamic/instance-identity/document.
// This document provides cryptographically verifiable instance information.
type InstanceIdentityDocument struct {
	InstanceID              string    `json:"instance_id"`
	InstanceType            string    `json:"instance_type"`
	ImageID                 string    `json:"image_id"`
	AvailabilityZone        string    `json:"availability_zone"`
	AccountID               string    `json:"account_id"`
	Region                  string    `json:"region"`
	Architecture            string    `json:"architecture"`
	PrivateIP               string    `json:"private_ip"`
	KernelID                string    `json:"kernel_id,omitempty"`
	RamdiskID               string    `json:"ramdisk_id,omitempty"`
	BillingProducts         []string  `json:"billing_products,omitempty"`
	MarketplaceProductCodes []string  `json:"marketplace_product_codes,omitempty"`
	PendingTime             time.Time `json:"pending_time,omitzero"`
	Version                 string    `json:"version,omitempty"`
}

// NetworkInfo represents additional network configuration details for the instance.
// Includes both IPv4 and IPv6 addresses, VPC information, and security group assignments.
type NetworkInfo struct {
	PrivateIPv4    string   `json:"private_ipv4"`
	PublicIPv4     string   `json:"public_ipv4,omitempty"`
	PublicIPv6     string   `json:"public_ipv6,omitempty"`
	LocalHostname  string   `json:"local_hostname,omitempty"`
	PublicHostname string   `json:"public_hostname,omitempty"`
	MACAddress     string   `json:"mac_address"`
	VPCID          string   `json:"vpc_id,omitempty"`
	SubnetID       string   `json:"subnet_id,omitempty"`
	SecurityGroups []string `json:"security_groups,omitempty"`
}

// IAMInfo represents IAM role information associated with the instance.
// This information is only available if the instance has an IAM instance profile attached.
type IAMInfo struct {
	Code            string    `json:"code,omitempty"`
	LastUpdated     time.Time `json:"last_updated,omitzero"`
	InstanceProfile string    `json:"instance_profile,omitempty"`
}

// VerificationInfo contains metadata about how the EC2 attestation was verified.
// Tracks IMDS access details, attestation timestamp, and attestor version information.
type VerificationInfo struct {
	IMDS            IMDSInfo  `json:"imds"`
	AttestedAt      time.Time `json:"attested_at"`
	AttestorVersion string    `json:"attestor_version"`
}

// IMDSInfo contains information about the Instance Metadata Service configuration.
// Tracks the IMDS version used, endpoint accessibility, and session token details.
type IMDSInfo struct {
	Version    string `json:"version"`
	Endpoint   string `json:"endpoint"`
	Accessible bool   `json:"accessible"`
	TokenTTL   int    `json:"token_ttl,omitempty"`
}
