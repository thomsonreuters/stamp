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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/thomsonreuters/stamp/pkg/logger"
	ec2predicate "github.com/thomsonreuters/stamp/pkg/predicates/ec2/v1"
)

// TestRedactSensitiveFieldsComprehensive provides comprehensive coverage of all redaction field paths.
//
//nolint:funlen // Comprehensive test requires extensive test cases for all sensitive fields
func TestRedactSensitiveFieldsComprehensive(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	basePredicate := ec2predicate.Predicate{
		Environment: ec2predicate.InstanceMetadata{
			IdentityDocument: ec2predicate.InstanceIdentityDocument{
				InstanceID:       "i-1234567890abcdef0",
				InstanceType:     "t3.micro",
				ImageID:          "ami-0abcdef1234567890",
				AvailabilityZone: "us-east-1a",
				AccountID:        "123456789012",
				Region:           "us-east-1",
				Architecture:     "x86_64",
				PrivateIP:        "10.0.1.42",
				KernelID:         "aki-12345678",
				RamdiskID:        "ari-12345678",
			},
			Network: ec2predicate.NetworkInfo{
				MACAddress:     "02:42:ac:11:00:02",
				PrivateIPv4:    "10.0.1.42",
				PublicIPv4:     "54.123.45.67",
				PublicIPv6:     "2600:1f18:1234:5678::1",
				LocalHostname:  "ip-10-0-1-42",
				PublicHostname: "ec2-54-123-45-67.compute-1.amazonaws.com",
				VPCID:          "vpc-12345678",
				SubnetID:       "subnet-12345678",
				SecurityGroups: []string{"sg-111", "sg-222"},
			},
			IAM: &ec2predicate.IAMInfo{
				Code:            "Success",
				LastUpdated:     time.Now(),
				InstanceProfile: "arn:aws:iam::123456789012:instance-profile/test",
			},
			InstanceLifecycle: "on-demand",
			Tags: map[string]string{
				"Name":        "test-instance",
				"Environment": "production",
			},
		},
		Verification: ec2predicate.VerificationInfo{
			IMDS: ec2predicate.IMDSInfo{
				Version:    "v2",
				Endpoint:   "http://169.254.169.254",
				Accessible: true,
			},
			AttestedAt:      time.Now(),
			AttestorVersion: "1.0.0",
		},
	}

	tests := []struct {
		name        string
		fields      []string
		validate    func(*testing.T, ec2predicate.Predicate)
		description string
	}{
		{
			name:   "redact_accountId",
			fields: []string{"accountId"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.AccountID)
				assert.Equal(t, "10.0.1.42", p.Environment.IdentityDocument.PrivateIP) // Not redacted
			},
			description: "should redact account ID only",
		},
		{
			name:   "redact_identityDocument_accountId",
			fields: []string{"identityDocument.accountId"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.AccountID)
			},
			description: "should redact account ID using long form",
		},
		{
			name:   "redact_privateIp",
			fields: []string{"privateIp"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.PrivateIP)
				assert.Equal(t, "10.0.1.42", p.Environment.Network.PrivateIPv4) // Different field
			},
			description: "should redact identity document private IP",
		},
		{
			name:   "redact_network_privateIpv4",
			fields: []string{"network.privateIpv4"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.Network.PrivateIPv4)
				assert.Equal(t, "10.0.1.42", p.Environment.IdentityDocument.PrivateIP) // Different field
			},
			description: "should redact network private IPv4",
		},
		{
			name:   "redact_network_publicIpv4",
			fields: []string{"network.publicIpv4"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.Network.PublicIPv4)
			},
			description: "should redact network public IPv4",
		},
		{
			name:   "redact_network_publicIpv6",
			fields: []string{"network.publicIpv6"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.Network.PublicIPv6)
			},
			description: "should redact network public IPv6",
		},
		{
			name:   "redact_network_vpcId",
			fields: []string{"network.vpcId"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.Network.VPCID)
			},
			description: "should redact VPC ID",
		},
		{
			name:   "redact_network_subnetId",
			fields: []string{"network.subnetId"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.Network.SubnetID)
			},
			description: "should redact subnet ID",
		},
		{
			name:   "redact_network_securityGroups",
			fields: []string{"network.securityGroups"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, []string{"[REDACTED]"}, p.Environment.Network.SecurityGroups)
			},
			description: "should redact security groups",
		},
		{
			name:   "redact_network_macAddress",
			fields: []string{"network.macAddress"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.Network.MACAddress)
			},
			description: "should redact MAC address",
		},
		{
			name:   "redact_network_localHostname",
			fields: []string{"network.localHostname"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.Network.LocalHostname)
			},
			description: "should redact local hostname",
		},
		{
			name:   "redact_network_publicHostname",
			fields: []string{"network.publicHostname"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.Network.PublicHostname)
			},
			description: "should redact public hostname",
		},
		{
			name:   "redact_iam_complete",
			fields: []string{"iam"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.NotNil(t, p.Environment.IAM)
				assert.Equal(t, "[REDACTED]", p.Environment.IAM.Code)
				assert.Equal(t, "[REDACTED]", p.Environment.IAM.InstanceProfile)
			},
			description: "should redact all IAM fields",
		},
		{
			name:   "redact_iam_instanceProfile",
			fields: []string{"iam.instanceProfile"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.NotNil(t, p.Environment.IAM)
				assert.Equal(t, "[REDACTED]", p.Environment.IAM.InstanceProfile)
				assert.Equal(t, "Success", p.Environment.IAM.Code) // Not redacted
			},
			description: "should redact IAM instance profile only",
		},
		{
			name:   "redact_tags",
			fields: []string{"tags"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, map[string]string{"redacted": "[REDACTED]"}, p.Environment.Tags)
			},
			description: "should redact all tags",
		},
		{
			name:   "redact_imageId",
			fields: []string{"imageId"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.ImageID)
			},
			description: "should redact image ID",
		},
		{
			name:   "redact_instanceType",
			fields: []string{"instanceType"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.InstanceType)
			},
			description: "should redact instance type",
		},
		{
			name:   "redact_availabilityZone",
			fields: []string{"availabilityZone"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.AvailabilityZone)
			},
			description: "should redact availability zone",
		},
		{
			name:   "redact_region",
			fields: []string{"region"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.Region)
			},
			description: "should redact region",
		},
		{
			name:   "redact_architecture",
			fields: []string{"architecture"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.Architecture)
			},
			description: "should redact architecture",
		},
		{
			name:   "redact_kernelId",
			fields: []string{"kernelId"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.KernelID)
			},
			description: "should redact kernel ID",
		},
		{
			name:   "redact_ramdiskId",
			fields: []string{"ramdiskId"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.RamdiskID)
			},
			description: "should redact ramdisk ID",
		},
		{
			name:   "redact_instanceLifecycle",
			fields: []string{"instanceLifecycle"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.InstanceLifecycle)
			},
			description: "should redact instance lifecycle",
		},
		{
			name:   "redact_imds_endpoint",
			fields: []string{"imds.endpoint"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Verification.IMDS.Endpoint)
			},
			description: "should redact IMDS endpoint",
		},
		{
			name:   "redact_multiple_fields",
			fields: []string{"accountId", "privateIp", "network.vpcId", "network.subnetId", "tags"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.AccountID)
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.PrivateIP)
				assert.Equal(t, "[REDACTED]", p.Environment.Network.VPCID)
				assert.Equal(t, "[REDACTED]", p.Environment.Network.SubnetID)
				assert.Equal(t, map[string]string{"redacted": "[REDACTED]"}, p.Environment.Tags)
			},
			description: "should redact multiple fields simultaneously",
		},
		{
			name:   "redact_short_and_long_forms",
			fields: []string{"vpcId", "network.subnetId"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.Network.VPCID)
				assert.Equal(t, "[REDACTED]", p.Environment.Network.SubnetID)
			},
			description: "should handle both short and long form field paths",
		},
		{
			name:   "redact_unknown_field_no_error",
			fields: []string{"unknownField", "network.unknownSubfield"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				// Should not cause errors, just ignored
				assert.Equal(t, "123456789012", p.Environment.IdentityDocument.AccountID) // Not redacted
			},
			description: "should gracefully ignore unknown field paths",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy for each test
			testPredicate := basePredicate
			result := attestor.redactSensitiveFields(testPredicate, tt.fields)
			tt.validate(t, result)
		})
	}
}

// TestRedactSensitiveFieldsEdgeCases tests edge cases and boundary conditions.
func TestRedactSensitiveFieldsEdgeCases(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	tests := []struct {
		name      string
		predicate ec2predicate.Predicate
		fields    []string
		validate  func(*testing.T, ec2predicate.Predicate)
	}{
		{
			name: "redact_iam_when_nil",
			predicate: ec2predicate.Predicate{
				Environment: ec2predicate.InstanceMetadata{
					IAM: nil, // IAM is nil
				},
			},
			fields: []string{"iam.instanceProfile"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Nil(t, p.Environment.IAM)
			},
		},
		{
			name: "redact_tags_when_empty",
			predicate: ec2predicate.Predicate{
				Environment: ec2predicate.InstanceMetadata{
					Tags: map[string]string{}, // Empty tags
				},
			},
			fields: []string{"tags"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, map[string]string{"redacted": "[REDACTED]"}, p.Environment.Tags)
			},
		},
		{
			name: "redact_security_groups_when_empty",
			predicate: ec2predicate.Predicate{
				Environment: ec2predicate.InstanceMetadata{
					Network: ec2predicate.NetworkInfo{
						SecurityGroups: []string{}, // Empty list
					},
				},
			},
			fields: []string{"network.securityGroups"},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, []string{"[REDACTED]"}, p.Environment.Network.SecurityGroups)
			},
		},
		{
			name: "no_fields_to_redact",
			predicate: ec2predicate.Predicate{
				Environment: ec2predicate.InstanceMetadata{
					IdentityDocument: ec2predicate.InstanceIdentityDocument{
						AccountID: "123456789012",
					},
				},
			},
			fields: []string{},
			validate: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "123456789012", p.Environment.IdentityDocument.AccountID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := attestor.redactSensitiveFields(tt.predicate, tt.fields)
			tt.validate(t, result)
		})
	}
}
