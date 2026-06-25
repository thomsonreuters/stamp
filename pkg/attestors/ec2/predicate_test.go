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
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/logger"
	ec2predicate "github.com/thomsonreuters/stamp/pkg/predicates/ec2/v1"
)

// TestGeneratePredicate verifies that the GeneratePredicate method creates
// a properly structured EC2Predicate with all required fields.
func TestGeneratePredicate(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		metadata: ec2predicate.InstanceMetadata{
			IdentityDocument: ec2predicate.InstanceIdentityDocument{
				InstanceID:       "i-1234567890abcdef0",
				InstanceType:     "t3.micro",
				ImageID:          "ami-0abcdef1234567890",
				AvailabilityZone: "us-east-1a",
				AccountID:        "123456789012",
				Region:           "us-east-1",
				Architecture:     "x86_64",
				PrivateIP:        "10.0.1.42",
			},
			Network: ec2predicate.NetworkInfo{
				PrivateIPv4: "10.0.1.42",
				PublicIPv4:  "54.123.45.67",
				VPCID:       "vpc-12345678",
				SubnetID:    "subnet-12345678",
				MACAddress:  "02:42:ac:11:00:02",
			},
		},
		imdsInfo: ec2predicate.IMDSInfo{
			Version:    "v2",
			Endpoint:   "http://169.254.169.254",
			Accessible: true,
			TokenTTL:   60,
		},
	}

	config := core.Config{}

	predicate, err := attestor.GeneratePredicate(config)
	require.NoError(t, err, "GeneratePredicate failed")

	ec2Pred, ok := predicate.(ec2predicate.Predicate)
	require.True(t, ok, "Expected ec2predicate.Predicate type, got %T", predicate)

	// Verify environment data
	assert.Equal(t, "i-1234567890abcdef0", ec2Pred.Environment.IdentityDocument.InstanceID, "Expected instance ID i-1234567890abcdef0")

	assert.Equal(t, "123456789012", ec2Pred.Environment.IdentityDocument.AccountID, "Expected account ID 123456789012")

	// Verify verification info
	assert.Equal(t, "v2", ec2Pred.Verification.IMDS.Version, "Expected IMDS version v2")

	assert.Equal(t, "1.0.0", ec2Pred.Verification.AttestorVersion, "Expected attestor version 1.0.0")

	assert.False(t, ec2Pred.Verification.AttestedAt.IsZero(), "Expected AttestedAt to be set")
}

// TestGeneratePredicateWithRedaction verifies that redaction configuration
// properly redacts sensitive fields in the predicate.
func TestGeneratePredicateWithRedaction(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		metadata: ec2predicate.InstanceMetadata{
			IdentityDocument: ec2predicate.InstanceIdentityDocument{
				InstanceID:       "i-1234567890abcdef0",
				InstanceType:     "t3.micro",
				ImageID:          "ami-0abcdef1234567890",
				AvailabilityZone: "us-east-1a",
				AccountID:        "123456789012",
				Region:           "us-east-1",
				Architecture:     "x86_64",
				PrivateIP:        "10.0.1.42",
			},
			Network: ec2predicate.NetworkInfo{
				PrivateIPv4: "10.0.1.42",
				PublicIPv4:  "54.123.45.67",
				VPCID:       "vpc-12345678",
				SubnetID:    "subnet-12345678",
			},
		},
		imdsInfo: ec2predicate.IMDSInfo{
			Version:    "v2",
			Endpoint:   "http://169.254.169.254",
			Accessible: true,
		},
	}

	tests := []struct {
		name           string
		config         core.Config
		checkAccountID string
		checkPrivateIP string
		checkVpcID     string
	}{
		{
			name: "redact account ID",
			config: core.Config{
				"redact-account-id": true,
			},
			checkAccountID: "[REDACTED]",
			checkPrivateIP: "10.0.1.42",
			checkVpcID:     "vpc-12345678",
		},
		{
			name: "redact private IPs",
			config: core.Config{
				"redact-private-ips": true,
			},
			checkAccountID: "123456789012",
			checkPrivateIP: "[REDACTED]",
			checkVpcID:     "vpc-12345678",
		},
		{
			name: "redact via sensitive-fields",
			config: core.Config{
				"sensitive-fields": []string{"vpcId", "accountId"},
			},
			checkAccountID: "[REDACTED]",
			checkPrivateIP: "10.0.1.42",
			checkVpcID:     "[REDACTED]",
		},
		{
			name: "combined redaction",
			config: core.Config{
				"redact-account-id":  true,
				"redact-private-ips": true,
				"sensitive-fields":   []string{"vpcId"},
			},
			checkAccountID: "[REDACTED]",
			checkPrivateIP: "[REDACTED]",
			checkVpcID:     "[REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh attestor for each test
			testAttestor := &Attestor{
				logger:   logger.NewNoop(),
				metadata: attestor.metadata,
				imdsInfo: attestor.imdsInfo,
			}

			predicate, err := testAttestor.GeneratePredicate(tt.config)
			require.NoError(t, err, "GeneratePredicate failed")

			ec2Pred, _ := predicate.(ec2predicate.Predicate)

			assert.Equal(t, tt.checkAccountID, ec2Pred.Environment.IdentityDocument.AccountID, "Expected account ID %s", tt.checkAccountID)

			assert.Equal(t, tt.checkPrivateIP, ec2Pred.Environment.IdentityDocument.PrivateIP, "Expected private IP %s", tt.checkPrivateIP)

			assert.Equal(t, tt.checkVpcID, ec2Pred.Environment.Network.VPCID, "Expected VPC ID %s", tt.checkVpcID)
		})
	}
}

// TestSubjects verifies that the Subjects method returns properly formatted
// subject identifiers for the EC2 instance.
func TestSubjects(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		metadata: ec2predicate.InstanceMetadata{
			IdentityDocument: ec2predicate.InstanceIdentityDocument{
				InstanceID: "i-1234567890abcdef0",
				ImageID:    "ami-0abcdef1234567890",
				AccountID:  "123456789012",
				Region:     "us-east-1",
			},
		},
	}

	subjects := attestor.Subjects(core.Config{})

	require.Len(t, subjects, 1, "Expected 1 subject")

	subject := subjects[0]

	expectedName := "ec2+us-east-1://i-1234567890abcdef0"
	assert.Equal(t, expectedName, subject.Name, "Expected name %s", expectedName)

	assert.Equal(t, "i-1234567890abcdef0", subject.Digest["instanceId"], "Expected instanceId i-1234567890abcdef0")

	assert.Equal(t, "ami-0abcdef1234567890", subject.Digest["imageId"], "Expected imageId ami-0abcdef1234567890")

	assert.Equal(t, "123456789012", subject.Digest["accountId"], "Expected accountId 123456789012")
}

// TestRedactSensitiveFields verifies granular field redaction functionality.
func TestRedactSensitiveFields(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	predicate := ec2predicate.Predicate{
		Environment: ec2predicate.InstanceMetadata{
			IdentityDocument: ec2predicate.InstanceIdentityDocument{
				InstanceID:   "i-1234567890abcdef0",
				AccountID:    "123456789012",
				PrivateIP:    "10.0.1.42",
				ImageID:      "ami-0abcdef1234567890",
				InstanceType: "t3.micro",
				Region:       "us-east-1",
			},
			Network: ec2predicate.NetworkInfo{
				PrivateIPv4: "10.0.1.42",
				PublicIPv4:  "54.123.45.67",
				VPCID:       "vpc-12345678",
				SubnetID:    "subnet-12345678",
				MACAddress:  "02:42:ac:11:00:02",
			},
			Tags: map[string]string{
				"Environment": "production",
				"Owner":       "team-platform",
			},
		},
		Verification: ec2predicate.VerificationInfo{
			IMDS: ec2predicate.IMDSInfo{
				Version:  "v2",
				Endpoint: "http://169.254.169.254",
			},
			AttestedAt:      time.Now(),
			AttestorVersion: "1.0.0",
		},
	}

	tests := []struct {
		name   string
		fields []string
		check  func(t *testing.T, p ec2predicate.Predicate)
	}{
		{
			name:   "redact account ID",
			fields: []string{"accountId"},
			check: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.AccountID, "Expected redacted account ID")
			},
		},
		{
			name:   "redact network VPC ID",
			fields: []string{"network.vpcId"},
			check: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.Network.VPCID, "Expected redacted VPC ID")
			},
		},
		{
			name:   "redact tags",
			fields: []string{"tags"},
			check: func(t *testing.T, p ec2predicate.Predicate) {
				require.Len(t, p.Environment.Tags, 1, "Expected redacted tags to have 1 entry")
				assert.Equal(t, "[REDACTED]", p.Environment.Tags["redacted"], "Expected redacted tags")
			},
		},
		{
			name:   "redact multiple fields",
			fields: []string{"accountId", "network.vpcId", "network.subnetId"},
			check: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.AccountID, "Expected redacted account ID")
				assert.Equal(t, "[REDACTED]", p.Environment.Network.VPCID, "Expected redacted VPC ID")
				assert.Equal(t, "[REDACTED]", p.Environment.Network.SubnetID, "Expected redacted subnet ID")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of the predicate for each test
			testPred := predicate
			result := attestor.redactSensitiveFields(testPred, tt.fields)
			tt.check(t, result)
		})
	}
}
