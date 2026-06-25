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

package v1

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPredicateURI(t *testing.T) {
	assert.Equal(t, "https://github.com/thomsonreuters/stamp/ec2/v1", PredicateURI)
}

func TestPredicate_JSONMarshal(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)
	pending := time.Date(2025, 11, 12, 9, 0, 0, 0, time.UTC)

	predicate := Predicate{
		Environment: InstanceMetadata{
			IdentityDocument: InstanceIdentityDocument{
				InstanceID:       "i-1234567890abcdef0",
				InstanceType:     "t3.medium",
				ImageID:          "ami-0123456789abcdef0",
				AvailabilityZone: "us-east-1a",
				AccountID:        "123456789012",
				Region:           "us-east-1",
				Architecture:     "x86_64",
				PrivateIP:        "10.0.1.100",
				PendingTime:      pending,
				Version:          "2017-09-30",
			},
			Network: NetworkInfo{
				PrivateIPv4:    "10.0.1.100",
				PublicIPv4:     "54.123.45.67",
				MACAddress:     "0a:12:34:56:78:9a",
				VPCID:          "vpc-abc123",
				SubnetID:       "subnet-def456",
				SecurityGroups: []string{"sg-123456", "sg-789012"},
			},
			IAM: &IAMInfo{
				Code:            "Success",
				LastUpdated:     now,
				InstanceProfile: "arn:aws:iam::123456789012:instance-profile/MyProfile",
			},
			InstanceLifecycle: "on-demand",
			Tags: map[string]string{
				"Name":        "test-instance",
				"Environment": "production",
			},
		},
		Verification: VerificationInfo{
			IMDS: IMDSInfo{
				Version:    "IMDSv2",
				Endpoint:   "http://169.254.169.254",
				Accessible: true,
				TokenTTL:   21600,
			},
			AttestedAt:      now,
			AttestorVersion: "1.0.0",
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	assert.Contains(t, string(data), "environment")
	assert.Contains(t, string(data), "verification")
	assert.Contains(t, string(data), "identity_document")
}

func TestPredicate_JSONUnmarshal(t *testing.T) {
	jsonData := `{
		"environment": {
			"identity_document": {
				"instance_id": "i-test123",
				"instance_type": "t2.micro",
				"image_id": "ami-test123",
				"availability_zone": "us-west-2a",
				"account_id": "999888777666",
				"region": "us-west-2",
				"architecture": "x86_64",
				"private_ip": "172.31.1.1"
			},
			"network": {
				"private_ipv4": "172.31.1.1",
				"mac_address": "0a:11:22:33:44:55"
			},
			"instance_lifecycle": "spot"
		},
		"verification": {
			"imds": {
				"version": "IMDSv1",
				"endpoint": "http://169.254.169.254",
				"accessible": true
			},
			"attested_at": "2025-11-12T10:00:00Z",
			"attestor_version": "0.9.0"
		}
	}`

	var predicate Predicate
	err := json.Unmarshal([]byte(jsonData), &predicate)
	require.NoError(t, err)

	assert.Equal(t, "i-test123", predicate.Environment.IdentityDocument.InstanceID)
	assert.Equal(t, "spot", predicate.Environment.InstanceLifecycle)
	assert.Equal(t, "IMDSv1", predicate.Verification.IMDS.Version)
}

func TestInstanceMetadata_Complete(t *testing.T) {
	now := time.Now()

	meta := InstanceMetadata{
		IdentityDocument: InstanceIdentityDocument{
			InstanceID:       "i-abcdef123456",
			InstanceType:     "m5.large",
			ImageID:          "ami-ubuntu",
			AvailabilityZone: "eu-west-1a",
			AccountID:        "111222333444",
			Region:           "eu-west-1",
			Architecture:     "x86_64",
			PrivateIP:        "10.0.2.50",
		},
		Network: NetworkInfo{
			PrivateIPv4: "10.0.2.50",
			PublicIPv4:  "52.100.200.100",
			MACAddress:  "0a:aa:bb:cc:dd:ee",
			VPCID:       "vpc-xyz789",
			SubnetID:    "subnet-abc123",
		},
		IAM: &IAMInfo{
			Code:            "Success",
			LastUpdated:     now,
			InstanceProfile: "arn:aws:iam::111222333444:instance-profile/EC2Role",
		},
		InstanceLifecycle: "on-demand",
		Tags: map[string]string{
			"Project": "attestation",
			"Owner":   "security-team",
		},
	}

	data, err := json.Marshal(meta)
	require.NoError(t, err)

	var result InstanceMetadata
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, meta.IdentityDocument.InstanceID, result.IdentityDocument.InstanceID)
	assert.NotNil(t, result.IAM)
	assert.Len(t, result.Tags, 2)
}

func TestInstanceMetadata_OmitEmptyFields(t *testing.T) {
	meta := InstanceMetadata{
		IdentityDocument: InstanceIdentityDocument{
			InstanceID:       "i-minimal",
			InstanceType:     "t2.nano",
			ImageID:          "ami-minimal",
			AvailabilityZone: "us-east-1b",
			AccountID:        "000111222333",
			Region:           "us-east-1",
			Architecture:     "x86_64",
			PrivateIP:        "10.0.1.1",
		},
		Network: NetworkInfo{
			PrivateIPv4: "10.0.1.1",
			MACAddress:  "0a:00:00:00:00:01",
		},
	}

	data, err := json.Marshal(meta)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "iam")
	assert.NotContains(t, string(data), "instanceLifecycle")
	assert.NotContains(t, string(data), "tags")
}

func TestInstanceIdentityDocument_Complete(t *testing.T) {
	pending := time.Date(2025, 11, 12, 9, 30, 0, 0, time.UTC)

	identityDocument := InstanceIdentityDocument{
		InstanceID:              "i-complete123",
		InstanceType:            "c5.xlarge",
		ImageID:                 "ami-complete123",
		AvailabilityZone:        "ap-south-1a",
		AccountID:               "999888777666",
		Region:                  "ap-south-1",
		Architecture:            "x86_64",
		PrivateIP:               "192.168.1.100",
		KernelID:                "aki-kernel123",
		RamdiskID:               "ari-ramdisk456",
		BillingProducts:         []string{"bp-product1", "bp-product2"},
		MarketplaceProductCodes: []string{"mpc-code1", "mpc-code2"},
		PendingTime:             pending,
		Version:                 "2017-09-30",
	}

	data, err := json.Marshal(identityDocument)
	require.NoError(t, err)

	var result InstanceIdentityDocument
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "i-complete123", result.InstanceID)
	assert.Equal(t, "aki-kernel123", result.KernelID)
	assert.Len(t, result.BillingProducts, 2)
	assert.Len(t, result.MarketplaceProductCodes, 2)
}

func TestInstanceIdentityDocument_OmitEmptyFields(t *testing.T) {
	identityDocument := InstanceIdentityDocument{
		InstanceID:       "i-simple",
		InstanceType:     "t3.small",
		ImageID:          "ami-simple",
		AvailabilityZone: "us-west-1a",
		AccountID:        "123456789012",
		Region:           "us-west-1",
		Architecture:     "x86_64",
		PrivateIP:        "10.1.1.1",
	}

	data, err := json.Marshal(identityDocument)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "kernelId")
	assert.NotContains(t, string(data), "ramdiskId")
	assert.NotContains(t, string(data), "billingProducts")
	assert.NotContains(t, string(data), "marketplaceProductCodes")
}

func TestNetworkInfo_Complete(t *testing.T) {
	networkInfo := NetworkInfo{
		PrivateIPv4:    "10.0.1.50",
		PublicIPv4:     "34.200.100.50",
		PublicIPv6:     "2600:1f18:1234:5678::1",
		LocalHostname:  "ip-10-0-1-50.ec2.internal",
		PublicHostname: "ec2-34-200-100-50.compute-1.amazonaws.com",
		MACAddress:     "0a:12:34:56:78:9a",
		VPCID:          "vpc-complete",
		SubnetID:       "subnet-complete",
		SecurityGroups: []string{"sg-web", "sg-ssh", "sg-internal"},
	}

	data, err := json.Marshal(networkInfo)
	require.NoError(t, err)

	var result NetworkInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "10.0.1.50", result.PrivateIPv4)
	assert.Equal(t, "34.200.100.50", result.PublicIPv4)
	assert.Contains(t, result.PublicIPv6, "2600")
	assert.Len(t, result.SecurityGroups, 3)
}

func TestNetworkInfo_PrivateOnly(t *testing.T) {
	networkInfo := NetworkInfo{
		PrivateIPv4:    "192.168.1.100",
		LocalHostname:  "ip-192-168-1-100.private",
		MACAddress:     "0a:aa:bb:cc:dd:ee",
		VPCID:          "vpc-private",
		SubnetID:       "subnet-private",
		SecurityGroups: []string{"sg-private"},
	}

	data, err := json.Marshal(networkInfo)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "publicIpv4")
	assert.NotContains(t, string(data), "publicIpv6")
	assert.NotContains(t, string(data), "publicHostname")
}

func TestIAMInfo_Complete(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	iamInfo := IAMInfo{
		Code:            "Success",
		LastUpdated:     now,
		InstanceProfile: "arn:aws:iam::123456789012:instance-profile/MyAppRole",
	}

	data, err := json.Marshal(iamInfo)
	require.NoError(t, err)

	var result IAMInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "Success", result.Code)
	assert.Equal(t, now.Unix(), result.LastUpdated.Unix())
	assert.Contains(t, result.InstanceProfile, "instance-profile")
}

func TestIAMInfo_OmitEmptyFields(t *testing.T) {
	iamInfo := IAMInfo{}

	data, err := json.Marshal(iamInfo)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "code")
	assert.NotContains(t, string(data), "instanceProfile")
}

func TestVerificationInfo_Complete(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	verificationInfo := VerificationInfo{
		IMDS: IMDSInfo{
			Version:    "IMDSv2",
			Endpoint:   "http://169.254.169.254",
			Accessible: true,
			TokenTTL:   21600,
		},
		AttestedAt:      now,
		AttestorVersion: "1.2.3",
	}

	data, err := json.Marshal(verificationInfo)
	require.NoError(t, err)

	var result VerificationInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "IMDSv2", result.IMDS.Version)
	assert.True(t, result.IMDS.Accessible)
	assert.Equal(t, 21600, result.IMDS.TokenTTL)
	assert.Equal(t, "1.2.3", result.AttestorVersion)
}

func TestIMDSInfo_V2(t *testing.T) {
	imdsInfo := IMDSInfo{
		Version:    "IMDSv2",
		Endpoint:   "http://169.254.169.254",
		Accessible: true,
		TokenTTL:   21600,
	}

	data, err := json.Marshal(imdsInfo)
	require.NoError(t, err)

	var result IMDSInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "IMDSv2", result.Version)
	assert.Equal(t, 21600, result.TokenTTL)
}

func TestIMDSInfo_V1(t *testing.T) {
	imdsInfo := IMDSInfo{
		Version:    "IMDSv1",
		Endpoint:   "http://169.254.169.254",
		Accessible: true,
	}

	data, err := json.Marshal(imdsInfo)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "tokenTTL")
}

func TestIMDSInfo_Inaccessible(t *testing.T) {
	imdsInfo := IMDSInfo{
		Version:    "unknown",
		Endpoint:   "http://169.254.169.254",
		Accessible: false,
	}

	data, err := json.Marshal(imdsInfo)
	require.NoError(t, err)

	var result IMDSInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.False(t, result.Accessible)
}

func TestPredicate_Complete(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)
	pending := time.Date(2025, 11, 12, 9, 0, 0, 0, time.UTC)

	predicate := Predicate{
		Environment: InstanceMetadata{
			IdentityDocument: InstanceIdentityDocument{
				InstanceID:              "i-complete-test",
				InstanceType:            "m5.2xlarge",
				ImageID:                 "ami-complete-test",
				AvailabilityZone:        "us-east-1c",
				AccountID:               "111222333444",
				Region:                  "us-east-1",
				Architecture:            "x86_64",
				PrivateIP:               "10.0.5.100",
				KernelID:                "aki-test",
				BillingProducts:         []string{"bp-6fa54006"},
				MarketplaceProductCodes: []string{"marketplace-code"},
				PendingTime:             pending,
				Version:                 "2017-09-30",
			},
			Network: NetworkInfo{
				PrivateIPv4:    "10.0.5.100",
				PublicIPv4:     "54.100.200.50",
				PublicIPv6:     "2600:1f18:abcd:ef00::1",
				LocalHostname:  "ip-10-0-5-100.ec2.internal",
				PublicHostname: "ec2-54-100-200-50.compute-1.amazonaws.com",
				MACAddress:     "0a:1b:2c:3d:4e:5f",
				VPCID:          "vpc-production",
				SubnetID:       "subnet-web",
				SecurityGroups: []string{"sg-web", "sg-monitoring"},
			},
			IAM: &IAMInfo{
				Code:            "Success",
				LastUpdated:     now,
				InstanceProfile: "arn:aws:iam::111222333444:instance-profile/WebServerRole",
			},
			InstanceLifecycle: "on-demand",
			Tags: map[string]string{
				"Name":        "web-server-01",
				"Environment": "production",
				"Team":        "platform",
			},
		},
		Verification: VerificationInfo{
			IMDS: IMDSInfo{
				Version:    "IMDSv2",
				Endpoint:   "http://169.254.169.254",
				Accessible: true,
				TokenTTL:   21600,
			},
			AttestedAt:      now,
			AttestorVersion: "1.0.0",
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, predicate.Environment.IdentityDocument.InstanceID, result.Environment.IdentityDocument.InstanceID)
	assert.NotNil(t, result.Environment.IAM)
	assert.Len(t, result.Environment.Tags, 3)
	assert.True(t, result.Verification.IMDS.Accessible)
}

func TestPredicate_Minimal(t *testing.T) {
	now := time.Now()

	predicate := Predicate{
		Environment: InstanceMetadata{
			IdentityDocument: InstanceIdentityDocument{
				InstanceID:       "i-minimal",
				InstanceType:     "t2.micro",
				ImageID:          "ami-minimal",
				AvailabilityZone: "us-east-1a",
				AccountID:        "123456789012",
				Region:           "us-east-1",
				Architecture:     "x86_64",
				PrivateIP:        "172.31.0.1",
			},
			Network: NetworkInfo{
				PrivateIPv4: "172.31.0.1",
				MACAddress:  "0a:00:00:00:00:01",
			},
		},
		Verification: VerificationInfo{
			IMDS: IMDSInfo{
				Version:    "IMDSv1",
				Endpoint:   "http://169.254.169.254",
				Accessible: true,
			},
			AttestedAt:      now,
			AttestorVersion: "1.0.0",
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "i-minimal", result.Environment.IdentityDocument.InstanceID)
	assert.Nil(t, result.Environment.IAM)
	assert.Empty(t, result.Environment.Tags)
}

func TestInstanceMetadata_InstanceLifecycle(t *testing.T) {
	tests := []struct {
		name      string
		lifecycle string
	}{
		{
			name:      "On-Demand",
			lifecycle: "on-demand",
		},
		{
			name:      "Spot",
			lifecycle: "spot",
		},
		{
			name:      "Scheduled",
			lifecycle: "scheduled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instanceMetadata := InstanceMetadata{
				IdentityDocument: InstanceIdentityDocument{
					InstanceID:       "i-test",
					InstanceType:     "t3.medium",
					ImageID:          "ami-test",
					AvailabilityZone: "us-east-1a",
					AccountID:        "123456789012",
					Region:           "us-east-1",
					Architecture:     "x86_64",
					PrivateIP:        "10.0.0.1",
				},
				Network: NetworkInfo{
					PrivateIPv4: "10.0.0.1",
					MACAddress:  "0a:00:00:00:00:01",
				},
				InstanceLifecycle: tt.lifecycle,
			}

			data, err := json.Marshal(instanceMetadata)
			require.NoError(t, err)

			var result InstanceMetadata
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.lifecycle, result.InstanceLifecycle)
		})
	}
}

func TestInstanceIdentityDocument_Architectures(t *testing.T) {
	architectures := []string{"x86_64", "arm64", "i386"}

	for _, arch := range architectures {
		t.Run(arch, func(t *testing.T) {
			instanceIdentityDocument := InstanceIdentityDocument{
				InstanceID:       "i-arch-test",
				InstanceType:     "t3.medium",
				ImageID:          "ami-arch-test",
				AvailabilityZone: "us-east-1a",
				AccountID:        "123456789012",
				Region:           "us-east-1",
				Architecture:     arch,
				PrivateIP:        "10.0.0.1",
			}

			data, err := json.Marshal(instanceIdentityDocument)
			require.NoError(t, err)

			var result InstanceIdentityDocument
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, arch, result.Architecture)
		})
	}
}

func TestNetworkInfo_SecurityGroups(t *testing.T) {
	networkInfo := NetworkInfo{
		PrivateIPv4: "10.0.1.1",
		MACAddress:  "0a:00:00:00:00:01",
		SecurityGroups: []string{
			"sg-web-80",
			"sg-web-443",
			"sg-ssh-22",
			"sg-monitoring",
			"sg-logging",
		},
	}

	data, err := json.Marshal(networkInfo)
	require.NoError(t, err)

	var result NetworkInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Len(t, result.SecurityGroups, 5)
	assert.Contains(t, result.SecurityGroups, "sg-web-80")
	assert.Contains(t, result.SecurityGroups, "sg-monitoring")
}

func TestInstanceMetadata_Tags(t *testing.T) {
	instanceMetadata := InstanceMetadata{
		IdentityDocument: InstanceIdentityDocument{
			InstanceID:       "i-tags-test",
			InstanceType:     "t3.medium",
			ImageID:          "ami-tags-test",
			AvailabilityZone: "us-east-1a",
			AccountID:        "123456789012",
			Region:           "us-east-1",
			Architecture:     "x86_64",
			PrivateIP:        "10.0.0.1",
		},
		Network: NetworkInfo{
			PrivateIPv4: "10.0.0.1",
			MACAddress:  "0a:00:00:00:00:01",
		},
		Tags: map[string]string{
			"Name":            "production-server",
			"Environment":     "production",
			"Team":            "backend",
			"CostCenter":      "engineering",
			"ManagedBy":       "terraform",
			"BackupSchedule":  "daily",
			"ComplianceLevel": "high",
		},
	}

	data, err := json.Marshal(instanceMetadata)
	require.NoError(t, err)

	var result InstanceMetadata
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Len(t, result.Tags, 7)
	assert.Equal(t, "production", result.Tags["Environment"])
	assert.Equal(t, "high", result.Tags["ComplianceLevel"])
}

func TestVerificationInfo_TimeFormats(t *testing.T) {
	tests := []struct {
		name     string
		jsonTime string
		valid    bool
	}{
		{
			name:     "RFC3339 format",
			jsonTime: `{"imds":{"version":"IMDSv2","endpoint":"http://169.254.169.254","accessible":true},"attested_at":"2025-11-12T10:00:00Z","attestor_version":"1.0.0"}`,
			valid:    true,
		},
		{
			name:     "RFC3339 with timezone",
			jsonTime: `{"imds":{"version":"IMDSv2","endpoint":"http://169.254.169.254","accessible":true},"attested_at":"2025-11-12T10:00:00+05:30","attestor_version":"1.0.0"}`,
			valid:    true,
		},
		{
			name:     "RFC3339 with nanoseconds",
			jsonTime: `{"imds":{"version":"IMDSv2","endpoint":"http://169.254.169.254","accessible":true},"attested_at":"2025-11-12T10:00:00.123456Z","attestor_version":"1.0.0"}`,
			valid:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var verificationInfo VerificationInfo
			err := json.Unmarshal([]byte(tt.jsonTime), &verificationInfo)

			if tt.valid {
				require.NoError(t, err)
				assert.False(t, verificationInfo.AttestedAt.IsZero())
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestIMDSInfo_TokenTTLs(t *testing.T) {
	tests := []struct {
		name     string
		tokenTTL int
	}{
		{
			name:     "Minimum TTL",
			tokenTTL: 1,
		},
		{
			name:     "Default TTL",
			tokenTTL: 21600,
		},
		{
			name:     "Custom TTL",
			tokenTTL: 3600,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imdsInfo := IMDSInfo{
				Version:    "IMDSv2",
				Endpoint:   "http://169.254.169.254",
				Accessible: true,
				TokenTTL:   tt.tokenTTL,
			}

			data, err := json.Marshal(imdsInfo)
			require.NoError(t, err)

			var result IMDSInfo
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.tokenTTL, result.TokenTTL)
		})
	}
}

func TestInstanceIdentityDocument_PendingTime(t *testing.T) {
	pending := time.Date(2025, 11, 12, 9, 30, 45, 0, time.UTC)

	instanceIdentityDocument := InstanceIdentityDocument{
		InstanceID:       "i-pending-test",
		InstanceType:     "t3.medium",
		ImageID:          "ami-pending-test",
		AvailabilityZone: "us-east-1a",
		AccountID:        "123456789012",
		Region:           "us-east-1",
		Architecture:     "x86_64",
		PrivateIP:        "10.0.0.1",
		PendingTime:      pending,
	}

	data, err := json.Marshal(instanceIdentityDocument)
	require.NoError(t, err)

	var result InstanceIdentityDocument
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, pending.Unix(), result.PendingTime.Unix())
}
