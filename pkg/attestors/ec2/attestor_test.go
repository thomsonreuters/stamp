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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	awsec2 "github.com/thomsonreuters/stamp/pkg/clients/aws/ec2"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/logger"
	ec2predicate "github.com/thomsonreuters/stamp/pkg/predicates/ec2/v1"
)

// TestID verifies the attestor returns the correct unique identifier.
func TestID(t *testing.T) {
	attestor := &Attestor{}
	assert.Equal(t, "ec2", attestor.ID())
}

// TestPredicateURI verifies the attestor returns the correct predicate URI.
func TestPredicateURI(t *testing.T) {
	attestor := &Attestor{}
	expected := ec2predicate.PredicateURI
	assert.Equal(t, expected, attestor.PredicateURI())
	assert.Contains(t, attestor.PredicateURI(), "github.com/thomsonreuters/stamp/ec2")
}

// TestName verifies the attestor returns a human-readable name.
func TestName(t *testing.T) {
	attestor := &Attestor{}
	assert.Equal(t, "EC2 Attestor", attestor.Name())
	assert.NotEmpty(t, attestor.Name())
}

// TestDescription verifies the attestor returns a meaningful description.
func TestDescription(t *testing.T) {
	attestor := &Attestor{}
	description := attestor.Description()
	assert.NotEmpty(t, description)
	assert.Contains(t, description, "EC2")
	assert.Contains(t, description, "metadata")
}

// TestConfigSchemaStructure verifies the configuration schema structure.
func TestConfigSchemaStructure(t *testing.T) {
	attestor := &Attestor{}
	schema := attestor.ConfigSchema()

	require.NotEmpty(t, schema, "ConfigSchema should not be empty")

	// Build a map for easier field verification
	fieldMap := make(map[string]core.ConfigField)
	for _, field := range schema {
		fieldMap[field.Name] = field
	}

	// Verify critical configuration fields exist
	criticalFields := []string{
		"imds-version",
		"imds-endpoint",
		"timeout",
		"token-ttl",
		"include-network-details",
		"include-iam-info",
		"include-tags",
		"not-ec2-behavior",
		"imds-unavailable-behavior",
		"redact-account-id",
		"redact-private-ips",
		"sensitive-fields",
		"max-retries",
		"retry-delay",
	}

	for _, fieldName := range criticalFields {
		field, exists := fieldMap[fieldName]
		assert.True(t, exists, "Field %s should exist in schema", fieldName)

		if exists {
			assert.NotEmpty(t, field.Type, "Field %s should have a type", fieldName)
			assert.NotEmpty(t, field.Description, "Field %s should have a description", fieldName)

			// Verify specific field properties
			switch fieldName {
			case "imds-version":
				assert.Equal(t, "string", field.Type)
				assert.Equal(t, "v2", field.Default)
			case "timeout":
				assert.Equal(t, "duration", field.Type)
			case "token-ttl":
				assert.Equal(t, "int", field.Type)
			case "include-network-details":
				assert.Equal(t, "bool", field.Type)
				assert.Equal(t, true, field.Default)
			case "redact-account-id":
				assert.Equal(t, "bool", field.Type)
				assert.Equal(t, false, field.Default)
			case "sensitive-fields":
				assert.Equal(t, "[]string", field.Type)
			}
		}
	}
}

// TestPreAttest verifies the pre-attestation setup phase.
func TestPreAttest(t *testing.T) {
	tests := []struct {
		name        string
		config      core.Config
		setupMock   func(*awsec2.MockClient)
		expectError bool
		validate    func(*testing.T, *Attestor)
	}{
		{
			name:   "default configuration - IMDS accessible",
			config: core.Config{},
			setupMock: func(m *awsec2.MockClient) {
				m.On("CheckIMDSAccessibility", mock.Anything, mock.Anything).Return(nil)
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				assert.NotNil(t, a.client)
				assert.True(t, a.imdsInfo.Accessible)
			},
		},
		{
			name: "custom IMDS endpoint - IMDS accessible",
			config: core.Config{
				"imds-endpoint": "http://custom-endpoint:8080",
			},
			setupMock: func(m *awsec2.MockClient) {
				m.On("CheckIMDSAccessibility", mock.Anything, mock.Anything).Return(nil)
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				assert.NotNil(t, a.client)
				assert.True(t, a.imdsInfo.Accessible)
			},
		},
		{
			name: "IMDSv1 version - IMDS accessible",
			config: core.Config{
				"imds-version": "v1",
			},
			setupMock: func(m *awsec2.MockClient) {
				m.On("CheckIMDSAccessibility", mock.Anything, mock.Anything).Return(nil)
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				assert.NotNil(t, a.client)
				assert.True(t, a.imdsInfo.Accessible)
			},
		},
		{
			name: "auto version detection - IMDS accessible",
			config: core.Config{
				"imds-version": "auto",
			},
			setupMock: func(m *awsec2.MockClient) {
				m.On("CheckIMDSAccessibility", mock.Anything, mock.Anything).Return(nil)
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				assert.NotNil(t, a.client)
				assert.True(t, a.imdsInfo.Accessible)
			},
		},
		{
			name: "IMDS not accessible with warn behavior",
			config: core.Config{
				"not-ec2-behavior": "warn",
			},
			setupMock: func(m *awsec2.MockClient) {
				m.On("CheckIMDSAccessibility", mock.Anything, mock.Anything).Return(assert.AnError)
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				assert.NotNil(t, a.client)
				assert.False(t, a.imdsInfo.Accessible)
			},
		},
		{
			name: "IMDS not accessible with skip behavior",
			config: core.Config{
				"not-ec2-behavior": "skip",
			},
			setupMock: func(m *awsec2.MockClient) {
				m.On("CheckIMDSAccessibility", mock.Anything, mock.Anything).Return(assert.AnError)
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				assert.NotNil(t, a.client)
				assert.False(t, a.imdsInfo.Accessible)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := awsec2.SetupMockClient(t)
			if tt.setupMock != nil {
				tt.setupMock(mockClient)
			}

			attestor := &Attestor{
				logger: logger.NewNoop(),
			}

			err := attestor.PreAttest(t.Context(), tt.config)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, attestor)
				}
			}
		})
	}
}

// TestAttest verifies the attestation collection phase.
func TestAttest(t *testing.T) {
	tests := []struct {
		name        string
		setupFn     func(*Attestor, *awsec2.MockClient)
		config      core.Config
		expectError bool
	}{
		{
			name: "IMDS unavailable with fail behavior",
			setupFn: func(a *Attestor, m *awsec2.MockClient) {
				a.imdsInfo = ec2predicate.IMDSInfo{
					Accessible: false,
				}
			},
			config: core.Config{
				"imds-unavailable-behavior": "fail",
			},
			expectError: true,
		},
		{
			name: "IMDS unavailable with warn behavior",
			setupFn: func(a *Attestor, m *awsec2.MockClient) {
				a.imdsInfo = ec2predicate.IMDSInfo{
					Accessible: false,
				}
			},
			config: core.Config{
				"imds-unavailable-behavior": "warn",
			},
			expectError: false,
		},
		{
			name: "IMDS accessible - successful collection",
			setupFn: func(a *Attestor, m *awsec2.MockClient) {
				a.client = m
				a.imdsInfo = ec2predicate.IMDSInfo{
					Accessible: true,
					Version:    "v2",
					Endpoint:   "http://169.254.169.254",
				}
				// Mock successful instance identity document retrieval
				m.On("GetInstanceIdentityDocument", mock.Anything, mock.Anything).Return(&awsec2.InstanceIdentityDocument{
					AccountID:        "123456789012",
					Architecture:     "x86_64",
					AvailabilityZone: "us-east-1a",
					ImageID:          "ami-test123",
					InstanceID:       "i-test123",
					InstanceType:     "t3.micro",
					PrivateIP:        "10.0.1.100",
					Region:           "us-east-1",
					Version:          "2017-09-30",
					PendingTime:      time.Now().Add(-1 * time.Hour),
				}, nil)
				// Mock instance lifecycle (always called from collectInstanceMetadata)
				m.On("GetInstanceLifecycle", mock.Anything, mock.Anything).Return("on-demand", nil)
			},
			config: core.Config{
				"include-network-details": false,
				"include-iam-info":        false,
				"include-tags":            false,
			},
			expectError: false,
		},
		{
			name: "IMDS accessible with network details",
			setupFn: func(a *Attestor, m *awsec2.MockClient) {
				a.client = m
				a.imdsInfo = ec2predicate.IMDSInfo{
					Accessible: true,
					Version:    "v2",
					Endpoint:   "http://169.254.169.254",
				}
				m.On("GetInstanceIdentityDocument", mock.Anything, mock.Anything).Return(&awsec2.InstanceIdentityDocument{
					InstanceID:       "i-test123",
					InstanceType:     "t3.micro",
					AccountID:        "123456789012",
					Region:           "us-east-1",
					AvailabilityZone: "us-east-1a",
					ImageID:          "ami-test123",
					Architecture:     "x86_64",
					PrivateIP:        "10.0.1.100",
					Version:          "2017-09-30",
					PendingTime:      time.Now().Add(-1 * time.Hour),
				}, nil)
				m.On("GetNetworkInfo", mock.Anything, mock.Anything).Return(&awsec2.NetworkInfo{
					MACAddress:     "0a:1b:2c:3d:4e:5f",
					VPCID:          "vpc-test123",
					SubnetID:       "subnet-test123",
					SecurityGroups: []string{"sg-test123"},
					PrivateIPv4:    "10.0.1.100",
					PublicIPv4:     "54.123.45.67",
					LocalHostname:  "ip-10-0-1-100.ec2.internal",
				}, nil)
				m.On("GetInstanceLifecycle", mock.Anything, mock.Anything).Return("on-demand", nil)
			},
			config: core.Config{
				"include-network-details": true,
				"include-iam-info":        false,
				"include-tags":            false,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := awsec2.SetupMockClient(t)

			attestor := &Attestor{
				logger: logger.NewNoop(),
			}

			if tt.setupFn != nil {
				tt.setupFn(attestor, mockClient)
			}

			err := attestor.Attest(t.Context(), tt.config)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestPostAttest verifies the post-attestation cleanup phase.
func TestPostAttest(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	// PostAttest should never fail for EC2 attestor as it performs no cleanup
	err := attestor.PostAttest(t.Context(), core.Config{})
	require.NoError(t, err)

	// Verify it's idempotent
	err = attestor.PostAttest(t.Context(), core.Config{})
	assert.NoError(t, err)
}

// TestGeneratePredicateBasic verifies basic predicate generation.
func TestGeneratePredicateBasic(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		metadata: ec2predicate.InstanceMetadata{
			IdentityDocument: ec2predicate.InstanceIdentityDocument{
				InstanceID:       "i-test123",
				InstanceType:     "t3.micro",
				ImageID:          "ami-test123",
				AvailabilityZone: "us-east-1a",
				AccountID:        "123456789012",
				Region:           "us-east-1",
				Architecture:     "x86_64",
				PrivateIP:        "10.0.1.100",
			},
		},
		imdsInfo: ec2predicate.IMDSInfo{
			Version:    "v2",
			Endpoint:   "http://169.254.169.254",
			Accessible: true,
		},
	}

	config := core.Config{}

	predicate, err := attestor.GeneratePredicate(config)
	require.NoError(t, err)
	require.NotNil(t, predicate)

	ec2Pred, ok := predicate.(ec2predicate.Predicate)
	require.True(t, ok, "Predicate should be of type ec2predicate.Predicate")

	// Verify structure
	assert.Equal(t, "i-test123", ec2Pred.Environment.IdentityDocument.InstanceID)
	assert.Equal(t, "123456789012", ec2Pred.Environment.IdentityDocument.AccountID)
	assert.Equal(t, "v2", ec2Pred.Verification.IMDS.Version)
	assert.False(t, ec2Pred.Verification.AttestedAt.IsZero())
}

// TestSubjectsBasic verifies basic subject generation.
func TestSubjectsBasic(t *testing.T) {
	attestor := &Attestor{
		metadata: ec2predicate.InstanceMetadata{
			IdentityDocument: ec2predicate.InstanceIdentityDocument{
				InstanceID: "i-test123",
				ImageID:    "ami-test123",
				AccountID:  "123456789012",
				Region:     "us-east-1",
			},
		},
	}

	subjects := attestor.Subjects(core.Config{})

	require.Len(t, subjects, 1, "Should return exactly one subject")

	subject := subjects[0]
	assert.Equal(t, "ec2+us-east-1://i-test123", subject.Name)
	assert.Equal(t, "i-test123", subject.Digest["instanceId"])
	assert.Equal(t, "ami-test123", subject.Digest["imageId"])
	assert.Equal(t, "123456789012", subject.Digest["accountId"])
}

// TestSchema verifies JSON schema generation for the predicate (attestation output).
func TestSchema(t *testing.T) {
	attestor := &Attestor{}
	schema := attestor.Schema()

	require.NotNil(t, schema, "Schema should not be nil")
	assert.Equal(t, "EC2 Runtime Environment Attestation", schema.Title)
	assert.Equal(t, "AWS EC2 instance metadata collected from IMDS for runtime attestation", schema.Description)

	// The schema is generated from ec2predicate.Predicate using reflection
	// The actual structure depends on the jsonschema library's reflection behavior
	// We just verify that a schema was generated successfully
}

// TestAttestorInterfaceCompliance verifies the attestor implements core.Attestor.
func TestAttestorInterfaceCompliance(t *testing.T) {
	// Compile-time verification that Attestor implements core.Attestor interface
	var _ core.Attestor = (*Attestor)(nil)

	// Runtime verification
	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	// Verify all interface methods are callable
	assert.NotEmpty(t, attestor.ID())
	assert.NotEmpty(t, attestor.PredicateURI())
	assert.NotEmpty(t, attestor.Name())
	assert.NotEmpty(t, attestor.Description())
	assert.NotNil(t, attestor.ConfigSchema())
	require.NoError(t, attestor.ValidateConfig(core.Config{}))
	assert.NotNil(t, attestor.Schema())

	// PostAttest should always succeed
	err := attestor.PostAttest(t.Context(), core.Config{})
	require.NoError(t, err)

	// Subjects should work even without metadata (may be empty)
	subjects := attestor.Subjects(core.Config{})
	assert.NotNil(t, subjects)
}

// TestFullAttestationLifecycle verifies the complete attestation workflow.
func TestFullAttestationLifecycle(t *testing.T) {
	mockClient := awsec2.SetupMockClient(t)

	// Mock IMDS accessibility check
	mockClient.On("CheckIMDSAccessibility", mock.Anything, mock.Anything).Return(nil)

	// Mock instance identity document
	mockClient.On("GetInstanceIdentityDocument", mock.Anything, mock.Anything).Return(&awsec2.InstanceIdentityDocument{
		AccountID:        "123456789012",
		Architecture:     "x86_64",
		AvailabilityZone: "us-east-1a",
		ImageID:          "ami-test123",
		InstanceID:       "i-test123",
		InstanceType:     "t3.micro",
		PrivateIP:        "10.0.1.100",
		Region:           "us-east-1",
		Version:          "2017-09-30",
		PendingTime:      time.Now().Add(-1 * time.Hour),
	}, nil)

	// Mock network info
	mockClient.On("GetNetworkInfo", mock.Anything, mock.Anything).Return(&awsec2.NetworkInfo{
		MACAddress:     "0a:1b:2c:3d:4e:5f",
		VPCID:          "vpc-test123",
		SubnetID:       "subnet-test123",
		SecurityGroups: []string{"sg-test123"},
		PrivateIPv4:    "10.0.1.100",
		LocalHostname:  "ip-10-0-1-100.ec2.internal",
	}, nil)

	// Mock lifecycle
	mockClient.On("GetInstanceLifecycle", mock.Anything, mock.Anything).Return("on-demand", nil)

	config := core.Config{
		"imds-version":              "v2",
		"include-network-details":   true,
		"include-iam-info":          false,
		"include-tags":              false,
		"redact-account-id":         false,
		"redact-private-ips":        false,
		"imds-unavailable-behavior": "warn",
	}

	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	// Step 1: Validate configuration
	err := attestor.ValidateConfig(config)
	require.NoError(t, err, "ValidateConfig should succeed")

	// Step 2: Pre-attestation setup
	err = attestor.PreAttest(t.Context(), config)
	require.NoError(t, err, "PreAttest should succeed")
	assert.NotNil(t, attestor.client)
	assert.True(t, attestor.imdsInfo.Accessible)

	// Step 3: Attestation
	err = attestor.Attest(t.Context(), config)
	require.NoError(t, err, "Attest should succeed")

	// Generate predicate
	predicate, err := attestor.GeneratePredicate(config)
	require.NoError(t, err, "GeneratePredicate should succeed")
	require.NotNil(t, predicate)

	// Verify predicate type
	ec2Pred, ok := predicate.(ec2predicate.Predicate)
	require.True(t, ok)
	assert.NotEmpty(t, ec2Pred.Environment.IdentityDocument.InstanceID)
	assert.Equal(t, "i-test123", ec2Pred.Environment.IdentityDocument.InstanceID)

	// Get subjects
	subjects := attestor.Subjects(core.Config{})
	require.Len(t, subjects, 1)
	assert.Contains(t, subjects[0].Name, "ec2+")

	// Step 4: Post-attestation cleanup (should always succeed)
	err = attestor.PostAttest(t.Context(), config)
	require.NoError(t, err, "PostAttest should always succeed")
}

// TestConfigurationParsing verifies configuration values are parsed correctly.
func TestConfigurationParsing(t *testing.T) {
	tests := []struct {
		name     string
		config   core.Config
		validate func(*testing.T, *Attestor)
	}{
		{
			name: "custom endpoint parsing",
			config: core.Config{
				"imds-endpoint": "http://custom:9090",
			},
			validate: func(t *testing.T, a *Attestor) {
				_ = a.PreAttest(t.Context(), core.Config{
					"imds-endpoint": "http://custom:9090",
				})
				assert.NotNil(t, a.client)
			},
		},
		{
			name: "version string parsing",
			config: core.Config{
				"imds-version": "v1",
			},
			validate: func(t *testing.T, a *Attestor) {
				_ = a.PreAttest(t.Context(), core.Config{
					"imds-version": "v1",
				})
				assert.NotNil(t, a.client)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
			}
			if tt.validate != nil {
				tt.validate(t, attestor)
			}
		})
	}
}

// TestRedactionConfiguration verifies redaction settings are applied correctly.
func TestRedactionConfiguration(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		metadata: ec2predicate.InstanceMetadata{
			IdentityDocument: ec2predicate.InstanceIdentityDocument{
				InstanceID: "i-test123",
				AccountID:  "123456789012",
				PrivateIP:  "10.0.1.100",
				Region:     "us-east-1",
			},
			Network: ec2predicate.NetworkInfo{
				PrivateIPv4: "10.0.1.100",
				VPCID:       "vpc-test123",
			},
		},
		imdsInfo: ec2predicate.IMDSInfo{
			Version:    "v2",
			Accessible: true,
		},
	}

	tests := []struct {
		name   string
		config core.Config
		verify func(*testing.T, ec2predicate.Predicate)
	}{
		{
			name: "no redaction",
			config: core.Config{
				"redact-account-id":  false,
				"redact-private-ips": false,
			},
			verify: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "123456789012", p.Environment.IdentityDocument.AccountID)
				assert.Equal(t, "10.0.1.100", p.Environment.IdentityDocument.PrivateIP)
			},
		},
		{
			name: "redact account ID only",
			config: core.Config{
				"redact-account-id": true,
			},
			verify: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.AccountID)
				assert.Equal(t, "10.0.1.100", p.Environment.IdentityDocument.PrivateIP)
			},
		},
		{
			name: "redact private IPs only",
			config: core.Config{
				"redact-private-ips": true,
			},
			verify: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "123456789012", p.Environment.IdentityDocument.AccountID)
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.PrivateIP)
				assert.Equal(t, "[REDACTED]", p.Environment.Network.PrivateIPv4)
			},
		},
		{
			name: "redact both",
			config: core.Config{
				"redact-account-id":  true,
				"redact-private-ips": true,
			},
			verify: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.AccountID)
				assert.Equal(t, "[REDACTED]", p.Environment.IdentityDocument.PrivateIP)
			},
		},
		{
			name: "sensitive fields redaction",
			config: core.Config{
				"sensitive-fields": []string{"vpcId"},
			},
			verify: func(t *testing.T, p ec2predicate.Predicate) {
				assert.Equal(t, "[REDACTED]", p.Environment.Network.VPCID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh attestor for each test to avoid state pollution
			testAttestor := &Attestor{
				logger:   logger.NewNoop(),
				metadata: attestor.metadata,
				imdsInfo: attestor.imdsInfo,
			}

			predicate, err := testAttestor.GeneratePredicate(tt.config)
			require.NoError(t, err)

			ec2Pred, ok := predicate.(ec2predicate.Predicate)
			require.True(t, ok)

			tt.verify(t, ec2Pred)
		})
	}
}

// TestEmptyMetadata verifies handling of empty or incomplete metadata.
func TestEmptyMetadata(t *testing.T) {
	attestor := &Attestor{
		logger:   logger.NewNoop(),
		metadata: ec2predicate.InstanceMetadata{},
		imdsInfo: ec2predicate.IMDSInfo{
			Accessible: false,
		},
	}

	// Should still generate predicate without errors
	predicate, err := attestor.GeneratePredicate(core.Config{})
	require.NoError(t, err)
	require.NotNil(t, predicate)

	// Subjects may be empty or have empty values
	subjects := attestor.Subjects(core.Config{})
	assert.NotNil(t, subjects)
}
