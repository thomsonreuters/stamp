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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	awsec2 "github.com/thomsonreuters/stamp/pkg/clients/aws/ec2"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// TestCollectNetworkInfo tests the network information collection.
func TestCollectNetworkInfo(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(*awsec2.MockClient)
		expectError bool
		validate    func(*testing.T, *Attestor)
	}{
		{
			name: "successful_network_collection",
			setupMock: func(m *awsec2.MockClient) {
				m.On("GetNetworkInfo", mock.Anything, mock.Anything).Return(&awsec2.NetworkInfo{
					MACAddress:     "0a:1b:2c:3d:4e:5f",
					VPCID:          "vpc-12345",
					SubnetID:       "subnet-67890",
					SecurityGroups: []string{"sg-111", "sg-222"},
					PrivateIPv4:    "10.0.1.100",
					PublicIPv4:     "54.1.2.3",
					LocalHostname:  "ip-10-0-1-100",
					PublicHostname: "ec2-54-1-2-3.compute-1.amazonaws.com",
				}, nil)
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				assert.Equal(t, "vpc-12345", a.metadata.Network.VPCID)
				assert.Equal(t, "subnet-67890", a.metadata.Network.SubnetID)
				assert.Equal(t, "10.0.1.100", a.metadata.Network.PrivateIPv4)
				assert.Equal(t, "54.1.2.3", a.metadata.Network.PublicIPv4)
				assert.Len(t, a.metadata.Network.SecurityGroups, 2)
			},
		},
		{
			name: "network_collection_fails",
			setupMock: func(m *awsec2.MockClient) {
				m.On("GetNetworkInfo", mock.Anything, mock.Anything).Return(nil, errors.New("network unavailable"))
			},
			expectError: true,
			validate:    func(t *testing.T, a *Attestor) {},
		},
		{
			name: "network_collection_without_public_ip",
			setupMock: func(m *awsec2.MockClient) {
				m.On("GetNetworkInfo", mock.Anything, mock.Anything).Return(&awsec2.NetworkInfo{
					VPCID:       "vpc-12345",
					SubnetID:    "subnet-67890",
					PrivateIPv4: "10.0.1.100",
					// No public IP
				}, nil)
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				assert.Equal(t, "vpc-12345", a.metadata.Network.VPCID)
				assert.Empty(t, a.metadata.Network.PublicIPv4)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(awsec2.MockClient)
			tt.setupMock(mockClient)

			attestor := &Attestor{
				client: mockClient,
				logger: logger.NewNoop(),
			}

			opts := &awsec2.IMDSOptions{
				Endpoint: "http://169.254.169.254",
				Version:  "v2",
			}

			err := attestor.collectNetworkInfo(t.Context(), opts)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				tt.validate(t, attestor)
			}

			mockClient.AssertExpectations(t)
		})
	}
}

// TestCollectIAMInfo tests the IAM information collection.
func TestCollectIAMInfo(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(*awsec2.MockClient)
		expectError bool
		validate    func(*testing.T, *Attestor)
	}{
		{
			name: "successful_iam_collection",
			setupMock: func(m *awsec2.MockClient) {
				m.On("GetIAMInfo", mock.Anything, mock.Anything).Return(&awsec2.IAMInfo{
					Code:            "Success",
					LastUpdated:     time.Now(),
					InstanceProfile: "arn:aws:iam::123456789012:instance-profile/MyProfile",
				}, nil)
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				require.NotNil(t, a.metadata.IAM)
				assert.Equal(t, "Success", a.metadata.IAM.Code)
				assert.Equal(t, "arn:aws:iam::123456789012:instance-profile/MyProfile", a.metadata.IAM.InstanceProfile)
			},
		},
		{
			name: "iam_collection_fails",
			setupMock: func(m *awsec2.MockClient) {
				m.On("GetIAMInfo", mock.Anything, mock.Anything).Return(nil, errors.New("no IAM role attached"))
			},
			expectError: true,
			validate:    func(t *testing.T, a *Attestor) {},
		},
		{
			name: "iam_collection_with_empty_profile",
			setupMock: func(m *awsec2.MockClient) {
				m.On("GetIAMInfo", mock.Anything, mock.Anything).Return(&awsec2.IAMInfo{
					Code:            "Success",
					LastUpdated:     time.Now(),
					InstanceProfile: "",
				}, nil)
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				require.NotNil(t, a.metadata.IAM)
				assert.Equal(t, "Success", a.metadata.IAM.Code)
				assert.Empty(t, a.metadata.IAM.InstanceProfile)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(awsec2.MockClient)
			tt.setupMock(mockClient)

			attestor := &Attestor{
				client: mockClient,
				logger: logger.NewNoop(),
			}

			opts := &awsec2.IMDSOptions{
				Endpoint: "http://169.254.169.254",
				Version:  "v2",
			}

			err := attestor.collectIAMInfo(t.Context(), opts)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				tt.validate(t, attestor)
			}

			mockClient.AssertExpectations(t)
		})
	}
}

// TestCollectInstanceLifecycle tests the instance lifecycle detection.
func TestCollectInstanceLifecycle(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(*awsec2.MockClient)
		expectError   bool
		expectedValue string
		description   string
	}{
		{
			name: "spot_instance",
			setupMock: func(m *awsec2.MockClient) {
				m.On("GetInstanceLifecycle", mock.Anything, mock.Anything).Return("spot", nil)
			},
			expectError:   false,
			expectedValue: "spot",
			description:   "should detect spot instance",
		},
		{
			name: "scheduled_instance",
			setupMock: func(m *awsec2.MockClient) {
				m.On("GetInstanceLifecycle", mock.Anything, mock.Anything).Return("scheduled", nil)
			},
			expectError:   false,
			expectedValue: "scheduled",
			description:   "should detect scheduled instance",
		},
		{
			name: "lifecycle_detection_fails_defaults_to_on_demand",
			setupMock: func(m *awsec2.MockClient) {
				m.On("GetInstanceLifecycle", mock.Anything, mock.Anything).Return("", errors.New("not available"))
			},
			expectError:   false, // Should NOT return error - defaults to on-demand
			expectedValue: "on-demand",
			description:   "should default to on-demand when detection fails",
		},
		{
			name: "on_demand_explicit",
			setupMock: func(m *awsec2.MockClient) {
				m.On("GetInstanceLifecycle", mock.Anything, mock.Anything).Return("on-demand", nil)
			},
			expectError:   false,
			expectedValue: "on-demand",
			description:   "should handle explicit on-demand response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(awsec2.MockClient)
			tt.setupMock(mockClient)

			attestor := &Attestor{
				client: mockClient,
				logger: logger.NewNoop(),
			}

			opts := &awsec2.IMDSOptions{
				Endpoint: "http://169.254.169.254",
				Version:  "v2",
			}

			err := attestor.collectInstanceLifecycle(t.Context(), opts)

			if tt.expectError {
				require.Error(t, err, tt.description)
			} else {
				require.NoError(t, err, tt.description)
			}

			assert.Equal(t, tt.expectedValue, attestor.metadata.InstanceLifecycle, tt.description)
			mockClient.AssertExpectations(t)
		})
	}
}

// TestCollectTags tests the instance tags collection.
func TestCollectTags(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(*awsec2.MockClient)
		expectError bool
		validate    func(*testing.T, *Attestor)
	}{
		{
			name: "successful_tags_collection",
			setupMock: func(m *awsec2.MockClient) {
				m.On("GetAllTags", mock.Anything, mock.Anything).Return(map[string]string{
					"Name":        "test-instance",
					"Environment": "production",
					"Team":        "platform",
				}, nil)
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				assert.Len(t, a.metadata.Tags, 3)
				assert.Equal(t, "test-instance", a.metadata.Tags["Name"])
				assert.Equal(t, "production", a.metadata.Tags["Environment"])
				assert.Equal(t, "platform", a.metadata.Tags["Team"])
			},
		},
		{
			name: "tags_collection_fails_permission_denied",
			setupMock: func(m *awsec2.MockClient) {
				m.On("GetAllTags", mock.Anything, mock.Anything).Return(nil, errors.New("permission denied"))
			},
			expectError: true,
			validate:    func(t *testing.T, a *Attestor) {},
		},
		{
			name: "tags_collection_empty_tags",
			setupMock: func(m *awsec2.MockClient) {
				m.On("GetAllTags", mock.Anything, mock.Anything).Return(map[string]string{}, nil)
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				assert.Empty(t, a.metadata.Tags)
			},
		},
		{
			name: "tags_collection_with_special_characters",
			setupMock: func(m *awsec2.MockClient) {
				m.On("GetAllTags", mock.Anything, mock.Anything).Return(map[string]string{
					"aws:cloudformation:stack-name": "example-stack",
					"kubernetes.io/cluster/prod":    "owned",
				}, nil)
			},
			expectError: false,
			validate: func(t *testing.T, a *Attestor) {
				assert.Len(t, a.metadata.Tags, 2)
				assert.Equal(t, "example-stack", a.metadata.Tags["aws:cloudformation:stack-name"])
				assert.Equal(t, "owned", a.metadata.Tags["kubernetes.io/cluster/prod"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(awsec2.MockClient)
			tt.setupMock(mockClient)

			attestor := &Attestor{
				client: mockClient,
				logger: logger.NewNoop(),
			}

			opts := &awsec2.IMDSOptions{
				Endpoint: "http://169.254.169.254",
				Version:  "v2",
			}

			err := attestor.collectTags(t.Context(), opts)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				tt.validate(t, attestor)
			}

			mockClient.AssertExpectations(t)
		})
	}
}

// TestCollectInstanceMetadata tests the full metadata collection orchestration.
func TestCollectInstanceMetadata(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		setupMock func(*awsec2.MockClient)
		validate  func(*testing.T, *Attestor)
	}{
		{
			name: "full_collection_all_enabled",
			config: Config{
				IMDSOptions: &awsec2.IMDSOptions{
					Endpoint: "http://169.254.169.254",
					Version:  "v2",
				},
				IncludeNetwork: true,
				IncludeIAM:     true,
				IncludeTags:    true,
			},
			setupMock: func(m *awsec2.MockClient) {
				m.On("GetInstanceIdentityDocument", mock.Anything, mock.Anything).Return(&awsec2.InstanceIdentityDocument{
					InstanceID:   "i-1234567890abcdef0",
					InstanceType: "t3.micro",
					Region:       "us-east-1",
				}, nil)
				m.On("GetNetworkInfo", mock.Anything, mock.Anything).Return(&awsec2.NetworkInfo{
					VPCID: "vpc-12345",
				}, nil)
				m.On("GetIAMInfo", mock.Anything, mock.Anything).Return(&awsec2.IAMInfo{
					InstanceProfile: "test-profile",
				}, nil)
				m.On("GetInstanceLifecycle", mock.Anything, mock.Anything).Return("on-demand", nil)
				m.On("GetAllTags", mock.Anything, mock.Anything).Return(map[string]string{
					"Name": "test",
				}, nil)
			},
			validate: func(t *testing.T, a *Attestor) {
				assert.Equal(t, "i-1234567890abcdef0", a.metadata.IdentityDocument.InstanceID)
				assert.Equal(t, "vpc-12345", a.metadata.Network.VPCID)
				assert.NotNil(t, a.metadata.IAM)
				assert.Equal(t, "on-demand", a.metadata.InstanceLifecycle)
				assert.NotEmpty(t, a.metadata.Tags)
			},
		},
		{
			name: "minimal_collection_optional_disabled",
			config: Config{
				IMDSOptions: &awsec2.IMDSOptions{
					Endpoint: "http://169.254.169.254",
					Version:  "v2",
				},
				IncludeNetwork: false,
				IncludeIAM:     false,
				IncludeTags:    false,
			},
			setupMock: func(m *awsec2.MockClient) {
				m.On("GetInstanceIdentityDocument", mock.Anything, mock.Anything).Return(&awsec2.InstanceIdentityDocument{
					InstanceID:   "i-1234567890abcdef0",
					InstanceType: "t3.micro",
				}, nil)
				m.On("GetInstanceLifecycle", mock.Anything, mock.Anything).Return("", errors.New("not available"))
			},
			validate: func(t *testing.T, a *Attestor) {
				assert.Equal(t, "i-1234567890abcdef0", a.metadata.IdentityDocument.InstanceID)
				assert.Empty(t, a.metadata.Network.VPCID)                  // Not collected
				assert.Nil(t, a.metadata.IAM)                              // Not collected
				assert.Empty(t, a.metadata.Tags)                           // Not collected
				assert.Equal(t, "on-demand", a.metadata.InstanceLifecycle) // Default value
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(awsec2.MockClient)
			tt.setupMock(mockClient)

			attestor := &Attestor{
				client: mockClient,
				logger: logger.NewNoop(),
				config: tt.config,
			}

			err := attestor.collectInstanceMetadata(t.Context())
			require.NoError(t, err)

			tt.validate(t, attestor)
			mockClient.AssertExpectations(t)
		})
	}
}
