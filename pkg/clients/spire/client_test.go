// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package spire

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockWorkloadAPIClient is a mock for WorkloadAPIClient used in tests.
type mockWorkloadAPIClient struct {
	mock.Mock
}

func (m *mockWorkloadAPIClient) FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(*jwtsvid.SVID)
	return result, args.Error(1)
}

func (m *mockWorkloadAPIClient) Close() error {
	return m.Called().Error(0)
}

func TestClient_FetchJWTToken_Error(t *testing.T) {
	ctx := t.Context()
	audience := "test-audience"
	expectedErr := errors.New("connection failed")

	mockAPI := &mockWorkloadAPIClient{}
	mockAPI.On("FetchJWTSVID", ctx, jwtsvid.Params{Audience: audience}).Return(nil, expectedErr)

	client := &Client{workloadAPIClient: mockAPI}

	token, err := client.FetchJWTToken(ctx, audience)

	require.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Empty(t, token)
	mockAPI.AssertExpectations(t)
}

func TestClient_Close_WithClient(t *testing.T) {
	mockAPI := &mockWorkloadAPIClient{}
	mockAPI.On("Close").Return(nil)

	client := &Client{workloadAPIClient: mockAPI}

	err := client.Close()

	require.NoError(t, err)
	mockAPI.AssertExpectations(t)
}

func TestClient_Close_WithClientError(t *testing.T) {
	expectedErr := errors.New("close failed")

	mockAPI := &mockWorkloadAPIClient{}
	mockAPI.On("Close").Return(expectedErr)

	client := &Client{workloadAPIClient: mockAPI}

	err := client.Close()

	require.Error(t, err)
	assert.Equal(t, expectedErr, err)
	mockAPI.AssertExpectations(t)
}

func TestClient_Close_NilClient(t *testing.T) {
	client := &Client{workloadAPIClient: nil}

	err := client.Close()

	require.NoError(t, err)
}

func TestGetSocketPath_Default(t *testing.T) {
	_ = os.Unsetenv(SocketPathEnvVar)

	path := GetSocketPath()

	assert.Equal(t, defaultSocketPath, path)
}

func TestGetSocketPath_FromEnvVar(t *testing.T) {
	customPath := "unix:///custom/spire/socket.sock"

	t.Setenv(SocketPathEnvVar, customPath)

	path := GetSocketPath()

	assert.Equal(t, customPath, path)
}

func TestGetSocketPath_EmptyEnvVar(t *testing.T) {
	t.Setenv(SocketPathEnvVar, "")

	path := GetSocketPath()

	assert.Equal(t, defaultSocketPath, path)
}
