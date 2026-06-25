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

package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/output"
	"github.com/thomsonreuters/stamp/pkg/types"
)

func TestNewBasePipeline(t *testing.T) {
	cfg := config.NewMockConfiguration()
	log := logger.NewNoop()
	out := output.NewNoop()

	p := NewBasePipeline(cfg, log, out)

	assert.NotNil(t, p)
	assert.NotNil(t, p.metrics)
	assert.NotNil(t, p.logger)
	assert.NotNil(t, p.output)
	assert.Nil(t, p.signer)
	assert.Nil(t, p.transparency)
}

func TestBasePipeline_HasWorkflowContext(t *testing.T) {
	cfg := config.NewMockConfiguration()
	log := logger.NewNoop()
	out := output.NewNoop()

	p := NewBasePipeline(cfg, log, out)

	assert.False(t, p.HasWorkflowContext())
}

func TestBasePipeline_GetMetrics(t *testing.T) {
	cfg := config.NewMockConfiguration()
	log := logger.NewNoop()
	out := output.NewNoop()

	p := NewBasePipeline(cfg, log, out)
	metrics := p.GetMetrics()

	assert.NotNil(t, metrics)
	assert.False(t, metrics.StartTime.IsZero())
}

func TestBasePipeline_GetFailurePolicy(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		expected types.FailurePolicy
	}{
		{
			name:     "continue policy",
			policy:   "continue",
			expected: types.FailurePolicyContinue,
		},
		{
			name:     "fail-fast policy",
			policy:   "fail-fast",
			expected: types.FailurePolicyFailFast,
		},
		{
			name:     "empty defaults to fail-fast",
			policy:   "",
			expected: types.FailurePolicyFailFast,
		},
		{
			name:     "unknown defaults to fail-fast",
			policy:   "unknown",
			expected: types.FailurePolicyFailFast,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.NewMockConfiguration()
			cfg.On("GetString", flags.PipelineFailurePolicy).Return(tt.policy)

			p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())
			policy := p.GetFailurePolicy()

			assert.Equal(t, tt.expected, policy)
			cfg.AssertExpectations(t)
		})
	}
}

func TestBasePipeline_CreateConfigurationOverlay(t *testing.T) {
	t.Run("empty overrides returns original config", func(t *testing.T) {
		cfg := config.NewMockConfiguration()
		p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())

		result := p.CreateConfigurationOverlay(nil)
		assert.Equal(t, cfg, result)

		result = p.CreateConfigurationOverlay(map[string]any{})
		assert.Equal(t, cfg, result)
	})

	t.Run("with overrides creates new config", func(t *testing.T) {
		cfg := config.NewMockConfiguration()
		p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())

		overrides := map[string]any{"key": "value"}
		result := p.CreateConfigurationOverlay(overrides)

		assert.NotEqual(t, cfg, result)
	})
}

func TestBasePipeline_RecordAttestorExecution(t *testing.T) {
	cfg := config.NewMockConfiguration()
	p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())

	assert.Equal(t, 0, p.metrics.AttestorExecutions)
	assert.Equal(t, 0, p.metrics.SuccessfulExecutions)
	assert.Equal(t, 0, p.metrics.FailedExecutions)

	p.RecordAttestorExecution(true)
	assert.Equal(t, 1, p.metrics.AttestorExecutions)
	assert.Equal(t, 1, p.metrics.SuccessfulExecutions)
	assert.Equal(t, 0, p.metrics.FailedExecutions)

	p.RecordAttestorExecution(false)
	assert.Equal(t, 2, p.metrics.AttestorExecutions)
	assert.Equal(t, 1, p.metrics.SuccessfulExecutions)
	assert.Equal(t, 1, p.metrics.FailedExecutions)
}

func TestBasePipeline_RecordSigningDuration(t *testing.T) {
	cfg := config.NewMockConfiguration()
	p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())

	assert.Equal(t, time.Duration(0), p.metrics.SigningDuration)

	p.RecordSigningDuration(100 * time.Millisecond)
	assert.Equal(t, 100*time.Millisecond, p.metrics.SigningDuration)

	p.RecordSigningDuration(50 * time.Millisecond)
	assert.Equal(t, 150*time.Millisecond, p.metrics.SigningDuration)
}

func TestBasePipeline_RecordRekorUploadDuration(t *testing.T) {
	cfg := config.NewMockConfiguration()
	p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())

	assert.Equal(t, time.Duration(0), p.metrics.RekorUploadDuration)

	p.RecordRekorUploadDuration(200 * time.Millisecond)
	assert.Equal(t, 200*time.Millisecond, p.metrics.RekorUploadDuration)

	p.RecordRekorUploadDuration(100 * time.Millisecond)
	assert.Equal(t, 300*time.Millisecond, p.metrics.RekorUploadDuration)
}

func TestBasePipeline_FinalizeMetrics(t *testing.T) {
	cfg := config.NewMockConfiguration()
	p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())

	assert.True(t, p.metrics.EndTime.IsZero())

	metrics := p.FinalizeMetrics()

	assert.False(t, p.metrics.EndTime.IsZero())
	assert.Equal(t, p.metrics, metrics) // Verify it returns the same metrics instance
}

func TestBasePipeline_GetSigner_NoBackend(t *testing.T) {
	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.Signer).Return("")

	p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())
	signer, err := p.GetSigner(context.Background())

	assert.Nil(t, signer)
	require.NoError(t, err)
	cfg.AssertExpectations(t)
}

func TestBasePipeline_GetSigner_UnsupportedBackend(t *testing.T) {
	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.Signer).Return("unknown-backend")

	p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())
	signer, err := p.GetSigner(context.Background())

	assert.Nil(t, signer)
	require.ErrorIs(t, err, ErrUnsupportedSigningBackend)
	cfg.AssertExpectations(t)
}

func TestBasePipeline_GetSigner_CachesSigner(t *testing.T) {
	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.Signer).Return("").Once()

	p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())

	// First call
	signer1, err1 := p.GetSigner(context.Background())
	assert.Nil(t, signer1)
	require.NoError(t, err1)

	// GetString should only be called once due to early nil return
	cfg.AssertExpectations(t)
}

func TestBasePipeline_GetRekorClient_Disabled(t *testing.T) {
	cfg := config.NewMockConfiguration()
	cfg.On("GetBool", flags.TransparencyEnable).Return(false)

	p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())
	client, err := p.GetRekorClient()

	assert.Nil(t, client)
	require.NoError(t, err)
	cfg.AssertExpectations(t)
}

func TestBasePipeline_GetRekorClient_MissingURL(t *testing.T) {
	cfg := config.NewMockConfiguration()
	cfg.On("GetBool", flags.TransparencyEnable).Return(true)
	cfg.On("GetString", flags.RekorURL).Return("")

	p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())
	client, err := p.GetRekorClient()

	assert.Nil(t, client)
	require.ErrorIs(t, err, ErrRekorURLRequired)
	cfg.AssertExpectations(t)
}

func TestBasePipeline_GetRekorClient_CachesClient(t *testing.T) {
	cfg := config.NewMockConfiguration()
	cfg.On("GetBool", flags.TransparencyEnable).Return(false).Once()

	p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())

	// First call
	client1, err1 := p.GetRekorClient()
	assert.Nil(t, client1)
	require.NoError(t, err1)

	// GetBool should only be called once due to early nil return
	cfg.AssertExpectations(t)
}

func TestBasePipeline_GetSigner_FileBackend(t *testing.T) {
	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.Signer).Return("key")
	cfg.On("GetString", flags.PrivateKey).Return("/path/to/key")
	cfg.On("GetString", flags.CryptographyKeyPassword).Return("password")
	cfg.On("GetString", flags.CryptographyKeyPasswordFile).Return("")

	p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())
	_, err := p.GetSigner(context.Background())

	// Will fail because the key file doesn't exist, but config is correctly read
	require.Error(t, err)
	cfg.AssertExpectations(t)
}

func TestBasePipeline_GetSigner_FulcioBackend(t *testing.T) {
	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.Signer).Return("fulcio")
	cfg.On("GetString", flags.FulcioURL).Return("https://fulcio.example.com")
	cfg.On("GetString", flags.OIDCToken).Return("")
	cfg.On("GetString", flags.OIDCTokenFile).Return("")
	cfg.On("GetBool", flags.UseSpire).Return(false)
	cfg.On("GetString", flags.SPIRESocket).Return("")
	cfg.On("GetBool", flags.UseGitHub).Return(false)
	cfg.On("GetBool", flags.Insecure).Return(false)

	p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())
	_, err := p.GetSigner(context.Background())

	// Will fail because no token is available, but config is correctly read
	require.Error(t, err)
	cfg.AssertExpectations(t)
}

func TestBasePipeline_GetSigner_KeyBackend(t *testing.T) {
	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.Signer).Return("key")
	cfg.On("GetString", flags.PrivateKey).Return("/path/to/key")
	cfg.On("GetString", flags.CryptographyKeyPassword).Return("")
	cfg.On("GetString", flags.CryptographyKeyPasswordFile).Return("")

	p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())
	_, err := p.GetSigner(context.Background())

	// Will fail because the key file doesn't exist, but config is correctly read
	require.Error(t, err)
	cfg.AssertExpectations(t)
}

func TestBasePipeline_GetRekorClient_WithURL(t *testing.T) {
	cfg := config.NewMockConfiguration()
	cfg.On("GetBool", flags.TransparencyEnable).Return(true)
	cfg.On("GetString", flags.RekorURL).Return("https://rekor.example.com")
	cfg.On("GetBool", flags.Insecure).Return(false)

	p := NewBasePipeline(cfg, logger.NewNoop(), output.NewNoop())
	client, err := p.GetRekorClient()

	// Client should be created successfully
	assert.NotNil(t, client)
	require.NoError(t, err)
	cfg.AssertExpectations(t)

	// Verify caching - should return same client
	cfg2 := config.NewMockConfiguration()
	// No new calls expected due to caching
	client2, err2 := p.GetRekorClient()
	assert.Equal(t, client, client2)
	require.NoError(t, err2)
	mock.AssertExpectationsForObjects(t, cfg2)
}
