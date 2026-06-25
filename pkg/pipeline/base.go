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

// Package pipeline provides the core pipeline execution infrastructure for attestation generation.
// It implements a hierarchical pipeline system: WorkflowPipeline → AttestorPipeline.
package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	"github.com/thomsonreuters/stamp/pkg/destination"
	_ "github.com/thomsonreuters/stamp/pkg/destination/file" // Register file destination
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/output"
	"github.com/thomsonreuters/stamp/pkg/signing"
	"github.com/thomsonreuters/stamp/pkg/transparency"
	"github.com/thomsonreuters/stamp/pkg/types"
)

// BasePipeline provides common infrastructure for all pipeline implementations.
// It handles configuration management and shared resource creation with caching.
type BasePipeline struct {
	config       config.ConfigurationIface
	signer       signing.Signer
	transparency *transparency.Client
	destManager  *destination.Manager
	metrics      *Metrics
	logger       logger.Logger
	output       output.OutputIface
}

// GetSigner returns a cached signer instance or nil if signing is not configured.
func (p *BasePipeline) GetSigner(ctx context.Context) (signing.Signer, error) {
	if p.signer != nil {
		return p.signer, nil
	}

	backend := p.config.GetString(flags.Signer)
	if backend == "" {
		return nil, nil //nolint:nilnil // Valid: nil signer with nil error indicates signing is not configured
	}

	signerConfig := signing.SignerConfig{Provider: backend}

	switch backend {
	case "key":
		signerConfig.Key = &signing.KeySignerConfig{
			KeyPath:         p.config.GetString(flags.PrivateKey),
			KeyPassword:     p.config.GetString(flags.CryptographyKeyPassword),
			KeyPasswordFile: p.config.GetString(flags.CryptographyKeyPasswordFile),
		}

	case "fulcio":
		signerConfig.Fulcio = &signing.FulcioSignerConfig{
			FulcioURL:        p.config.GetString(flags.FulcioURL),
			Token:            p.config.GetString(flags.OIDCToken),
			TokenPath:        p.config.GetString(flags.OIDCTokenFile),
			UseSpire:         p.config.GetBool(flags.UseSpire),
			SpireAgentSocket: p.config.GetString(flags.SPIRESocket),
			UseGitHub:        p.config.GetBool(flags.UseGitHub),
			Insecure:         p.config.GetBool(flags.Insecure),
		}

	default:
		return nil, ErrUnsupportedSigningBackend
	}

	signer, err := signing.NewSigner(ctx, signerConfig)
	if err != nil {
		return nil, err
	}

	if err := signer.PreSign(ctx, signerConfig); err != nil {
		return nil, err
	}

	p.signer = signer
	return signer, nil
}

// HasWorkflowContext returns whether this pipeline is executing within a workflow.
func (p *BasePipeline) HasWorkflowContext() bool {
	return false
}

// GetRekorClient returns a cached Rekor client or nil if transparency is not enabled.
func (p *BasePipeline) GetRekorClient() (*transparency.Client, error) {
	if p.transparency != nil {
		return p.transparency, nil
	}
	if !p.config.GetBool(flags.TransparencyEnable) {
		return nil, nil //nolint:nilnil // Valid: nil client with nil error indicates transparency is not enabled
	}

	rekorURL := p.config.GetString(flags.RekorURL)
	if rekorURL == "" {
		return nil, ErrRekorURLRequired
	}

	client, err := transparency.NewClient(rekorURL, p.config.GetBool(flags.Insecure), p.logger)
	if err != nil {
		return nil, ErrRekorClientFailed
	}

	p.transparency = client
	return client, nil
}

// GetMetrics returns current execution metrics.
func (p *BasePipeline) GetMetrics() *Metrics {
	return p.metrics
}

// GetDestinationManager returns a cached destination manager or creates one if --persist is enabled.
// Returns nil if persist mode is not enabled.
func (p *BasePipeline) GetDestinationManager() (*destination.Manager, error) {
	if p.destManager != nil {
		return p.destManager, nil
	}

	// Check if --persist flag is set
	if !p.config.GetBool(flags.RunPersist) {
		return nil, nil //nolint:nilnil // Valid: nil manager indicates persist is not enabled
	}

	// Create the manager
	manager := destination.NewManager(nil, p.logger)

	// Get file destination from registry
	dest, err := destination.Get("file")
	if err != nil {
		return nil, fmt.Errorf("failed to get file destination: %w", err)
	}

	// Get template from config or use default
	template := p.config.GetString(flags.RunTemplate)
	if template == "" {
		template = "./attestations/${attestor}/${id}.json"
	}

	// Configure file destination
	destConfig := map[string]any{
		"path":          template,
		"pretty":        true,
		"create_dirs":   true,
		"overwrite":     p.config.GetBool(flags.RunForce),
		"atomic_writes": true,
	}

	if err := dest.Configure(destConfig); err != nil {
		return nil, fmt.Errorf("failed to configure file destination: %w", err)
	}

	if err := manager.Add("persist-file", dest); err != nil {
		return nil, fmt.Errorf("failed to add file destination: %w", err)
	}

	// Cache the manager
	p.destManager = manager
	return manager, nil
}

// RecordDestinationWriteDuration adds destination write duration to metrics.
func (p *BasePipeline) RecordDestinationWriteDuration(duration time.Duration) {
	p.metrics.DestinationDuration += duration
}

// GetFailurePolicy returns the configured failure handling policy (defaults to fail-fast).
func (p *BasePipeline) GetFailurePolicy() types.FailurePolicy {
	policy := p.config.GetString(flags.PipelineFailurePolicy)

	if policy == types.FailurePolicyContinue.String() {
		return types.FailurePolicyContinue
	}

	return types.FailurePolicyFailFast
}

// CreateConfigurationOverlay creates a configuration overlay with the given overrides.
func (p *BasePipeline) CreateConfigurationOverlay(overrides map[string]any) config.ConfigurationIface {
	if len(overrides) == 0 {
		return p.config
	}
	return config.New(p.config, overrides)
}

// RecordAttestorExecution records metrics for an attestor execution attempt.
func (p *BasePipeline) RecordAttestorExecution(success bool) {
	p.metrics.AttestorExecutions++
	if success {
		p.metrics.SuccessfulExecutions++
	} else {
		p.metrics.FailedExecutions++
	}
}

// RecordSigningDuration adds signing duration to metrics.
func (p *BasePipeline) RecordSigningDuration(duration time.Duration) {
	p.metrics.SigningDuration += duration
}

// RecordRekorUploadDuration adds Rekor upload duration to metrics.
func (p *BasePipeline) RecordRekorUploadDuration(duration time.Duration) {
	p.metrics.RekorUploadDuration += duration
}

// FinalizeMetrics marks the pipeline execution as complete and returns the metrics.
func (p *BasePipeline) FinalizeMetrics() *Metrics {
	p.metrics.Finalize()
	return p.metrics
}

// NewBasePipeline creates a new base pipeline with the provided configuration.
func NewBasePipeline(cfg config.ConfigurationIface, logger logger.Logger, output output.OutputIface) *BasePipeline {
	return &BasePipeline{
		config:  cfg,
		logger:  logger,
		output:  output,
		metrics: NewMetrics(),
	}
}
