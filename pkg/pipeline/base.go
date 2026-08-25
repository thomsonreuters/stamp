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
	"github.com/thomsonreuters/stamp/pkg/signing/sigstore"
	"github.com/thomsonreuters/stamp/pkg/types"
)

// BasePipeline provides common infrastructure for all pipeline implementations.
// It handles configuration management and shared resource creation with caching.
type BasePipeline struct {
	config          config.ConfigurationIface
	sigstoreSigner  *sigstore.Signer
	sigstoreOpts    *sigstore.Options
	sigstoreLoaded  bool
	destManager     *destination.Manager
	metrics         *Metrics
	logger          logger.Logger
	output          output.OutputIface
}

// GetSigstoreSigner returns the cached sigstore signer instance (safe for reuse
// across many SignBundle calls).
func (p *BasePipeline) GetSigstoreSigner() *sigstore.Signer {
	if p.sigstoreSigner == nil {
		p.sigstoreSigner = sigstore.NewSigner(p.logger)
	}
	return p.sigstoreSigner
}

// GetSigstoreOptions returns a cached sigstore.Options built from configuration,
// or (nil, nil) if signing is not configured.
func (p *BasePipeline) GetSigstoreOptions(ctx context.Context) (*sigstore.Options, error) {
	if p.sigstoreLoaded {
		return p.sigstoreOpts, nil
	}

	backend := p.config.GetString(flags.Signer)
	if backend == "" {
		p.sigstoreLoaded = true
		return nil, nil //nolint:nilnil // Valid: nil options with nil error indicates signing is not configured
	}
	if backend != types.SignerKey.String() && backend != types.SignerFulcio.String() {
		return nil, ErrUnsupportedSigningBackend
	}

	opts, err := sigstore.BuildOptionsFromConfig(ctx, p.config, p.logger)
	if err != nil {
		return nil, err
	}
	p.sigstoreOpts = &opts
	p.sigstoreLoaded = true
	return p.sigstoreOpts, nil
}

// HasWorkflowContext returns whether this pipeline is executing within a workflow.
func (p *BasePipeline) HasWorkflowContext() bool {
	return false
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

	if !p.config.GetBool(flags.RunPersist) {
		return nil, nil //nolint:nilnil // Valid: nil manager indicates persist is not enabled
	}

	manager := destination.NewManager(nil, p.logger)

	dest, err := destination.Get("file")
	if err != nil {
		return nil, fmt.Errorf("failed to get file destination: %w", err)
	}

	template := p.config.GetString(flags.RunTemplate)
	if template == "" {
		template = "./attestations/${attestor}/${id}.sigstore.json"
	}

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
