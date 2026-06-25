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

package pipeline

import (
	"context"
	"fmt"
	"maps"
	"time"

	"github.com/google/uuid"
	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/destination"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/output"
	"github.com/thomsonreuters/stamp/pkg/types"
)

// AttestorPipeline executes a single attestor to generate an attestation.
// It handles the complete lifecycle: attestor execution, signing, and output.
type AttestorPipeline struct {
	*BasePipeline
	attestorID string
	name       string
	workflow   string
	result     *Result
}

// Execute runs the attestor pipeline.
func (p *AttestorPipeline) Execute(ctx context.Context) error {
	logFields := []any{"attestor_id", p.attestorID}
	if p.name != p.attestorID {
		logFields = append(logFields, "attestor_name", p.name)
	}
	if p.HasWorkflowContext() {
		logFields = append(logFields, "workflow", p.workflow)
	}
	logger := p.logger.With(logFields...)

	logger.InfoContext(ctx, "starting attestor pipeline")
	p.output.Progress("Generating attestation for %s...", p.name)

	defer func() {
		if p.signer != nil {
			if err := p.signer.PostSign(ctx); err != nil {
				logger.WarnContext(ctx, "signer cleanup failed", "error", err)
			}
		}
	}()

	envelope, err := p.ExecuteAttestor(ctx)
	// AttestorName is p.name which is:
	// - For single attestor execution: the attestorID (e.g., "git", "command")
	// - For workflow execution: the configured instance name from workflow config
	envelopeResult := EnvelopeResult{
		Envelope:      envelope,
		AttestorName:  p.name,
		PredicateType: p.getPredicateType(),
	}
	if err != nil {
		p.RecordAttestorExecution(false)
		envelopeResult.Error = err
		p.result.Attestations = append(p.result.Attestations, envelopeResult)
		return pkgerrors.WrapPipeline(err, "attestation", p.name).
			Suggest(
				fmt.Sprintf("Run 'stamp list %s --show-config' to verify configuration", p.name),
				"Check attestor prerequisites are met",
				"Verify required resources are available",
			)
	}
	p.RecordAttestorExecution(true)

	if err := p.SignEnvelope(ctx, envelope); err != nil {
		envelopeResult.Error = err
		p.result.Attestations = append(p.result.Attestations, envelopeResult)
		return pkgerrors.WrapPipeline(err, "signing", p.name).
			Suggest(
				"Check signer configuration (file/fulcio)",
				"Verify signing key exists and is accessible",
				"Check network connectivity for Fulcio signer",
			)
	}

	if err := p.handleStdoutOutput(ctx, envelope); err != nil {
		envelopeResult.Error = err
		p.result.Attestations = append(p.result.Attestations, envelopeResult)
		return pkgerrors.WrapPipeline(err, "output", p.name).
			Suggest(
				"Check --output-format flag value",
				"Verify stdout is not redirected or blocked",
			)
	}

	if err := p.handlePersistOutput(ctx, envelope); err != nil {
		envelopeResult.Error = err
		p.result.Attestations = append(p.result.Attestations, envelopeResult)
		return pkgerrors.WrapPipeline(err, "persist", p.name).
			Suggest(
				"Check --template path is writable",
				"Use --force to overwrite existing files",
			)
	}

	if err := p.uploadToRekor(ctx, envelope); err != nil {
		envelopeResult.Error = err
		p.result.Attestations = append(p.result.Attestations, envelopeResult)
		return pkgerrors.WrapPipeline(err, "transparency", p.name).
			Suggest(
				"Check Rekor URL configuration",
				"Verify network connectivity to transparency log",
				"Check if attestation is signed (required for Rekor)",
			)
	}

	p.result.Attestations = append(p.result.Attestations, envelopeResult)

	p.result.Metrics = p.FinalizeMetrics()

	logger.InfoContext(ctx, "pipeline completed successfully",
		"duration_ms", p.GetMetrics().Duration().Milliseconds(),
	)
	p.output.Success("Attestation for %s completed successfully", p.name)

	return nil
}

// ExecuteAttestor runs the attestor lifecycle and generates an envelope.
func (p *AttestorPipeline) ExecuteAttestor(ctx context.Context) (*intoto.Envelope, error) {
	attestor, err := core.GetAttestorByID(p.attestorID, p.logger)
	if err != nil {
		p.logger.ErrorContext(ctx, "attestor not found", "error", err)
		return nil, pkgerrors.WrapAttestor(err, p.name, "initialization")
	}

	attestorConfig, err := p.getAttestorConfig()
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "pipeline", "get_attestor_config",
			fmt.Sprintf("failed to get configuration for attestor: %s (id: %s)", p.name, p.attestorID))
	}

	p.logger.DebugContext(ctx, "validating attestor configuration")
	if validateErr := attestor.ValidateConfig(attestorConfig); validateErr != nil {
		p.logger.ErrorContext(ctx, "attestor configuration validation failed", "error", validateErr)
		wrappedErr := pkgerrors.WrapWithContext(validateErr, "attestor", "validate_config",
			fmt.Sprintf("invalid attestor configuration for: %s (id: %s)", p.name, p.attestorID))
		_ = wrappedErr.Suggest(
			fmt.Sprintf("Check attestor.%s configuration in config file", p.name),
			"Verify all required parameters are set",
			"Run 'stamp list --show-config' to see attestor configurations",
		)
		return nil, wrappedErr
	}
	p.logger.DebugContext(ctx, "attestor configuration validated successfully")

	if lifecycleErr := p.runAttestorLifecycle(ctx, attestor, attestorConfig); lifecycleErr != nil {
		return nil, lifecycleErr
	}

	p.logger.InfoContext(ctx, "generating predicate", "predicate_type", attestor.PredicateURI())
	predicate, err := attestor.GeneratePredicate(attestorConfig)
	if err != nil {
		p.logger.ErrorContext(ctx, "predicate generation failed", "error", err)
		return nil, pkgerrors.WrapAttestor(err, p.name, "predicate-generation")
	}
	p.logger.InfoContext(ctx, "predicate generated successfully")

	envelope, err := p.createEnvelope(ctx, attestor, predicate, attestorConfig)
	if err != nil {
		return nil, err
	}

	return envelope, nil
}

// getAttestorConfig retrieves and merges attestor configuration from config file and command-line flags.
func (p *AttestorPipeline) getAttestorConfig() (core.Config, error) {
	configKey := fmt.Sprintf("attestor.%s", p.name)
	attestorConfig := make(core.Config)

	if p.config.IsSet(configKey) {
		if err := p.config.UnmarshalKey(configKey, &attestorConfig); err != nil {
			return nil, pkgerrors.WrapWithContext(err, "pipeline", "unmarshal_attestor_config",
				fmt.Sprintf("failed to unmarshal base configuration for attestor: %s", p.name))
		}
	}

	setFlags := p.config.GetStringSlice(flags.RunSet)
	if len(setFlags) > 0 {
		setConfig, err := config.ParseSetFlags(setFlags, p.attestorID)
		if err != nil {
			return nil, pkgerrors.WrapWithContext(err, "pipeline", "parse_set_flags",
				fmt.Sprintf("failed to parse --set flags for attestor: %s (id: %s)", p.name, p.attestorID))
		}

		maps.Copy(attestorConfig, setConfig)
		return attestorConfig, nil
	}

	return attestorConfig, nil
}

// runAttestorLifecycle executes the pre-attest, attest, and post-attest phases of an attestor.
func (p *AttestorPipeline) runAttestorLifecycle(ctx context.Context, attestor core.Attestor, config core.Config) error {
	if err := attestor.PreAttest(ctx, config); err != nil {
		p.logger.ErrorContext(ctx, "pre-attest phase failed", "error", err)
		return pkgerrors.WrapAttestor(err, p.name, "pre-attest")
	}

	if err := attestor.Attest(ctx, config); err != nil {
		return pkgerrors.WrapAttestor(err, p.name, "attest")
	}

	if err := attestor.PostAttest(ctx, config); err != nil {
		return pkgerrors.WrapAttestor(err, p.name, "post-attest")
	}

	return nil
}

// createEnvelope creates the in-toto statement and DSSE envelope.
func (p *AttestorPipeline) createEnvelope(ctx context.Context, attestor core.Attestor, predicate any, config core.Config) (*intoto.Envelope, error) {
	subjects := attestor.Subjects(config)
	p.logger.InfoContext(ctx, "creating in-toto statement", "subject_count", len(subjects))

	statement, err := intoto.NewStatement(attestor.PredicateURI(), predicate, subjects)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "intoto", "create_statement",
			fmt.Sprintf("failed to create statement for attestor: %s (predicate: %s)", p.name, attestor.PredicateURI()))
	}

	p.logger.InfoContext(ctx, "creating DSSE envelope")
	envelope, err := intoto.NewEnvelope(statement)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "intoto", "create_envelope",
			fmt.Sprintf("failed to create envelope for attestor: %s", p.name))
	}

	return envelope, nil
}

// SignEnvelope signs the attestation envelope if signing is configured.
func (p *AttestorPipeline) SignEnvelope(ctx context.Context, envelope *intoto.Envelope) error {
	signer, err := p.GetSigner(ctx)
	if err != nil {
		return err
	}
	if signer == nil {
		p.logger.DebugContext(ctx, "no signer configured, attestation will be unsigned")
		return nil
	}

	start := time.Now()
	p.logger.InfoContext(ctx, "signing attestation envelope")

	if err := envelope.Sign(ctx, signer); err != nil {
		return pkgerrors.WrapWithContext(err, "signing", "sign_envelope",
			fmt.Sprintf("failed to sign envelope for attestor: %s", p.name))
	}

	duration := time.Since(start)
	p.RecordSigningDuration(duration)

	return nil
}

// handleStdoutOutput writes the attestation envelope to stdout if output is enabled.
func (p *AttestorPipeline) handleStdoutOutput(ctx context.Context, envelope *intoto.Envelope) error {
	if p.HasWorkflowContext() {
		p.logger.DebugContext(ctx, "skipping stdout output - handled by workflow pipeline")
		return nil
	}

	if !p.output.IsDataOutputEnabled() {
		p.logger.DebugContext(ctx, "stdout data output disabled")
		return nil
	}

	p.logger.DebugContext(ctx, "writing attestation to stdout")
	if err := p.output.Data(p.logger, "attestation generated", envelope); err != nil {
		if p.GetFailurePolicy() == types.FailurePolicyFailFast {
			return pkgerrors.WrapWithContext(err, "output", "stdout_write",
				fmt.Sprintf("failed to write attestation to stdout for attestor: %s", p.name))
		}
		p.logger.WarnContext(ctx, "continuing despite stdout write failure")
	}

	return nil
}

// handlePersistOutput writes the attestation envelope to a file if --persist is enabled.
// Uses the destination system for file writing with template variable resolution.
func (p *AttestorPipeline) handlePersistOutput(ctx context.Context, envelope *intoto.Envelope) error {
	if p.HasWorkflowContext() {
		p.logger.DebugContext(ctx, "skipping persist output - handled by workflow pipeline")
		return nil
	}

	manager, err := p.GetDestinationManager()
	if err != nil {
		return pkgerrors.WrapWithContext(err, "persist", "get_manager",
			fmt.Sprintf("failed to get destination manager for attestor: %s", p.name))
	}

	// No destinations configured (persist not enabled)
	if manager == nil {
		return nil
	}

	attestor, err := core.GetAttestorByID(p.attestorID, p.logger)
	predicateType := ""
	if err == nil {
		predicateType = attestor.PredicateURI()
	}

	sha256Hash, _ := envelope.SHA256()

	attestation := &destination.Attestation{
		ID:            uuid.New().String(),
		AttestorID:    p.name,
		PredicateType: predicateType,
		Envelope:      envelope,
		Timestamp:     time.Now(),
		SHA256:        sha256Hash,
		WorkflowName:  p.workflow,
	}

	start := time.Now()
	result, err := manager.Write(ctx, attestation, destination.WriteOptions{
		FailurePolicy: destination.FailurePolicyFailFast,
	})
	if err != nil {
		return pkgerrors.WrapWithContext(err, "persist", "write",
			fmt.Sprintf("failed to write attestation for attestor: %s", p.name))
	}

	duration := time.Since(start)
	p.RecordDestinationWriteDuration(duration)

	for name, writeResult := range result.Successful {
		p.logger.InfoContext(ctx, "attestation persisted",
			"destination", name,
			"location", writeResult.Location,
			"size", writeResult.Size)
		p.output.Success("Attestation saved to: %s", writeResult.Location)
	}

	return nil
}

// uploadToRekor uploads the attestation envelope to the Rekor transparency log.
func (p *AttestorPipeline) uploadToRekor(ctx context.Context, envelope *intoto.Envelope) error {
	if p.HasWorkflowContext() {
		p.logger.DebugContext(ctx, "skipping rekor upload - handled by workflow pipeline")
		return nil
	}

	client, err := p.GetRekorClient()
	if err != nil {
		return err
	}
	if client == nil {
		p.logger.DebugContext(ctx, "rekor not configured")
		return nil
	}

	start := time.Now()
	p.logger.InfoContext(ctx, "uploading attestation to transparency log")
	publicKeyPath := p.config.GetString(flags.PublicKey)

	entry, err := client.Upload(ctx, envelope, publicKeyPath, nil)
	if err != nil {
		p.logger.ErrorContext(ctx, "rekor upload failed", "error", err)
		if p.GetFailurePolicy() == types.FailurePolicyFailFast {
			rekorURL := p.config.GetString(flags.RekorURL)
			return pkgerrors.WrapWithContext(err, "transparency", "upload_rekor",
				fmt.Sprintf("failed to upload to rekor for attestor: %s (url: %s)", p.name, rekorURL))
		}
		p.logger.WarnContext(ctx, "continuing despite rekor upload failure")
		return nil
	}

	duration := time.Since(start)
	p.RecordRekorUploadDuration(duration)

	p.logger.InfoContext(ctx, "attestation uploaded to transparency log",
		"entry_uuid", entry.UUID,
		"log_index", entry.LogIndex,
		"duration_ms", duration.Milliseconds(),
	)
	p.output.Success("Attestation uploaded to transparency log (UUID: %s)", entry.UUID)

	return nil
}

// getPredicateType returns the predicate type URI for the attestor.
func (p *AttestorPipeline) getPredicateType() string {
	attestor, err := core.GetAttestorByID(p.attestorID, p.logger)
	if err != nil {
		return ""
	}
	return attestor.PredicateURI()
}

// GetResult returns the pipeline execution result.
func (p *AttestorPipeline) GetResult() *Result {
	if p.result.Metrics == nil {
		p.result.Metrics = p.GetMetrics()
	}
	return p.result
}

// HasWorkflowContext returns whether this pipeline is executing within a workflow.
func (p *AttestorPipeline) HasWorkflowContext() bool {
	return p.workflow != ""
}

// NewAttestorPipeline creates a new pipeline for direct attestor execution.
func NewAttestorPipeline(attestorID string, cfg config.ConfigurationIface, logger logger.Logger, output output.OutputIface) *AttestorPipeline {
	return &AttestorPipeline{
		BasePipeline: NewBasePipeline(cfg, logger, output),
		attestorID:   attestorID,
		name:         attestorID,
		result:       &Result{Attestations: make([]EnvelopeResult, 0)},
	}
}

// NewNamedAttestorPipeline creates a pipeline with an explicit instance name.
func NewNamedAttestorPipeline(
	attestorID, instanceName string,
	cfg config.ConfigurationIface,
	logger logger.Logger,
	output output.OutputIface,
) *AttestorPipeline {
	return &AttestorPipeline{
		BasePipeline: NewBasePipeline(cfg, logger, output),
		attestorID:   attestorID,
		name:         instanceName,
		result:       &Result{Attestations: make([]EnvelopeResult, 0)},
	}
}

// NewAttestorPipelineWithWorkflow creates an attestor pipeline with workflow context.
func NewAttestorPipelineWithWorkflow(
	attestorID, instanceName, workflowName string,
	cfg config.ConfigurationIface,
	logger logger.Logger,
	output output.OutputIface,
) *AttestorPipeline {
	pipeline := NewNamedAttestorPipeline(attestorID, instanceName, cfg, logger, output)
	pipeline.workflow = workflowName
	return pipeline
}
