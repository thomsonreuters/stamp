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
	"crypto/sha256"
	"encoding/hex"
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

	statementBytes, err := p.ExecuteAttestor(ctx)
	signedResult := SignedResult{
		StatementJSON: statementBytes,
		AttestorName:  p.name,
		PredicateType: p.getPredicateType(),
	}
	if err != nil {
		p.RecordAttestorExecution(false)
		signedResult.Error = err
		p.result.Attestations = append(p.result.Attestations, signedResult)
		return pkgerrors.WrapPipeline(err, "attestation", p.name).
			Suggest(
				fmt.Sprintf("Run 'stamp list %s --show-config' to verify configuration", p.name),
				"Check attestor prerequisites are met",
				"Verify required resources are available",
			)
	}
	p.RecordAttestorExecution(true)

	bundleJSON, err := p.signAndBundle(ctx, statementBytes)
	if err != nil {
		signedResult.Error = err
		p.result.Attestations = append(p.result.Attestations, signedResult)
		return pkgerrors.WrapPipeline(err, "signing", p.name).
			Suggest(
				"Check signer configuration (file/fulcio)",
				"Verify signing key exists and is accessible",
				"Check network connectivity for Fulcio and Rekor",
			)
	}
	signedResult.BundleJSON = bundleJSON

	if err := p.handleStdoutOutput(ctx, signedResult); err != nil {
		signedResult.Error = err
		p.result.Attestations = append(p.result.Attestations, signedResult)
		return pkgerrors.WrapPipeline(err, "output", p.name).
			Suggest(
				"Check --output-format flag value",
				"Verify stdout is not redirected or blocked",
			)
	}

	if err := p.handlePersistOutput(ctx, signedResult); err != nil {
		signedResult.Error = err
		p.result.Attestations = append(p.result.Attestations, signedResult)
		return pkgerrors.WrapPipeline(err, "persist", p.name).
			Suggest(
				"Check --template path is writable",
				"Use --force to overwrite existing files",
			)
	}

	p.result.Attestations = append(p.result.Attestations, signedResult)

	p.result.Metrics = p.FinalizeMetrics()

	logger.InfoContext(ctx, "pipeline completed successfully",
		"duration_ms", p.GetMetrics().Duration().Milliseconds(),
	)
	p.output.Success("Attestation for %s completed successfully", p.name)

	return nil
}

// ExecuteAttestor runs the attestor lifecycle and returns the in-toto Statement bytes.
func (p *AttestorPipeline) ExecuteAttestor(ctx context.Context) ([]byte, error) {
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

	subjects := attestor.Subjects(attestorConfig)
	p.logger.InfoContext(ctx, "creating in-toto statement", "subject_count", len(subjects))

	statement, err := intoto.NewStatement(attestor.PredicateURI(), predicate, subjects)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "intoto", "create_statement",
			fmt.Sprintf("failed to create statement for attestor: %s (predicate: %s)", p.name, attestor.PredicateURI()))
	}

	payload, err := statement.ToJSON()
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "intoto", "serialize_statement",
			fmt.Sprintf("failed to serialize statement for attestor: %s", p.name))
	}

	return payload, nil
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

// signAndBundle signs the statement payload into a sigstore Bundle v0.3.
// Returns (nil, nil) when signing is not configured; callers must handle
// nil bundle bytes and fall back to the raw statement.
func (p *AttestorPipeline) signAndBundle(ctx context.Context, payload []byte) ([]byte, error) {
	if p.HasWorkflowContext() {
		// Workflow pipeline owns signing so key/token material is reused
		// across per-attestor bundles + the collection.
		p.logger.DebugContext(ctx, "skipping attestor-level signing — handled by workflow pipeline")
		return nil, nil
	}

	opts, err := p.GetSigstoreOptions(ctx)
	if err != nil {
		return nil, err
	}
	if opts == nil {
		p.logger.DebugContext(ctx, "no signer configured, attestation will not be bundled")
		return nil, nil
	}

	start := time.Now()
	p.logger.InfoContext(ctx, "signing attestation via sigstore Bundle")

	res, err := p.GetSigstoreSigner().SignBundle(ctx, payload, intoto.PayloadType, *opts)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "signing", "sigstore_bundle",
			fmt.Sprintf("failed to sign bundle for attestor: %s", p.name))
	}

	duration := time.Since(start)
	p.RecordSigningDuration(duration)
	if opts.Rekor != nil {
		p.RecordRekorUploadDuration(duration)
	}
	return res.BundleJSON, nil
}

// handleStdoutOutput writes the attestation to stdout. When signing is
// configured it emits the sigstore Bundle v0.3; otherwise it emits the raw
// in-toto Statement.
func (p *AttestorPipeline) handleStdoutOutput(ctx context.Context, result SignedResult) error {
	if p.HasWorkflowContext() {
		p.logger.DebugContext(ctx, "skipping stdout output - handled by workflow pipeline")
		return nil
	}

	if !p.output.IsDataOutputEnabled() {
		p.logger.DebugContext(ctx, "stdout data output disabled")
		return nil
	}

	payload := result.BundleJSON
	if len(payload) == 0 {
		payload = result.StatementJSON
	}
	if len(payload) == 0 {
		return nil
	}

	p.logger.DebugContext(ctx, "writing attestation to stdout")
	if err := p.output.Data(p.logger, "attestation generated", rawJSON(payload)); err != nil {
		if p.GetFailurePolicy() == types.FailurePolicyFailFast {
			return pkgerrors.WrapWithContext(err, "output", "stdout_write",
				fmt.Sprintf("failed to write attestation to stdout for attestor: %s", p.name))
		}
		p.logger.WarnContext(ctx, "continuing despite stdout write failure")
	}

	return nil
}

// handlePersistOutput writes the attestation bundle to a file if --persist is enabled.
func (p *AttestorPipeline) handlePersistOutput(ctx context.Context, result SignedResult) error {
	if p.HasWorkflowContext() {
		p.logger.DebugContext(ctx, "skipping persist output - handled by workflow pipeline")
		return nil
	}

	if len(result.BundleJSON) == 0 {
		p.logger.DebugContext(ctx, "no bundle available to persist (unsigned attestation)")
		return nil
	}

	manager, err := p.GetDestinationManager()
	if err != nil {
		return pkgerrors.WrapWithContext(err, "persist", "get_manager",
			fmt.Sprintf("failed to get destination manager for attestor: %s", p.name))
	}

	if manager == nil {
		return nil
	}

	attestor, err := core.GetAttestorByID(p.attestorID, p.logger)
	predicateType := ""
	if err == nil {
		predicateType = attestor.PredicateURI()
	}

	sha := sha256.Sum256(result.BundleJSON)

	attestation := &destination.Attestation{
		ID:            uuid.New().String(),
		AttestorID:    p.name,
		PredicateType: predicateType,
		Bundle:        result.BundleJSON,
		Timestamp:     time.Now(),
		SHA256:        hex.EncodeToString(sha[:]),
		WorkflowName:  p.workflow,
	}

	start := time.Now()
	writeResult, err := manager.Write(ctx, attestation, destination.WriteOptions{
		FailurePolicy: destination.FailurePolicyFailFast,
	})
	if err != nil {
		return pkgerrors.WrapWithContext(err, "persist", "write",
			fmt.Sprintf("failed to write attestation for attestor: %s", p.name))
	}

	duration := time.Since(start)
	p.RecordDestinationWriteDuration(duration)

	for name, wr := range writeResult.Successful {
		p.logger.InfoContext(ctx, "attestation persisted",
			"destination", name,
			"location", wr.Location,
			"size", wr.Size)
		p.output.Success("Attestation saved to: %s", wr.Location)
	}

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

// rawJSON adapts pre-serialized JSON bytes to the OutputIface.Data JSON encoder
// so we don't double-encode a byte slice as a base64 string.
type rawJSON []byte

func (r rawJSON) MarshalJSON() ([]byte, error) {
	if len(r) == 0 {
		return []byte("null"), nil
	}
	return []byte(r), nil
}

// NewAttestorPipeline creates a new pipeline for direct attestor execution.
func NewAttestorPipeline(attestorID string, cfg config.ConfigurationIface, logger logger.Logger, output output.OutputIface) *AttestorPipeline {
	return &AttestorPipeline{
		BasePipeline: NewBasePipeline(cfg, logger, output),
		attestorID:   attestorID,
		name:         attestorID,
		result:       &Result{Attestations: make([]SignedResult, 0)},
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
		result:       &Result{Attestations: make([]SignedResult, 0)},
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
