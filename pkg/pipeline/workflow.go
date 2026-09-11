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
	"time"

	"github.com/google/uuid"
	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	"github.com/thomsonreuters/stamp/pkg/destination"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/output"
	collectionv1 "github.com/thomsonreuters/stamp/pkg/predicates/collection/v1"
	"github.com/thomsonreuters/stamp/pkg/types"
)

// OutputMode controls how attestations are output.
type OutputMode string

const (
	// OutputModeIndividual outputs each attestation separately.
	OutputModeIndividual OutputMode = "individual"

	// OutputModeCollection bundles all attestations into a collection.
	OutputModeCollection OutputMode = "collection"

	// OutputModeBoth outputs both individual attestations and a collection.
	OutputModeBoth OutputMode = "both"
)

// WorkflowPipeline executes a workflow containing multiple attestors.
// It handles the complete lifecycle for each attestor in the workflow and
// can output results as individual attestations, a collection, or both.
type WorkflowPipeline struct {
	*BasePipeline
	workflow *config.Workflow
	name     string
	result   *Result
	// cachedCollection is signed once and reused across stdout, persist,
	// and upload so all destinations reference the same tlog entry.
	cachedCollection *CollectionResult
}

// HasWorkflowContext returns true as WorkflowPipeline always has workflow context.
func (p *WorkflowPipeline) HasWorkflowContext() bool {
	return true
}

// Execute runs all attestors defined in the workflow.
func (p *WorkflowPipeline) Execute(ctx context.Context) error {
	p.logger.InfoContext(ctx, "starting workflow pipeline")
	p.output.Progress("Executing workflow: %s", p.name)

	wf, err := p.loadWorkflow()
	if err != nil {
		return err
	}
	p.workflow = wf

	workflowOverlay := p.createWorkflowOverlay(wf)

	if err := p.executeAttestors(ctx, wf, workflowOverlay); err != nil {
		if getFailurePolicyFromConfig(workflowOverlay) == types.FailurePolicyFailFast {
			return err
		}
		p.logger.WarnContext(ctx, "workflow completed with errors", "error", err)
	}

	// Workflow owns signing so the same signer is reused across all
	// per-attestor bundles and the collection.
	if err := p.signAttestations(ctx); err != nil {
		return pkgerrors.WrapPipeline(err, "signing", p.name).
			Suggest(
				"Check signer configuration (file/fulcio)",
				"Verify signing key exists and is accessible",
				"Check network connectivity for Fulcio and Rekor",
			)
	}

	// Ensure collection is created for collection/both modes regardless of
	// output configuration, so library consumers can always access it.
	if err := p.ensureCollection(ctx, workflowOverlay); err != nil {
		return pkgerrors.WrapPipeline(err, "collection-creation", p.name).
			Suggest(
				"Check workflow output mode configuration",
				"Verify signer configuration for collection signing",
			)
	}

	if err := p.handleOutput(ctx, workflowOverlay); err != nil {
		return pkgerrors.WrapPipeline(err, "output-handling", p.name).
			Suggest(
				"Check workflow output configuration",
				"Verify output accessibility",
				"Check write permissions for output locations",
			)
	}

	p.result.Metrics = p.FinalizeMetrics()

	successful := p.result.Successful()
	failed := p.result.Failed()

	p.logger.InfoContext(ctx, "workflow pipeline completed",
		"duration_ms", p.GetMetrics().Duration().Milliseconds(),
		"attestors_executed", len(p.result.Attestations),
		"attestors_succeeded", len(successful),
		"attestors_failed", len(failed),
	)

	if len(failed) > 0 {
		p.output.Warning("Workflow %s completed with %d failures", p.name, len(failed))
	} else {
		p.output.Success("Workflow %s completed successfully (%d attestors)", p.name, len(successful))
	}

	return nil
}

// loadWorkflow retrieves the workflow definition from configuration by name.
func (p *WorkflowPipeline) loadWorkflow() (*config.Workflow, error) {
	var workflows []config.Workflow
	if err := p.config.UnmarshalKey(flags.Workflows, &workflows); err != nil {
		return nil, pkgerrors.WrapWithContext(err, "workflow", "load_workflows",
			fmt.Sprintf("failed to load workflows for: %s", p.name))
	}

	for _, wf := range workflows {
		if wf.Name == p.name {
			if err := wf.Validate(); err != nil {
				return nil, err
			}
			return &wf, nil
		}
	}

	wrappedErr := pkgerrors.NewWithContext("workflow", "find_workflow",
		fmt.Sprintf("workflow not found: %s (available: %d)", p.name, len(workflows)))
	_ = wrappedErr.Suggest(
		fmt.Sprintf("Check spelling of workflow name '%s'", p.name),
		"Verify workflow is defined in config file",
	)
	return nil, wrappedErr
}

// createWorkflowOverlay creates a configuration overlay with workflow-level overrides.
// This uses the immutable overlay approach instead of mutating base configuration.
func (p *WorkflowPipeline) createWorkflowOverlay(wf *config.Workflow) config.ConfigurationIface {
	overrides := make(map[string]any)
	if wf.FailurePolicy != "" {
		overrides[flags.PipelineFailurePolicy] = wf.FailurePolicy
	}
	if wf.OutputMode != "" {
		overrides[flags.OutputMode] = wf.OutputMode
	}
	if wf.Rekor.Upload {
		overrides[flags.TransparencyEnable] = true
	}
	if wf.Rekor.UploadTarget != "" {
		overrides[flags.RekorUploadTarget] = wf.Rekor.UploadTarget
	}
	return p.CreateConfigurationOverlay(overrides)
}

// executeAttestors runs all attestors defined in the workflow sequentially.
func (p *WorkflowPipeline) executeAttestors(ctx context.Context, wf *config.Workflow, workflowOverlay config.ConfigurationIface) error {
	failurePolicy := getFailurePolicyFromConfig(workflowOverlay)
	var executionErrors []error

	for _, attestor := range wf.Attestors {
		p.logger.InfoContext(ctx, "executing attestor", "attestor_name", attestor.Name, "attestor_type", attestor.Type)

		attestorOverlay := p.createAttestorOverlay(workflowOverlay, attestor)
		attestorPipeline := NewAttestorPipelineWithWorkflow(attestor.Type, attestor.Name, p.name, attestorOverlay, p.logger, p.output)
		err := attestorPipeline.Execute(ctx)
		p.result.Attestations = append(p.result.Attestations, attestorPipeline.GetResult().Attestations...)

		if err != nil {
			p.logger.ErrorContext(ctx, "attestor failed", "attestor_name", attestor.Name, "attestor_type", attestor.Type, "error", err)
			wrappedErr := pkgerrors.WrapAttestor(err, attestor.Name, "workflow-execution")
			executionErrors = append(executionErrors, wrappedErr)

			if failurePolicy == types.FailurePolicyFailFast {
				return wrappedErr.Suggest(
					fmt.Sprintf("Check attestor '%s' configuration in workflow", attestor.Name),
					"Verify attestor prerequisites are met",
					"Consider using failure_policy: 'continue' to execute all attestors despite failures",
				)
			}
		} else {
			p.logger.InfoContext(ctx, "attestor completed successfully", "attestor_name", attestor.Name, "attestor_type", attestor.Type)
		}
	}

	if len(executionErrors) > 0 {
		successful := p.result.Successful()
		return pkgerrors.NewWithContext("workflow", "execute_attestors",
			fmt.Sprintf("workflow '%s' completed with %d failures (out of %d attestors): %d succeeded, %d failed",
				p.name, len(executionErrors), len(p.result.Attestations), len(successful), len(executionErrors)))
	}
	return nil
}

// createAttestorOverlay creates a configuration overlay with attestor-specific overrides.
func (p *WorkflowPipeline) createAttestorOverlay(workflowOverlay config.ConfigurationIface, attestor config.Attestor) config.ConfigurationIface {
	if len(attestor.Config) == 0 {
		return workflowOverlay
	}
	overrides := map[string]any{
		fmt.Sprintf("attestor.%s", attestor.Name): attestor.Config,
	}
	return config.New(workflowOverlay, overrides)
}

// signAttestations signs each successful attestor's statement into a sigstore
// Bundle v0.3. Per-attestor pipelines skip their own signing when inside a
// workflow so options resolution + Rekor upload happen once per workflow run.
func (p *WorkflowPipeline) signAttestations(ctx context.Context) error {
	opts, err := p.GetSigstoreOptions(ctx)
	if err != nil {
		return err
	}
	if opts == nil {
		p.logger.DebugContext(ctx, "no signer configured — leaving attestations unsigned")
		return nil
	}

	signer := p.GetSigstoreSigner()
	failurePolicy := p.GetFailurePolicy()

	for i := range p.result.Attestations {
		att := &p.result.Attestations[i]
		if att.Error != nil {
			continue
		}
		if len(att.StatementJSON) == 0 {
			continue
		}
		if len(att.BundleJSON) > 0 {
			continue
		}

		start := time.Now()
		res, err := signer.SignBundle(ctx, att.StatementJSON, intoto.PayloadType, *opts)
		duration := time.Since(start)
		p.RecordSigningDuration(duration)
		if opts.Rekor != nil {
			p.RecordRekorUploadDuration(duration)
		}

		if err != nil {
			wrapped := pkgerrors.WrapWithContext(err, "signing", "sigstore_bundle",
				fmt.Sprintf("failed to sign bundle for attestor: %s", att.AttestorName))
			if failurePolicy == types.FailurePolicyFailFast {
				return wrapped
			}
			att.Error = wrapped
			p.logger.WarnContext(ctx, "continuing despite bundle signing failure",
				"attestor", att.AttestorName, "error", err)
			continue
		}
		att.BundleJSON = res.BundleJSON
	}
	return nil
}

// handleStdoutOutput writes attestations to stdout based on the configured output mode.
func (p *WorkflowPipeline) handleStdoutOutput(ctx context.Context, overlayConfig config.ConfigurationIface) error {
	if !p.output.IsDataOutputEnabled() {
		p.logger.DebugContext(ctx, "stdout data output disabled")
		return nil
	}

	successful := p.result.Successful()
	if len(successful) == 0 {
		p.logger.DebugContext(ctx, "no successful attestations to output")
		return nil
	}

	outputMode := OutputMode(overlayConfig.GetString(flags.OutputMode))
	if outputMode == "" {
		outputMode = OutputModeIndividual
	}

	var dataToOutput []any

	switch outputMode {
	case OutputModeIndividual:
		for _, result := range successful {
			if payload := chooseStdoutPayload(result); payload != nil {
				dataToOutput = append(dataToOutput, payload)
			}
		}

	case OutputModeCollection:
		collection, err := p.getOrCreateSignedCollection(ctx, successful)
		if err != nil {
			return pkgerrors.WrapWithContext(err, "output", "create_collection",
				"failed to create collection for stdout output")
		}
		if payload := collectionStdoutPayload(collection); payload != nil {
			dataToOutput = []any{payload}
		}

	case OutputModeBoth:
		for _, result := range successful {
			if payload := chooseStdoutPayload(result); payload != nil {
				dataToOutput = append(dataToOutput, payload)
			}
		}
		collection, err := p.getOrCreateSignedCollection(ctx, successful)
		if err != nil {
			return pkgerrors.WrapWithContext(err, "output", "create_collection",
				"failed to create collection for stdout output")
		}
		if payload := collectionStdoutPayload(collection); payload != nil {
			dataToOutput = append(dataToOutput, payload)
		}

	default:
		return pkgerrors.NewWithContext("output", "stdout_write",
			fmt.Sprintf("invalid output mode: %s", outputMode))
	}

	if len(dataToOutput) == 0 {
		return nil
	}

	p.logger.DebugContext(ctx, "writing attestations to stdout", "mode", outputMode, "count", len(dataToOutput))
	if err := p.output.DataBatch(dataToOutput); err != nil {
		p.logger.ErrorContext(ctx, "failed to write attestations to stdout", "error", err)
		if p.GetFailurePolicy() == types.FailurePolicyFailFast {
			return pkgerrors.WrapWithContext(err, "output", "stdout_write",
				"failed to write attestations to stdout")
		}
		p.logger.WarnContext(ctx, "continuing despite stdout write failure")
	}

	return nil
}

func chooseStdoutPayload(result SignedResult) any {
	if len(result.BundleJSON) > 0 {
		return rawJSON(result.BundleJSON)
	}
	if len(result.StatementJSON) > 0 {
		return rawJSON(result.StatementJSON)
	}
	return nil
}

func collectionStdoutPayload(collection *CollectionResult) any {
	if collection == nil {
		return nil
	}
	if len(collection.BundleJSON) > 0 {
		return rawJSON(collection.BundleJSON)
	}
	if len(collection.StatementJSON) > 0 {
		return rawJSON(collection.StatementJSON)
	}
	return nil
}

// getOrCreateSignedCollection returns a cached collection or creates one if
// not cached. Caching keeps the same timestamp/fingerprint across stdout,
// persist, and tlog upload so users can fetch the exact collection they saved.
func (p *WorkflowPipeline) getOrCreateSignedCollection(ctx context.Context, successful []SignedResult) (*CollectionResult, error) {
	if p.cachedCollection != nil {
		p.logger.DebugContext(ctx, "reusing cached collection")
		return p.cachedCollection, nil
	}

	statements := make([][]byte, 0, len(successful))
	for _, result := range successful {
		if len(result.StatementJSON) == 0 {
			continue
		}
		statements = append(statements, result.StatementJSON)
	}
	if len(statements) == 0 {
		return nil, pkgerrors.NewWithContext("workflow", "create_collection",
			"no statements available for collection")
	}

	p.logger.DebugContext(ctx, "creating new collection")
	stmt, err := CreateStructuredCollectionStatement(p.name, statements)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "workflow", "create_collection",
			"failed to create collection statement")
	}
	statementJSON, err := stmt.ToJSON()
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "workflow", "serialize_collection",
			"failed to serialize collection statement")
	}

	collection := &CollectionResult{
		StatementJSON: statementJSON,
		WorkflowName:  p.name,
	}

	opts, err := p.GetSigstoreOptions(ctx)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "workflow", "get_sigstore_options",
			"failed to build sigstore options for collection")
	}
	if opts != nil {
		start := time.Now()
		p.logger.DebugContext(ctx, "signing collection bundle")
		res, err := p.GetSigstoreSigner().SignBundle(ctx, statementJSON, intoto.PayloadType, *opts)
		duration := time.Since(start)
		p.RecordSigningDuration(duration)
		if opts.Rekor != nil {
			p.RecordRekorUploadDuration(duration)
		}
		if err != nil {
			return nil, pkgerrors.WrapWithContext(err, "workflow", "sign_collection",
				"failed to sign collection bundle")
		}
		collection.BundleJSON = res.BundleJSON
	}

	p.cachedCollection = collection
	return collection, nil
}

// ensureCollection creates the collection bundle when the workflow output mode
// requires it (collection or both) and there are successful attestations.
func (p *WorkflowPipeline) ensureCollection(ctx context.Context, overlayConfig config.ConfigurationIface) error {
	outputMode := OutputMode(overlayConfig.GetString(flags.OutputMode))
	if outputMode != OutputModeCollection && outputMode != OutputModeBoth {
		return nil
	}

	successful := p.result.Successful()
	if len(successful) == 0 {
		return nil
	}

	collection, err := p.getOrCreateSignedCollection(ctx, successful)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "workflow", "create_collection", "failed to create collection for workflow")
	}
	p.result.Collections = append(p.result.Collections, *collection)
	return nil
}

// handleOutput orchestrates stdout, persist, and Rekor output based on workflow configuration.
func (p *WorkflowPipeline) handleOutput(ctx context.Context, overlayConfig config.ConfigurationIface) error {
	failurePolicy := getFailurePolicyFromConfig(overlayConfig)

	if err := p.handleStdoutOutput(ctx, overlayConfig); err != nil {
		p.logger.ErrorContext(ctx, "failed to write stdout output", "error", err)
		if failurePolicy == types.FailurePolicyFailFast {
			return err
		}
	}

	if err := p.handlePersistOutput(ctx, overlayConfig); err != nil {
		p.logger.ErrorContext(ctx, "failed to persist output", "error", err)
		if failurePolicy == types.FailurePolicyFailFast {
			return err
		}
	}

	return nil
}

// handlePersistOutput writes attestations to files based on output mode if --persist is enabled.
func (p *WorkflowPipeline) handlePersistOutput(ctx context.Context, overlayConfig config.ConfigurationIface) error {
	manager, err := p.GetDestinationManager()
	if err != nil {
		return pkgerrors.WrapWithContext(err, "persist", "get_manager",
			"failed to get destination manager for workflow")
	}

	if manager == nil {
		p.logger.DebugContext(ctx, "persist not enabled")
		return nil
	}

	successful := p.result.Successful()
	if len(successful) == 0 {
		p.logger.DebugContext(ctx, "no successful attestations to persist")
		return nil
	}

	outputMode := OutputMode(overlayConfig.GetString(flags.OutputMode))
	if outputMode == "" {
		outputMode = OutputModeIndividual
	}

	switch outputMode {
	case OutputModeIndividual:
		if err := p.persistIndividualAttestations(ctx, manager, successful); err != nil {
			return err
		}

	case OutputModeCollection:
		if err := p.persistCollection(ctx, manager, successful); err != nil {
			return err
		}

	case OutputModeBoth:
		if err := p.persistIndividualAttestations(ctx, manager, successful); err != nil {
			return err
		}
		if err := p.persistCollection(ctx, manager, successful); err != nil {
			return err
		}
	}

	return nil
}

// persistIndividualAttestations writes each attestation bundle to a separate file.
func (p *WorkflowPipeline) persistIndividualAttestations(ctx context.Context, manager *destination.Manager, successful []SignedResult) error {
	for _, result := range successful {
		if len(result.BundleJSON) == 0 {
			p.logger.DebugContext(ctx, "skipping unsigned attestation for persist",
				"attestor", result.AttestorName)
			continue
		}

		sum := sha256.Sum256(result.BundleJSON)

		attestation := &destination.Attestation{
			ID:            uuid.New().String(),
			AttestorID:    result.AttestorName,
			PredicateType: result.PredicateType,
			Bundle:        result.BundleJSON,
			Timestamp:     time.Now(),
			SHA256:        hex.EncodeToString(sum[:]),
			WorkflowName:  p.name,
		}

		start := time.Now()
		writeResult, err := manager.Write(ctx, attestation, destination.WriteOptions{
			FailurePolicy: destination.FailurePolicyFailFast,
		})
		if err != nil {
			return pkgerrors.WrapWithContext(err, "persist", "write_individual",
				fmt.Sprintf("failed to persist attestation for attestor: %s", result.AttestorName))
		}

		duration := time.Since(start)
		p.RecordDestinationWriteDuration(duration)

		for name, wr := range writeResult.Successful {
			p.logger.InfoContext(ctx, "attestation persisted",
				"destination", name,
				"attestor", result.AttestorName,
				"location", wr.Location,
				"size", wr.Size)
			p.output.Success("Attestation saved to: %s", wr.Location)
		}
	}

	return nil
}

// persistCollection writes the collection bundle to a file.
func (p *WorkflowPipeline) persistCollection(ctx context.Context, manager *destination.Manager, successful []SignedResult) error {
	collection, err := p.getOrCreateSignedCollection(ctx, successful)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "persist", "create_collection",
			"failed to create collection for persist")
	}

	if len(collection.BundleJSON) == 0 {
		p.logger.DebugContext(ctx, "no signed collection bundle available to persist")
		return nil
	}

	sum := sha256.Sum256(collection.BundleJSON)

	attestation := &destination.Attestation{
		ID:            uuid.New().String(),
		AttestorID:    "collection",
		PredicateType: collectionv1.CollectionV1URI,
		Bundle:        collection.BundleJSON,
		Timestamp:     time.Now(),
		SHA256:        hex.EncodeToString(sum[:]),
		WorkflowName:  p.name,
	}

	start := time.Now()
	writeResult, err := manager.Write(ctx, attestation, destination.WriteOptions{
		FailurePolicy: destination.FailurePolicyFailFast,
	})
	if err != nil {
		return pkgerrors.WrapWithContext(err, "persist", "write_collection",
			"failed to persist collection attestation")
	}

	duration := time.Since(start)
	p.RecordDestinationWriteDuration(duration)

	for name, wr := range writeResult.Successful {
		p.logger.InfoContext(ctx, "collection persisted",
			"destination", name,
			"location", wr.Location,
			"size", wr.Size)
		p.output.Success("Collection saved to: %s", wr.Location)
	}

	return nil
}

// GetResult returns the pipeline execution result.
func (p *WorkflowPipeline) GetResult() *Result {
	if p.result.Metrics == nil {
		p.result.Metrics = p.GetMetrics()
	}
	return p.result
}

// getFailurePolicyFromConfig reads failure policy from the given configuration.
// This is used instead of BasePipeline.GetFailurePolicy() when we need to read
// from an overlay config (e.g., workflow-level overrides).
func getFailurePolicyFromConfig(cfg config.ConfigurationIface) types.FailurePolicy {
	policy := cfg.GetString(flags.PipelineFailurePolicy)
	if policy == types.FailurePolicyContinue.String() {
		return types.FailurePolicyContinue
	}
	return types.FailurePolicyFailFast
}

// NewWorkflowPipeline creates a new pipeline for workflow execution.
func NewWorkflowPipeline(workflowName string, cfg config.ConfigurationIface, log logger.Logger, out output.OutputIface) *WorkflowPipeline {
	log = log.With("workflow", workflowName)
	return &WorkflowPipeline{
		BasePipeline: NewBasePipeline(cfg, log, out),
		name:         workflowName,
		result: &Result{
			Attestations: make([]SignedResult, 0),
		},
	}
}
