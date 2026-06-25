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
	workflow         *config.Workflow
	name             string
	result           *Result
	cachedCollection *intoto.Envelope // Cached signed collection (created once, reused for stdout/Rekor)
}

// HasWorkflowContext returns true as WorkflowPipeline always has workflow context.
func (p *WorkflowPipeline) HasWorkflowContext() bool {
	return true
}

// Execute runs all attestors defined in the workflow.
func (p *WorkflowPipeline) Execute(ctx context.Context) error {
	p.logger.InfoContext(ctx, "starting workflow pipeline")
	p.output.Progress("Executing workflow: %s", p.name)

	// Ensure signer cleanup happens at the end
	defer func() {
		if p.signer != nil {
			if err := p.signer.PostSign(ctx); err != nil {
				p.logger.WarnContext(ctx, "signer cleanup failed", "error", err)
			}
		}
	}()

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
			if result.Envelope != nil {
				dataToOutput = append(dataToOutput, result.Envelope)
			}
		}

	case OutputModeCollection:
		collection, err := p.getOrCreateSignedCollection(ctx, successful)
		if err != nil {
			return pkgerrors.WrapWithContext(err, "output", "create_collection",
				"failed to create collection for stdout output")
		}
		dataToOutput = []any{collection}

	case OutputModeBoth:
		for _, result := range successful {
			if result.Envelope != nil {
				dataToOutput = append(dataToOutput, result.Envelope)
			}
		}
		collection, err := p.getOrCreateSignedCollection(ctx, successful)
		if err != nil {
			return pkgerrors.WrapWithContext(err, "output", "create_collection",
				"failed to create collection for stdout output")
		}
		dataToOutput = append(dataToOutput, collection)

	default:
		return pkgerrors.NewWithContext("output", "stdout_write",
			fmt.Sprintf("invalid output mode: %s", outputMode))
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

// getOrCreateSignedCollection returns a cached collection or creates one if not cached.
// This ensures the same collection (same timestamp, same fingerprint) is used for both
// stdout output and Rekor upload, allowing users to fetch the exact collection they saved.
func (p *WorkflowPipeline) getOrCreateSignedCollection(ctx context.Context, successful []EnvelopeResult) (*intoto.Envelope, error) {
	// Return cached collection if available
	if p.cachedCollection != nil {
		p.logger.DebugContext(ctx, "reusing cached collection")
		return p.cachedCollection, nil
	}

	envelopes := make([]*intoto.Envelope, 0, len(successful))
	for _, result := range successful {
		if result.Envelope != nil {
			envelopes = append(envelopes, result.Envelope)
		}
	}
	if len(envelopes) == 0 {
		return nil, pkgerrors.NewWithContext("workflow", "create_collection", "no envelopes available for collection")
	}

	p.logger.DebugContext(ctx, "creating new collection")
	collection, err := CreateStructuredCollectionEnvelope(p.name, envelopes)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "workflow", "create_collection", "failed to create collection envelope")
	}

	signer, err := p.GetSigner(ctx)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "workflow", "get_signer", "failed to get signer for collection")
	}
	if signer != nil {
		p.logger.DebugContext(ctx, "signing collection attestation")
		if err := collection.Sign(ctx, signer); err != nil {
			return nil, pkgerrors.WrapWithContext(err, "workflow", "sign_collection", "failed to sign collection")
		}
	}

	p.cachedCollection = collection
	return collection, nil
}

// ensureCollection creates the collection envelope when the workflow output mode
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
	p.result.Collections = append(p.result.Collections, CollectionResult{
		Envelope:     collection,
		WorkflowName: p.name,
	})
	return err
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

	if err := p.handleRekorOutput(ctx, overlayConfig); err != nil {
		p.logger.ErrorContext(ctx, "failed to upload to Rekor", "error", err)
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

// persistIndividualAttestations writes each attestation to a separate file.
func (p *WorkflowPipeline) persistIndividualAttestations(ctx context.Context, manager *destination.Manager, successful []EnvelopeResult) error {
	for _, result := range successful {
		if result.Envelope == nil {
			continue
		}

		sha256Hash, _ := result.Envelope.SHA256()

		attestation := &destination.Attestation{
			ID:            uuid.New().String(),
			AttestorID:    result.AttestorName,
			PredicateType: result.PredicateType,
			Envelope:      result.Envelope,
			Timestamp:     time.Now(),
			SHA256:        sha256Hash,
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

// persistCollection writes the collection attestation to a file.
func (p *WorkflowPipeline) persistCollection(ctx context.Context, manager *destination.Manager, successful []EnvelopeResult) error {
	collection, err := p.getOrCreateSignedCollection(ctx, successful)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "persist", "create_collection",
			"failed to create collection for persist")
	}

	sha256Hash, _ := collection.SHA256()

	attestation := &destination.Attestation{
		ID:            uuid.New().String(),
		AttestorID:    "collection",
		PredicateType: collectionv1.CollectionV1URI,
		Envelope:      collection,
		Timestamp:     time.Now(),
		SHA256:        sha256Hash,
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

// handleRekorOutput uploads attestations to the Rekor transparency log based on output mode and upload target.
//
//nolint:gocognit // Rekor output handling requires multiple conditional paths for different output formats
func (p *WorkflowPipeline) handleRekorOutput(ctx context.Context, overlayConfig config.ConfigurationIface) error {
	if !overlayConfig.GetBool(flags.TransparencyEnable) {
		p.logger.DebugContext(ctx, "transparency log disabled")
		return nil
	}

	outputMode := OutputMode(overlayConfig.GetString(flags.OutputMode))
	if outputMode == "" {
		outputMode = OutputModeIndividual
	}
	successful := p.result.Successful()

	rekorTarget := overlayConfig.GetString(flags.RekorUploadTarget)
	uploadIndividual := rekorTarget == "individual" || rekorTarget == "both"
	uploadCollection := rekorTarget == "collection" || rekorTarget == "both"

	switch outputMode {
	case OutputModeIndividual:
		if uploadIndividual {
			if err := p.uploadIndividualToRekor(ctx, successful); err != nil {
				p.logger.WarnContext(ctx, "failed to upload individual attestations to Rekor", "error", err)
				if p.GetFailurePolicy() == types.FailurePolicyFailFast {
					return err
				}
			}
		}

	case OutputModeCollection:
		if uploadCollection {
			if err := p.uploadCollectionToRekor(ctx, successful); err != nil {
				p.logger.WarnContext(ctx, "failed to upload collection to Rekor", "error", err)
				if p.GetFailurePolicy() == types.FailurePolicyFailFast {
					return err
				}
			}
		}

	case OutputModeBoth:
		if uploadIndividual {
			if err := p.uploadIndividualToRekor(ctx, successful); err != nil {
				p.logger.WarnContext(ctx, "failed to upload individual attestations to Rekor", "error", err)
				if p.GetFailurePolicy() == types.FailurePolicyFailFast {
					return err
				}
			}
		}
		if uploadCollection {
			if err := p.uploadCollectionToRekor(ctx, successful); err != nil {
				p.logger.WarnContext(ctx, "failed to upload collection to Rekor", "error", err)
				if p.GetFailurePolicy() == types.FailurePolicyFailFast {
					return err
				}
			}
		}
	}

	return nil
}

// uploadCollectionToRekor uploads a bundled collection of attestations to the Rekor transparency log.
func (p *WorkflowPipeline) uploadCollectionToRekor(ctx context.Context, successful []EnvelopeResult) error {
	client, err := p.GetRekorClient()
	if err != nil {
		return pkgerrors.WrapWithContext(err, "workflow", "get_rekor_client", "failed to get rekor client")
	}
	if client == nil {
		p.logger.DebugContext(ctx, "rekor not configured")
		return nil
	}

	collection, err := p.getOrCreateSignedCollection(ctx, successful)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "workflow", "create_collection", "failed to create collection for rekor upload")
	}

	p.logger.InfoContext(ctx, "uploading collection to transparency log")
	start := time.Now()
	publicKeyPath := p.config.GetString(flags.PublicKey)
	entry, err := client.Upload(ctx, collection, publicKeyPath, nil)
	duration := time.Since(start)
	p.RecordRekorUploadDuration(duration)

	if err != nil {
		return pkgerrors.WrapWithContext(err, "workflow", "upload_rekor", "failed to upload collection to rekor")
	}

	p.logger.InfoContext(ctx, "collection uploaded to transparency log",
		"entry_uuid", entry.UUID, "log_index", entry.LogIndex, "duration_ms", duration.Milliseconds())
	p.output.Success("Collection uploaded to transparency log (UUID: %s)", entry.UUID)

	return nil
}

// uploadIndividualToRekor uploads each successful attestation separately to the Rekor transparency log.
func (p *WorkflowPipeline) uploadIndividualToRekor(ctx context.Context, successful []EnvelopeResult) error {
	client, err := p.GetRekorClient()
	if err != nil {
		return pkgerrors.WrapWithContext(err, "workflow", "get_rekor_client", "failed to get rekor client")
	}
	if client == nil {
		p.logger.DebugContext(ctx, "rekor not configured")
		return nil
	}

	p.logger.InfoContext(ctx, "uploading individual attestations to transparency log")
	publicKeyPath := p.config.GetString(flags.PublicKey)
	var uploadErrors []error

	for i, result := range successful {
		if result.Envelope == nil {
			continue
		}

		start := time.Now()
		p.logger.DebugContext(ctx, "uploading attestation to transparency log", "index", i)

		entry, err := client.Upload(ctx, result.Envelope, publicKeyPath, nil)
		duration := time.Since(start)
		p.RecordRekorUploadDuration(duration)

		if err != nil {
			uploadErrors = append(uploadErrors, pkgerrors.WrapWithContext(err, "workflow", "upload_individual_rekor",
				fmt.Sprintf("failed to upload attestation %d to rekor", i)))
			if p.GetFailurePolicy() == types.FailurePolicyFailFast {
				return pkgerrors.WrapWithContext(err, "workflow", "upload_individual_rekor_fast_fail",
					fmt.Sprintf("failed to upload individual attestation %d to rekor", i))
			}
			p.logger.WarnContext(ctx, "failed to upload attestation to Rekor", "index", i, "error", err)
		} else {
			p.logger.InfoContext(ctx, "attestation uploaded to transparency log",
				"index", i, "entry_uuid", entry.UUID, "log_index", entry.LogIndex, "duration_ms", duration.Milliseconds())
			p.output.Success("Attestation %d uploaded to transparency log (UUID: %s)", i, entry.UUID)
		}
	}

	if len(uploadErrors) > 0 {
		return pkgerrors.NewWithContext("workflow", "upload_individual_rekor_batch",
			fmt.Sprintf("some individual attestations failed to upload to rekor: %d errors", len(uploadErrors)))
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
			Attestations: make([]EnvelopeResult, 0),
		},
	}
}
