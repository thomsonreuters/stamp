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

package operations

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/output"
	"github.com/thomsonreuters/stamp/pkg/pipeline"
	"github.com/thomsonreuters/stamp/pkg/validation"
)

// ExecutionMode represents the type of execution being performed.
type ExecutionMode int

// Execution mode constants for the run operation.
const (
	// ModeUnknown indicates an unspecified or invalid execution mode.
	ModeUnknown ExecutionMode = iota
	// ModeSingleAttestor executes a single attestor using --attestor flag.
	ModeSingleAttestor
	// ModeSingleWorkflow executes a single named workflow.
	ModeSingleWorkflow
	// ModeMultipleWorkflows executes multiple explicitly named workflows.
	ModeMultipleWorkflows
	// ModeFilteredWorkflows executes workflows matching tag, include, or exclude filters.
	ModeFilteredWorkflows
	// ModeAllWorkflows executes all defined workflows using --all flag.
	ModeAllWorkflows
)

// String returns a human-readable name for the execution mode.
func (m ExecutionMode) String() string {
	switch m {
	case ModeUnknown:
		return "unknown"
	case ModeSingleAttestor:
		return "single-attestor"
	case ModeSingleWorkflow:
		return "single-workflow"
	case ModeMultipleWorkflows:
		return "multiple-workflows"
	case ModeFilteredWorkflows:
		return "filtered-workflows"
	case ModeAllWorkflows:
		return "all-workflows"
	default:
		return "unknown"
	}
}

// RunOp implements the operation for executing attestation workflows and individual attestors.
type RunOp struct {
	config config.ConfigurationIface
	logger logger.Logger
	output output.OutputIface
	mode   ExecutionMode
	result *pipeline.Result
}

// executeSingleAttestor runs a single attestor with the given type.
func (o *RunOp) executeSingleAttestor(ctx context.Context, attestorType string) error {
	o.logger.InfoContext(ctx, "executing single attestor", "attestor_type", attestorType)

	p := pipeline.NewAttestorPipeline(attestorType, o.config, o.logger, o.output)
	err := p.Execute(ctx)
	o.result = p.GetResult()

	if err != nil {
		return pkgerrors.WrapPipeline(err, "single-attestor", attestorType).
			Suggest(
				"Verify attestor prerequisites are met",
				"Check --set configuration values",
				"Run 'stamp list' to see available attestor types")
	}

	o.output.Success("Attestor %s executed successfully", attestorType)
	return nil
}

// executeSingleWorkflow runs a single named workflow.
func (o *RunOp) executeSingleWorkflow(ctx context.Context, workflowName string) error {
	o.logger.InfoContext(ctx, "executing single workflow", "workflow_name", workflowName)

	p := pipeline.NewWorkflowPipeline(workflowName, o.config, o.logger, o.output)
	err := p.Execute(ctx)
	o.result = p.GetResult()

	if err != nil {
		return pkgerrors.WrapPipeline(err, "single-workflow", workflowName).
			Suggest(
				"Check workflow configuration",
				"Verify all attestors are properly configured")
	}

	o.output.Success("Workflow %s: all %d attestors succeeded", workflowName, len(o.result.Successful()))
	return nil
}

// executeWorkflowsSequential runs multiple workflows one after another.
// Results, metrics, and collection envelopes from each workflow are
// merged into a single aggregated Result accessible via GetResult.
func (o *RunOp) executeWorkflowsSequential(ctx context.Context, workflowNames []string) error {
	failFast := !o.config.GetBool(flags.RunContinueOnError)

	aggregated := &pipeline.Result{
		Attestations: make([]pipeline.EnvelopeResult, 0, len(workflowNames)*4),
		Metrics:      pipeline.NewMetrics(),
	}

	var (
		succeededWorkflows int
		failedWorkflows    int
	)

	for i, workflowName := range workflowNames {
		o.output.Progress("[%d/%d] Executing workflow: %s", i+1, len(workflowNames), workflowName)

		p := pipeline.NewWorkflowPipeline(workflowName, o.config, o.logger, o.output)
		err := p.Execute(ctx)
		result := p.GetResult()
		aggregated.Merge(result)

		if err != nil {
			failedWorkflows++
			o.output.Warning("Workflow %s: %d attestors succeeded, %d failed",
				workflowName, len(result.Successful()), len(result.Failed()))

			if failFast {
				aggregated.Metrics.Finalize()
				o.result = aggregated
				return pkgerrors.NewWithContext("run", "multi_workflow_execution",
					"workflow execution stopped due to failure (fail-fast mode)")
			}
		} else {
			succeededWorkflows++
			o.output.Success("Workflow %s: all %d attestors succeeded",
				workflowName, len(result.Successful()))
		}
	}

	aggregated.Metrics.Finalize()
	o.result = aggregated

	if failedWorkflows == 0 {
		o.output.Success("All %d workflows completed successfully (%d attestors)",
			len(workflowNames), len(aggregated.Attestations))
		return nil
	}

	totalWorkflows := succeededWorkflows + failedWorkflows

	if succeededWorkflows == 0 {
		o.output.Error("All %d workflows failed (%d/%d attestors failed)",
			totalWorkflows, len(aggregated.Failed()), len(aggregated.Attestations))
		return pkgerrors.NewWithContext("run", "multi_workflow_execution",
			"all workflows failed")
	}

	o.output.Warning("Completed with failures: %d workflows succeeded, %d workflows failed (%d/%d attestors succeeded)",
		succeededWorkflows, failedWorkflows, len(aggregated.Successful()), len(aggregated.Attestations))

	return pkgerrors.NewWithContext("run", "multi_workflow_execution",
		fmt.Sprintf("some workflows failed: %d errors", failedWorkflows))
}

// applyFilters returns workflows matching the configured tag, include, and exclude filters.
func (o *RunOp) applyFilters(workflows []config.Workflow) []config.Workflow {
	tags := o.config.GetString(flags.RunTags)
	includePattern := o.config.GetString(flags.RunInclude)
	excludePattern := o.config.GetString(flags.RunExclude)

	filtered := make([]config.Workflow, 0, len(workflows))

	for _, workflow := range workflows {
		// Apply exclusion first
		if excludePattern != "" {
			if matched, _ := filepath.Match(excludePattern, workflow.Name); matched {
				continue
			}
		}

		// Apply inclusion
		if includePattern != "" {
			matched, _ := filepath.Match(includePattern, workflow.Name)
			if !matched {
				continue
			}
		}

		// Apply tag filtering
		if tags != "" {
			tagList := strings.Split(tags, ",")
			hasMatch := slices.ContainsFunc(tagList, func(tag string) bool {
				return slices.Contains(workflow.Tags, strings.TrimSpace(tag))
			})
			if !hasMatch {
				continue
			}
		}

		// Passed all filters
		filtered = append(filtered, workflow)
	}

	return filtered
}

// workflowNames extracts workflow names from a slice of workflows.
func (o *RunOp) workflowNames(workflows []config.Workflow) []string {
	names := make([]string, len(workflows))
	for i, wf := range workflows {
		names[i] = wf.Name
	}
	return names
}

// executeMultipleWorkflows runs multiple explicitly named workflows.
func (o *RunOp) executeMultipleWorkflows(ctx context.Context, workflowNames []string) error {
	o.logger.InfoContext(ctx, "executing multiple workflows", "count", len(workflowNames))

	return o.executeWorkflowsSequential(ctx, workflowNames)
}

// executeFilteredWorkflows runs workflows matching the configured filters.
func (o *RunOp) executeFilteredWorkflows(ctx context.Context) error {
	o.logger.InfoContext(ctx, "executing filtered workflows")

	var workflows []config.Workflow
	if err := o.config.UnmarshalKey(flags.Workflows, &workflows); err != nil {
		return pkgerrors.WrapWithContext(err, "config", "load_workflows",
			"failed to load workflows")
	}

	filteredWorkflows := o.applyFilters(workflows)

	workflowNames := make([]string, len(filteredWorkflows))
	for i, workflow := range filteredWorkflows {
		workflowNames[i] = workflow.Name
	}

	o.logger.InfoContext(ctx, "filtered workflows", "matched", len(workflowNames))

	return o.executeWorkflowsSequential(ctx, workflowNames)
}

// executeAllWorkflows runs all workflows defined in the configuration.
func (o *RunOp) executeAllWorkflows(ctx context.Context) error {
	o.logger.InfoContext(ctx, "executing all workflows")

	var workflows []config.Workflow
	if err := o.config.UnmarshalKey(flags.Workflows, &workflows); err != nil {
		return pkgerrors.WrapWithContext(err, "config", "load_workflows",
			"failed to load workflows")
	}

	workflowNames := make([]string, len(workflows))
	for i, workflow := range workflows {
		workflowNames[i] = workflow.Name
	}

	return o.executeWorkflowsSequential(ctx, workflowNames)
}

// Execute performs the run operation based on the determined execution mode.
func (o *RunOp) Execute(ctx context.Context, args []string) error {
	o.logger.InfoContext(ctx, "execution mode determined", "mode", o.mode.String())

	switch o.mode { //nolint:exhaustive // Default case handles ModeUnknown and invalid modes
	case ModeSingleAttestor:
		return o.executeSingleAttestor(ctx, o.config.GetString(flags.RunAttestor))

	case ModeSingleWorkflow:
		return o.executeSingleWorkflow(ctx, args[0])

	case ModeMultipleWorkflows:
		return o.executeMultipleWorkflows(ctx, args)

	case ModeFilteredWorkflows:
		return o.executeFilteredWorkflows(ctx)

	case ModeAllWorkflows:
		return o.executeAllWorkflows(ctx)

	default:
		return pkgerrors.NewUsageError("invalid execution mode")
	}
}

// determineExecutionMode analyzes flags and arguments to determine the execution mode.
func (o *RunOp) determineExecutionMode(args []string) (ExecutionMode, error) {
	attestorType := o.config.GetString(flags.RunAttestor)
	hasPositionalArgs := len(args) > 0
	hasTags := o.config.GetString(flags.RunTags) != ""
	hasInclude := o.config.GetString(flags.RunInclude) != ""
	hasExclude := o.config.GetString(flags.RunExclude) != ""
	hasAll := o.config.GetBool(flags.RunAll)

	hasFilters := hasTags || hasInclude || hasExclude

	if attestorType != "" {
		if hasPositionalArgs || hasFilters || hasAll {
			return ModeUnknown, pkgerrors.NewUsageError(
				"--attestor cannot be combined with workflow selection",
				"Use --attestor alone for single attestor mode",
				"Use positional args or filters for workflow mode",
			)
		}
		return ModeSingleAttestor, nil
	}

	if hasPositionalArgs {
		if hasFilters || hasAll {
			return ModeUnknown, pkgerrors.NewUsageError(
				"cannot combine explicit workflow names with --all, --tags, --include, or --exclude",
				"Use positional args alone: stamp run workflow1 workflow2",
				"Or use filters alone: stamp run --tags security",
			)
		}
		if len(args) == 1 {
			return ModeSingleWorkflow, nil
		}
		return ModeMultipleWorkflows, nil
	}

	if hasFilters {
		return ModeFilteredWorkflows, nil
	}

	if hasAll {
		return ModeAllWorkflows, nil
	}

	return ModeUnknown, pkgerrors.NewUsageError(
		"must specify: --attestor <type>, workflow names, --all, or filters (--tags, --include, --exclude)",
		"Single attestor: stamp run --attestor git --set repo_path=.",
		"Single workflow: stamp run security-audit -c config.yaml",
		"Multiple workflows: stamp run workflow1 workflow2 -c config.yaml",
		"Filtered workflows: stamp run --tags security -c config.yaml",
		"All workflows: stamp run --all -c config.yaml",
	)
}

// validateSingleAttestorMode validates configuration for single attestor execution.
func (o *RunOp) validateSingleAttestorMode() error {
	validator := pkgerrors.NewValidator()

	attestorType := o.config.GetString(flags.RunAttestor)

	if _, err := core.GetAttestorByID(attestorType, o.logger); err != nil {
		validator.AddError("attestor",
			fmt.Sprintf("unknown attestor type: %s", attestorType))
		_ = validator.Suggest(
			"Run 'stamp list' to see available attestor types")
		return validator
	}

	// Single attestor mode does NOT require config file
	// Configuration comes from --set flags

	return nil
}

// validateSingleWorkflowMode validates configuration for single workflow execution.
func (o *RunOp) validateSingleWorkflowMode(workflowName string) error {
	validator := pkgerrors.NewValidator()

	var workflows []config.Workflow
	if err := o.config.UnmarshalKey(flags.Workflows, &workflows); err != nil {
		validator.AddError("config",
			"workflow execution requires a configuration file")
		_ = validator.Suggest(
			"Specify config file: --config <path>")
		return validator
	}

	found := false
	for _, workflow := range workflows {
		if workflow.Name == workflowName {
			found = true
			break
		}
	}

	if !found {
		validator.AddError("workflow",
			fmt.Sprintf("workflow not found: %s", workflowName))
		_ = validator.Suggest(
			fmt.Sprintf("Available workflows: %s", strings.Join(o.workflowNames(workflows), ", ")),
			fmt.Sprintf("Check spelling of '%s'", workflowName))
		return validator
	}

	return nil
}

// validateSingleWorkflowMode validates configuration for multiple workflow execution.
func (o *RunOp) validateMultipleWorkflowsMode(workflowNames []string) error {
	validator := pkgerrors.NewValidator()

	var availableWorkflows []config.Workflow
	if err := o.config.UnmarshalKey(flags.Workflows, &availableWorkflows); err != nil {
		validator.AddError("config",
			"multi-workflow execution requires a configuration file")
		_ = validator.Suggest(
			"Specify config file: --config <path>")
		return validator
	}

	workflowMap := make(map[string]bool)
	for _, workflow := range availableWorkflows {
		workflowMap[workflow.Name] = true
	}

	var notFound []string
	for _, name := range workflowNames {
		if !workflowMap[name] {
			notFound = append(notFound, name)
		}
	}

	if len(notFound) > 0 {
		validator.AddError("workflows",
			fmt.Sprintf("workflows not found: %v", notFound))
		_ = validator.Suggest(
			fmt.Sprintf("Available workflows: %s", strings.Join(o.workflowNames(availableWorkflows), ", ")))
		return validator
	}

	return nil
}

// validateFilteredWorkflowsMode validates configuration for filtered workflow execution.
func (o *RunOp) validateFilteredWorkflowsMode() error {
	validator := pkgerrors.NewValidator()

	var workflows []config.Workflow
	if err := o.config.UnmarshalKey(flags.Workflows, &workflows); err != nil {
		validator.AddError("config",
			"filtered workflow execution requires a configuration file")
		_ = validator.Suggest(
			"Specify config file: --config <path>")
		return validator
	}

	if len(workflows) == 0 {
		validator.AddError("workflows",
			"no workflows defined in configuration")
		return validator
	}

	filteredWorkflows := o.applyFilters(workflows)
	if len(filteredWorkflows) == 0 {
		validator.AddError("filters",
			"no workflows match the specified filters")
		_ = validator.Suggest(
			fmt.Sprintf("Available workflows: %s", strings.Join(o.workflowNames(workflows), ", ")),
			"Check your --tags, --include, and --exclude filters")
		return validator
	}

	return nil
}

// validateAllWorkflowsMode validates configuration for all workflows execution.
func (o *RunOp) validateAllWorkflowsMode() error {
	validator := pkgerrors.NewValidator()

	var workflows []config.Workflow
	if err := o.config.UnmarshalKey(flags.Workflows, &workflows); err != nil {
		validator.AddError("config",
			"all-workflows mode requires a configuration file")
		_ = validator.Suggest(
			"Specify config file: --config <path>")
		return validator
	}

	if len(workflows) == 0 {
		validator.AddError("workflows",
			"no workflows defined in configuration")
		_ = validator.Suggest(
			"Add workflows to your configuration file")
		return validator
	}

	return nil
}

// validateCommonSettings validates settings common to all modes.
func (o *RunOp) validateCommonSettings() error {
	if o.config.GetString(flags.Signer) != "" {
		if err := validation.ValidateSignerConfig(o.config); err != nil {
			return err
		}
	}

	if o.config.GetBool(flags.TransparencyEnable) {
		backend := o.config.GetString(flags.Signer)
		if backend == "key" && o.config.GetString(flags.PublicKey) == "" {
			return pkgerrors.NewUsageError(
				"--public-key required when uploading to Rekor with file-based signing",
				"Specify public key: --public-key <path>",
				"Or use Fulcio signing (--signer fulcio) which doesn't require a separate public key",
			)
		}
	}

	return nil
}

// Validate checks that the run operation has valid configuration and arguments.
func (o *RunOp) Validate(args []string) error {
	mode, err := o.determineExecutionMode(args)
	if err != nil {
		return err
	}
	o.mode = mode

	switch mode { //nolint:exhaustive // ModeUnknown should never reach here, validated by determineExecutionMode
	case ModeSingleAttestor:
		if err := o.validateSingleAttestorMode(); err != nil {
			return err
		}
	case ModeSingleWorkflow:
		if err := o.validateSingleWorkflowMode(args[0]); err != nil {
			return err
		}
	case ModeMultipleWorkflows:
		if err := o.validateMultipleWorkflowsMode(args); err != nil {
			return err
		}
	case ModeFilteredWorkflows:
		if err := o.validateFilteredWorkflowsMode(); err != nil {
			return err
		}
	case ModeAllWorkflows:
		if err := o.validateAllWorkflowsMode(); err != nil {
			return err
		}
	}

	if err := o.validateCommonSettings(); err != nil {
		return err
	}

	return nil
}

// NewRunOp creates a new RunOp instance with the provided configuration, logger, and output handler.
func NewRunOp(config config.ConfigurationIface, logger logger.Logger, output output.OutputIface) *RunOp {
	return &RunOp{
		config: config,
		logger: logger,
		output: output,
	}
}

// GetResult returns the pipeline execution result.
// Returns nil if Execute has not been called.
func (o *RunOp) GetResult() *pipeline.Result {
	return o.result
}
