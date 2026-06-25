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

package githubworkflow

import (
	"context"
	"strconv"

	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
)

// collectAllData orchestrates the collection of all GitHub Actions workflow information.
func (a *Attestor) collectAllData(ctx context.Context, _ core.Config) error {
	// Read environment variables ──────────────────────────────
	ghInfo := readGitHubActionInfo(ctx, a.logger)
	if err := ghInfo.Validate(); err != nil {
		return pkgerrors.WrapWithContext(err, id, "collect", "not running in GitHub Actions environment")
	}

	// Fetch & verify OIDC token
	oidcInfo, allClaims, err := a.fetchAndVerifyOIDCToken(ctx)
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "collect",
			"OIDC token is required but failed: ensure workflow has 'permissions.id-token: write'")
	}
	if oidcInfo == nil {
		return pkgerrors.NewWithContext(id, "collect",
			"OIDC token is required but not available: ensure workflow has 'permissions.id-token: write'")
	}

	a.oidcInfo = oidcInfo
	a.allClaims = allClaims

	// Populate predicate fields from env vars (not available in OIDC)
	a.workflowInfo.Job = ghInfo.WorkflowJob
	a.workflowInfo.Action = ghInfo.WorkflowAction
	a.workflowInfo.ActionPath = ghInfo.WorkflowActionPath

	a.runnerInfo.Name = ghInfo.RunnerName
	a.runnerInfo.OS = ghInfo.RunnerOS
	a.runnerInfo.Arch = ghInfo.RunnerArch

	a.repositoryInfo.RefName = ghInfo.GithubRefName
	a.metadataInfo.ServerURL = ghInfo.GithubServerURL

	// Populate predicate fields from OIDC claims (source of truth)
	a.workflowInfo.Name = a.getStringClaim("workflow")
	a.workflowInfo.Ref = a.getStringClaim("workflow_ref")
	a.workflowInfo.SHA = a.getStringClaim("workflow_sha")
	a.workflowInfo.JobWorkflowRef = a.getStringClaim("job_workflow_ref")
	a.workflowInfo.RunID = a.getStringClaim("run_id")
	a.workflowInfo.RunNumber, _ = strconv.Atoi(a.getStringClaim("run_number"))
	a.workflowInfo.RunAttempt, _ = strconv.Atoi(a.getStringClaim("run_attempt"))

	a.runnerInfo.HostedType = a.getStringClaim("runner_environment")

	a.triggerInfo.EventName = a.getStringClaim("event_name")
	a.triggerInfo.Actor = a.getStringClaim("actor")
	a.triggerInfo.ActorID = a.getStringClaim("actor_id")
	a.triggerInfo.HeadRef = a.getStringClaim("head_ref")
	a.triggerInfo.BaseRef = a.getStringClaim("base_ref")

	a.repositoryInfo.FullName = a.getStringClaim("repository")
	a.repositoryInfo.Owner = a.getStringClaim("repository_owner")
	a.repositoryInfo.OwnerID = a.getStringClaim("repository_owner_id")
	a.repositoryInfo.ID = a.getStringClaim("repository_id")
	a.repositoryInfo.Visibility = a.getStringClaim("repository_visibility")
	a.repositoryInfo.SHA = a.getStringClaim("sha")
	a.repositoryInfo.Ref = a.getStringClaim("ref")
	a.repositoryInfo.RefType = a.getStringClaim("ref_type")

	// workflow file subject
	if a.config.SubjectWorkflowFile {
		digest, err := ghInfo.GetWorkflowFileDigest(ctx)
		if err != nil {
			a.logger.WarnContext(ctx, "failed to get workflow file digest", "error", err.Error())
		}
		a.workflowFileSHA = digest
		a.workflowFilePath = ghInfo.WorkflowFilePath
	}

	// captured environment variables
	if a.config.CaptureEnvironment {
		a.runnerInfo.Environment = ghInfo.CaptureEnvironmentVariables(
			ctx, a.logger, a.config.EnvIncludePatterns, a.config.EnvExcludePatterns)
	}

	// event payload
	if a.config.CaptureEventPayload {
		if err := a.captureEventPayload(ctx, &ghInfo); err != nil {
			return err
		}
	}

	return nil
}

// captureEventPayload reads the event payload file and stores the result.
// Respects redact and missing-event-behavior config.
func (a *Attestor) captureEventPayload(ctx context.Context, ghInfo *GitHubActionInfo) error {
	payload, size, err := ghInfo.ReadEventPayload(ctx, a.config.RedactEventPayload, a.config.RedactPatterns)
	if err != nil {
		return a.handleEventPayloadError(err.Error())
	}

	a.triggerInfo.EventPayload = payload
	a.triggerInfo.EventPayloadSize = size
	return nil
}

// handleEventPayloadError handles event payload errors based on missing-event-behavior configuration.
// This provides unified error handling for all event payload issues: missing files, oversized payloads,
// invalid JSON, and read failures. The behavior is controlled by the missing-event-behavior setting:
//   - "allow": Continue without payload (no error)
//   - "warn": Continue without payload (log warning)
//   - "fail": Abort attestation (return error)
func (a *Attestor) handleEventPayloadError(reason string) error {
	a.logger.Debug("handling event payload error", "reason", reason)
	behavior := a.config.MissingEventBehavior

	switch behavior {
	case MissingEventBehaviorAllow:
		a.logger.Debug("event payload error allowed", "reason", reason, "behavior", behavior)
		return nil

	case MissingEventBehaviorWarn:
		a.logger.Warn("event payload error", "reason", reason, "behavior", behavior)
		return nil

	case MissingEventBehaviorFail:
		a.logger.Error("event payload error", "reason", reason, "behavior", behavior)
		return pkgerrors.NewWithContext(id, "collect", reason)

	default:
		a.logger.Warn("invalid missing-event-behavior value, defaulting to warn",
			"value", behavior,
			"valid_values", validMissingEventBehaviors)
		return nil
	}
}
