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

package buildenv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	githubclient "github.com/thomsonreuters/stamp/pkg/clients/github"
	jwtclient "github.com/thomsonreuters/stamp/pkg/clients/jwt"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

// GitHubContext holds workflow context collected from the GitHub Actions environment.
type GitHubContext struct {
	Repository      string
	RepositoryOwner string
	SHA             string
	Ref             string
	RefType         string
	BaseRef         string
	HeadRef         string
	Actor           string
	EventName       string
	Event           map[string]any
	Vars            map[string]any
	RunNumber       string
	RunID           string
	RunAttempt      string
	Workflow        string
	ServerURL       string
	RepositoryID    string
	ActorID         string
	OwnerID         string
	Arch            string
	OS              string
}

// GitHubEnvironment implements BuildEnvironment for GitHub Actions.
type GitHubEnvironment struct {
	logger        logger.Logger
	opts          DetectOptions
	githubContext *GitHubContext
	oidcClaims    map[string]any
}

func NewGitHubEnvironment(log logger.Logger, opts DetectOptions) *GitHubEnvironment {
	return &GitHubEnvironment{
		logger: log,
		opts:   opts,
	}
}

// Detect checks if running in GitHub Actions, collects context, and validates the OIDC token.
func (g *GitHubEnvironment) Detect(ctx context.Context) (BuildEnvironment, error) {
	if !githubclient.IsGitHubActionsEnv() {
		return nil, errors.New("not a GitHub Actions environment")
	}

	ghCtx, err := parseGitHubContext()
	if err != nil {
		g.logger.WarnContext(ctx, "GITHUB_CONTEXT not available, falling back to env vars", "error", err.Error())
		ghCtx, err = collectGitHubContextFromEnv()
		if err != nil {
			if g.opts.CaptureEventPayload {
				return nil, &DetectionFatalError{Err: fmt.Errorf("capture-event-payload enabled but failed: %w", err)}
			}
			g.logger.WarnContext(ctx, "failed to read event payload, skipping", "error", err.Error())
		}
	}
	g.githubContext = ghCtx

	if !githubclient.IsOIDCEnvAvailable() {
		return nil, &DetectionFatalError{Err: errors.New(
			"GitHub Actions detected but initialization failed: OIDC token request not available (ACTIONS_ID_TOKEN_REQUEST_TOKEN/URL not set): ensure workflow has 'permissions.id-token: write'",
		)}
	}

	ghClient, err := githubclient.New(ctx, githubclient.Options{})
	if err != nil {
		return nil, &DetectionFatalError{Err: fmt.Errorf("GitHub Actions detected but initialization failed: %w", err)}
	}

	jwtC, err := jwtclient.New(ctx, jwtclient.WithLogger(g.logger))
	if err != nil {
		return nil, &DetectionFatalError{Err: fmt.Errorf("GitHub Actions detected but initialization failed: %w", err)}
	}

	audience := g.githubContext.Repository
	if audience == "" {
		audience = githubclient.DefaultAudience
	}

	g.logger.InfoContext(ctx, "fetching OIDC token from GitHub Actions", "audience", audience)
	token, err := ghClient.FetchIDToken(ctx, audience)
	if err != nil {
		return nil, &DetectionFatalError{Err: fmt.Errorf("GitHub Actions detected but initialization failed: %w", err)}
	}

	result, err := utils.VerifyOIDCToken(ctx, jwtC, token, utils.OIDCVerifyOptions{
		TrustedIssuers:   g.resolveOIDCIssuers(),
		ExpectedAudience: audience,
	})
	if err != nil {
		return nil, &DetectionFatalError{Err: fmt.Errorf("GitHub Actions detected but initialization failed: %w", err)}
	}

	g.oidcClaims = result.TokenInfo.Claims.CustomClaims
	g.logger.InfoContext(ctx, "build environment detected: GitHub Actions")

	return g, nil
}

func (g *GitHubEnvironment) Type() EnvironmentType { return EnvironmentGitHub }

// BuilderID returns the GitHub builder URI.
func (g *GitHubEnvironment) BuilderID(_ context.Context) string {
	return BuilderIDGitHub
}

func (g *GitHubEnvironment) SourceURI() string {
	repo := g.getStringClaim("repository")
	if repo == "" {
		return ""
	}
	ref := g.getStringClaim("ref")
	refSuffix := ""
	if ref != "" {
		refSuffix = "@" + ref
	}
	return fmt.Sprintf("git+%s/%s%s", g.serverURL(), repo, refSuffix)
}

func (g *GitHubEnvironment) SourceDigest() map[string]string {
	sha := g.getStringClaim("sha")
	if sha == "" {
		return nil
	}
	return map[string]string{"gitCommit": sha}
}

// InternalParameters collects provenance parameters from OIDC claims and runner env vars.
func (g *GitHubEnvironment) InternalParameters() map[string]any {
	params := map[string]any{}

	// From runner environment (non-OIDC)
	utils.AddNonEmpty(params, "arch", g.githubContext.Arch)
	utils.AddNonEmpty(params, "os", g.githubContext.OS)
	utils.AddNonEmpty(params, "github_run_number", g.getStringClaim("run_number"))
	utils.AddNonEmpty(params, "github_run_id", g.getStringClaim("run_id"))
	utils.AddNonEmpty(params, "github_run_attempt", g.getStringClaim("run_attempt"))
	utils.AddNonEmpty(params, "github_event_name", g.getStringClaim("event_name"))

	// Event payload is from the filesystem, not OIDC-verified
	if g.opts.CaptureEventPayload && g.githubContext.Event != nil {
		params["github_event_payload"] = g.githubContext.Event
	}

	// From OIDC claims (verified)
	utils.AddNonEmpty(params, "github_ref_type", g.getStringClaim("ref_type"))
	utils.AddNonEmpty(params, "github_ref", g.getStringClaim("ref"))
	utils.AddNonEmpty(params, "github_base_ref", g.getStringClaim("base_ref"))
	utils.AddNonEmpty(params, "github_head_ref", g.getStringClaim("head_ref"))
	utils.AddNonEmpty(params, "github_actor", g.getStringClaim("actor"))
	utils.AddNonEmpty(params, "github_sha1", g.getStringClaim("sha"))
	utils.AddNonEmpty(params, "github_repository_owner", g.getStringClaim("repository_owner"))
	utils.AddNonEmpty(params, "github_repository_id", g.getStringClaim("repository_id"))
	utils.AddNonEmpty(params, "github_actor_id", g.getStringClaim("actor_id"))
	utils.AddNonEmpty(params, "github_repository_owner_id", g.getStringClaim("repository_owner_id"))

	return params
}

func (g *GitHubEnvironment) ResolvedDependencies() []ResourceDescriptor {
	deps := []ResourceDescriptor{
		{
			URI:    g.SourceURI(),
			Digest: g.SourceDigest(),
		},
	}

	// Runner image dependency
	// Note: ImageOS and ImageVersion environment variables are automatically set by GitHub-hosted runners
	// but may not be available or accurate for self-hosted runners or GitHub Enterprise instances.
	imageOS := os.Getenv("ImageOS")
	imageVersion := os.Getenv("ImageVersion")
	if imageOS != "" && imageVersion != "" {
		// GitHub runner-images releases use format: ubuntu22/20260518.146
		// But ImageVersion env var might include extra patch version: 20260518.146.0
		// We need to trim to match the actual release tag format
		imageVersion = normalizeGitHubImageVersion(imageVersion)

		var runnerImageURI string

		// Check for custom runner image repository (for self-hosted/GHE runners)
		if customRepo := os.Getenv("RUNNER_IMAGE_REPO"); customRepo != "" {
			// Custom runner image repository specified
			runnerImageURI = fmt.Sprintf("%s/releases/tag/%s/%s", customRepo, imageOS, imageVersion)
		} else if g.serverURL() == githubclient.DefaultServerURL {
			// Standard GitHub-hosted runners - use official runner-images repo
			runnerImageURI = fmt.Sprintf("https://github.com/actions/runner-images/releases/tag/%s/%s",
				imageOS, imageVersion)
		} else {
			// GHE instance without custom repo specified - attempt to use GHE URL
			// Note: This is a best-effort guess; actual runner images might be hosted elsewhere
			runnerImageURI = fmt.Sprintf("%s/actions/runner-images/releases/tag/%s/%s",
				g.serverURL(), imageOS, imageVersion)
			g.logger.Debug("Using GHE server URL for runner image; set RUNNER_IMAGE_REPO for accurate provenance")
		}

		deps = append(deps, ResourceDescriptor{
			URI: runnerImageURI,
		})
	}

	return deps
}

func (g *GitHubEnvironment) InvocationID() string {
	id := g.getStringClaim("run_id")
	if attempt := g.getStringClaim("run_attempt"); attempt != "" {
		id = id + "-" + attempt
	}
	return id
}

type WorkflowParameters struct {
	EventInputs any `json:"event_inputs,omitempty"`
	VarsContext any `json:"vars,omitempty"`
}

func (g *GitHubEnvironment) WorkflowInputs() any {
	var eventInputs any
	var varsContext any

	if g.githubContext.Event != nil {
		eventInputs = g.githubContext.Event["inputs"]
	}
	if g.githubContext.Vars != nil {
		varsContext = g.githubContext.Vars
	}

	if eventInputs == nil && varsContext == nil {
		return nil
	}

	return WorkflowParameters{
		EventInputs: eventInputs,
		VarsContext: varsContext,
	}
}

func (g *GitHubEnvironment) Context() *GitHubContext {
	return g.githubContext
}

func (g *GitHubEnvironment) serverURL() string {
	if g.githubContext.ServerURL != "" {
		return g.githubContext.ServerURL
	}
	return githubclient.DefaultServerURL
}

func (g *GitHubEnvironment) getStringClaim(key string) string {
	if g.oidcClaims == nil {
		return ""
	}
	val, ok := g.oidcClaims[key]
	if !ok {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (g *GitHubEnvironment) resolveOIDCIssuers() []string {
	return githubclient.DeriveOIDCIssuers()
}

func parseGitHubContext() (*GitHubContext, error) {
	ghContextJSON := os.Getenv("GITHUB_CONTEXT")
	if ghContextJSON == "" {
		return nil, errors.New("GITHUB_CONTEXT environment variable not set")
	}

	var raw struct {
		Repository      string         `json:"repository"`
		RepositoryOwner string         `json:"repository_owner"`
		SHA             string         `json:"sha"`
		Ref             string         `json:"ref"`
		RefType         string         `json:"ref_type"`
		BaseRef         string         `json:"base_ref"`
		HeadRef         string         `json:"head_ref"`
		Actor           string         `json:"actor"`
		EventName       string         `json:"event_name"`
		Event           map[string]any `json:"event"`
		Vars            map[string]any `json:"vars"`
		RunNumber       string         `json:"run_number"`
		RunID           string         `json:"run_id"`
		RunAttempt      string         `json:"run_attempt"`
		Workflow        string         `json:"workflow"`
		ServerURL       string         `json:"server_url"`
	}

	if err := json.Unmarshal([]byte(ghContextJSON), &raw); err != nil {
		return nil, fmt.Errorf("parsing GITHUB_CONTEXT: %w", err)
	}

	return &GitHubContext{
		Repository:      raw.Repository,
		RepositoryOwner: raw.RepositoryOwner,
		SHA:             raw.SHA,
		Ref:             raw.Ref,
		RefType:         raw.RefType,
		BaseRef:         raw.BaseRef,
		HeadRef:         raw.HeadRef,
		Actor:           raw.Actor,
		EventName:       raw.EventName,
		Event:           raw.Event,
		Vars:            raw.Vars,
		RunNumber:       raw.RunNumber,
		RunID:           raw.RunID,
		RunAttempt:      raw.RunAttempt,
		Workflow:        raw.Workflow,
		ServerURL:       raw.ServerURL,
		Arch:            os.Getenv("RUNNER_ARCH"),
		OS:              os.Getenv("ImageOS"),
	}, nil
}

// collectGitHubContextFromEnv is the fallback when GITHUB_CONTEXT is unavailable.
func collectGitHubContextFromEnv() (*GitHubContext, error) {
	ctx := &GitHubContext{
		Repository:      os.Getenv("GITHUB_REPOSITORY"),
		RepositoryOwner: os.Getenv("GITHUB_REPOSITORY_OWNER"),
		SHA:             os.Getenv("GITHUB_SHA"),
		Ref:             os.Getenv("GITHUB_REF"),
		RefType:         os.Getenv("GITHUB_REF_TYPE"),
		BaseRef:         os.Getenv("GITHUB_BASE_REF"),
		HeadRef:         os.Getenv("GITHUB_HEAD_REF"),
		Actor:           os.Getenv("GITHUB_ACTOR"),
		EventName:       os.Getenv("GITHUB_EVENT_NAME"),
		RunID:           os.Getenv("GITHUB_RUN_ID"),
		RunNumber:       os.Getenv("GITHUB_RUN_NUMBER"),
		RunAttempt:      os.Getenv("GITHUB_RUN_ATTEMPT"),
		Workflow:        os.Getenv("GITHUB_WORKFLOW"),
		ServerURL:       os.Getenv("GITHUB_SERVER_URL"),
		Arch:            os.Getenv("RUNNER_ARCH"),
		OS:              os.Getenv("ImageOS"),
	}
	event, err := readEventPayloadFromPath()
	if err != nil {
		return ctx, fmt.Errorf("reading event payload: %w", err)
	}
	ctx.Event = event
	return ctx, nil
}

func readEventPayloadFromPath() (map[string]any, error) {
	eventPath := os.Getenv("GITHUB_EVENT_PATH")
	if eventPath == "" {
		return nil, nil
	}
	return utils.ReadJSONFile(eventPath)
}

// normalizeGitHubImageVersion trims ImageVersion to two components to match release tags.
// E.g., "20260518.146.0" -> "20260518.146".
func normalizeGitHubImageVersion(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return version
}
