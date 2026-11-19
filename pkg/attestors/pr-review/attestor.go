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

// Package prreview generates pr-review attestations for merged GitHub pull requests. The
// attestation binds to the landed (post-merge) commit and records the reviews, the landing,
// and the branch rulesets that applied. It only reads from the GitHub REST API and
// authenticates with a GitHub App installation token.
package prreview

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/thomsonreuters/stamp/pkg/clients/github"
	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	prpredicate "github.com/thomsonreuters/stamp/pkg/predicates/pr-review/v1"
)

func init() {
	_ = core.RegisterAttestor(func(log logger.Logger) core.Attestor {
		return &Attestor{
			logger: log.With("attestor_id", id),
			now:    time.Now,
		}
	})
}

// Config holds parsed configuration values for the pr-review attestor.
type Config struct {
	Repository  string
	Owner       string
	Repo        string
	PullRequest int
	APIURL      string
	TokenEnv    string
}

// Attestor implements core.Attestor for GitHub pull-request review attestation.
type Attestor struct {
	logger logger.Logger
	config Config
	now    func() time.Time

	client   github.RESTClientIface
	evidence *evidence
	subjects []intoto.Subject
}

func (a *Attestor) ID() string           { return id }
func (a *Attestor) PredicateURI() string { return prpredicate.PredicateURI }
func (a *Attestor) Name() string         { return name }
func (a *Attestor) Description() string  { return description }

// ConfigSchema returns the configuration schema defining all available options.
func (a *Attestor) ConfigSchema() []core.ConfigField {
	return []core.ConfigField{
		{
			Name:        configRepository,
			Type:        "string",
			Required:    true,
			Description: "GitHub repository in owner/name form",
			Example:     "acme/widget-svc",
		},
		{
			Name:        configPullRequest,
			Type:        "int",
			Required:    true,
			Description: "Number of the merged pull request",
			Example:     512,
		},
		{
			Name:        configAPIURL,
			Type:        "string",
			Default:     github.DefaultAPIURL,
			Description: "GitHub REST API base URL (https only); set for GitHub Enterprise Server",
			Example:     "https://github.example.com/api/v3",
		},
		{
			Name:        configTokenEnv,
			Type:        "string",
			Default:     DefaultTokenEnv,
			Description: "Environment variable holding the GitHub App installation token (ghs_...); personal access tokens are rejected",
			Example:     "GH_APP_TOKEN",
		},
	}
}

func (a *Attestor) parseConfig(config core.Config) {
	a.config = Config{
		Repository:  strings.TrimSpace(config.GetString(configRepository, "")),
		PullRequest: config.GetInt(configPullRequest, 0),
		APIURL:      strings.TrimRight(config.GetString(configAPIURL, github.DefaultAPIURL), "/"),
		TokenEnv:    config.GetString(configTokenEnv, DefaultTokenEnv),
	}
	if owner, repo, ok := strings.Cut(a.config.Repository, "/"); ok {
		a.config.Owner, a.config.Repo = owner, repo
	}
}

// PreAttest validates configuration and creates the GitHub REST client.
func (a *Attestor) PreAttest(ctx context.Context, config core.Config) error {
	if err := a.ValidateConfig(config); err != nil {
		return err
	}

	client, err := github.NewREST(ctx, github.RESTOptions{
		BaseURL: a.config.APIURL,
		Token:   os.Getenv(a.config.TokenEnv),
		Logger:  a.logger,
	})
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "pre_attest",
			"failed to initialize GitHub client from environment variable "+a.config.TokenEnv)
	}
	a.client = client
	if a.now == nil {
		a.now = time.Now
	}
	return nil
}

// Attest collects the GitHub evidence for the merged pull request.
func (a *Attestor) Attest(ctx context.Context, _ core.Config) error {
	start := time.Now()
	a.logger.InfoContext(ctx, "collecting pull request review evidence",
		"repository", a.config.Repository, "pull_request", a.config.PullRequest)

	ev, err := a.collect(ctx)
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "attest", "failed to collect pull request review evidence")
	}
	a.evidence = ev

	a.logger.InfoContext(ctx, "pull request review evidence collected",
		"repository", a.config.Repository,
		"pull_request", a.config.PullRequest,
		"duration_ms", time.Since(start).Milliseconds())
	return nil
}

// PostAttest is a no-op for this attestor.
func (a *Attestor) PostAttest(_ context.Context, _ core.Config) error {
	return nil
}

// GeneratePredicate builds the pr-review predicate. Any missing required field fails the whole predicate.
func (a *Attestor) GeneratePredicate(_ core.Config) (any, error) {
	if a.evidence == nil {
		return nil, pkgerrors.WrapWithContext(ErrNotCollected, id, "generate_predicate", "attest must run first")
	}
	predicate, subjects, err := buildPredicate(a.evidence)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, id, "generate_predicate", "failed to build pr-review predicate")
	}
	a.subjects = subjects
	return predicate, nil
}

// Subjects returns the repository URL bound to the landed commit.
func (a *Attestor) Subjects(_ core.Config) []intoto.Subject {
	return a.subjects
}

// Schema returns the JSON schema for the predicate.
func (a *Attestor) Schema() *jsonschema.Schema {
	return prpredicate.Schema()
}
