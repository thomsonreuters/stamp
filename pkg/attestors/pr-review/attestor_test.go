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

package prreview

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/clients/github"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	prpredicate "github.com/thomsonreuters/stamp/pkg/predicates/pr-review/v1"
)

func TestMetadata(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "pr-review", a.ID())
	assert.Equal(t, prpredicate.PredicateURI, a.PredicateURI())
	assert.Equal(t, "https://thomsonreuters.com/pr-review/v1", a.PredicateURI())
	assert.Equal(t, "Pull Request Review Attestor", a.Name())
	assert.NotEmpty(t, a.Description())
	assert.Equal(t, "Pull Request Review Attestation", a.Schema().Title)
}

func TestRegistered(t *testing.T) {
	a, err := core.GetAttestorByID(id, logger.NewNoop())
	require.NoError(t, err)
	assert.Equal(t, id, a.ID())
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  core.Config
		wantErr string
	}{
		{name: "valid", config: core.Config{configRepository: "acme/widget-svc", configPullRequest: 512}},
		{
			name: "valid enterprise",
			config: core.Config{
				configRepository: "acme/widget.svc", configPullRequest: 1,
				configAPIURL: "https://github.example.com/api/v3/", configTokenEnv: "GH_APP_TOKEN",
			},
		},
		{name: "missing repository", config: core.Config{configPullRequest: 1}, wantErr: configRepository},
		{name: "missing pull request", config: core.Config{configRepository: "acme/widget"}, wantErr: configPullRequest},
		{name: "repository without owner", config: core.Config{configRepository: "widget", configPullRequest: 1}, wantErr: configRepository},
		{name: "repository path traversal", config: core.Config{configRepository: "acme/../x", configPullRequest: 1}, wantErr: configRepository},
		{name: "pull request not int", config: core.Config{configRepository: "acme/w", configPullRequest: "12"}, wantErr: configPullRequest},
		{name: "pull request zero", config: core.Config{configRepository: "acme/w", configPullRequest: 0}, wantErr: configPullRequest},
		{
			name:    "http api url",
			config:  core.Config{configRepository: "acme/w", configPullRequest: 1, configAPIURL: "http://api.github.com"},
			wantErr: configAPIURL,
		},
		{
			name:    "api url with credentials",
			config:  core.Config{configRepository: "acme/w", configPullRequest: 1, configAPIURL: "https://u:p@api.github.com"},
			wantErr: configAPIURL,
		},
		{
			name:    "bad token env",
			config:  core.Config{configRepository: "acme/w", configPullRequest: 1, configTokenEnv: "A-B"},
			wantErr: configTokenEnv,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Attestor{logger: logger.NewNoop()}
			err := a.ValidateConfig(tt.config)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestParseConfig(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	a.parseConfig(core.Config{configRepository: " acme/widget ", configPullRequest: 7})
	assert.Equal(t, Config{
		Repository: "acme/widget", Owner: "acme", Repo: "widget", PullRequest: 7,
		APIURL: github.DefaultAPIURL, TokenEnv: DefaultTokenEnv,
	}, a.config)
}

func TestPreAttestRequiresInstallationToken(t *testing.T) {
	config := core.Config{configRepository: "acme/widget", configPullRequest: 1}

	t.Run("missing token", func(t *testing.T) {
		t.Setenv(DefaultTokenEnv, "")
		a := &Attestor{logger: logger.NewNoop()}
		err := a.PreAttest(context.Background(), config)
		require.ErrorIs(t, err, github.ErrMissingInstallationToken)
	})

	t.Run("personal access token rejected", func(t *testing.T) {
		for _, token := range []string{"ghp_personal", "github_pat_fine", "gho_oauth"} {
			t.Setenv(DefaultTokenEnv, token)
			a := &Attestor{logger: logger.NewNoop()}
			err := a.PreAttest(context.Background(), config)
			require.ErrorIs(t, err, github.ErrNotInstallationToken, token)
		}
	})

	t.Run("installation token from custom env", func(t *testing.T) {
		t.Setenv("CUSTOM_APP_TOKEN", testToken)
		a := &Attestor{logger: logger.NewNoop()}
		cfg := core.Config{configRepository: "acme/widget", configPullRequest: 1, configTokenEnv: "CUSTOM_APP_TOKEN"}
		require.NoError(t, a.PreAttest(context.Background(), cfg))
		assert.NotNil(t, a.client)
		assert.NotNil(t, a.now)
	})
}

func TestGeneratePredicateBeforeAttest(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	predicate, err := a.GeneratePredicate(nil)
	require.ErrorIs(t, err, ErrNotCollected)
	assert.Nil(t, predicate)
	assert.Empty(t, a.Subjects(nil))
}

// runAttestor drives the full lifecycle and returns the in-toto statement JSON.
func runAttestor(t *testing.T, a *Attestor, config core.Config) ([]byte, error) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, a.PreAttest(ctx, config))
	if err := a.Attest(ctx, config); err != nil {
		return nil, err
	}
	require.NoError(t, a.PostAttest(ctx, config))
	predicate, err := a.GeneratePredicate(config)
	if err != nil {
		return nil, err
	}
	statement, err := intoto.NewStatement(a.PredicateURI(), predicate, a.Subjects(config))
	require.NoError(t, err)
	require.NoError(t, statement.Validate())
	return statement.ToJSONIndent()
}

func TestGolden(t *testing.T) {
	for _, sample := range []string{sample1, sample2} {
		t.Run(sample, func(t *testing.T) {
			f := loadFixture(t, sample)
			a, m, config := newTestAttestor(t, f)
			f.expect(t, m)

			got, err := runAttestor(t, a, config)
			require.NoError(t, err)
			assert.JSONEq(t, string(f.golden), string(got))
			m.AssertExpectations(t)
		})
	}
}

func TestAttestNotMerged(t *testing.T) {
	f := loadFixture(t, sample1)
	f.pullRequest["merged"] = false
	a, m, config := newTestAttestor(t, f)
	f.expect(t, m)

	_, err := runAttestor(t, a, config)
	require.ErrorIs(t, err, ErrNotMerged)
	assert.Contains(t, err.Error(), "example-org/example-service#101")
	m.AssertNotCalled(t, "GetCommit", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assert.Nil(t, a.evidence)
}

func TestAttestRuleSuites(t *testing.T) {
	t.Run("404 marks evaluation unavailable", func(t *testing.T) {
		f := loadFixture(t, sample1)
		a, m, config := newTestAttestor(t, f)
		f.expect(t, m)

		_, err := runAttestor(t, a, config)
		require.NoError(t, err)
		predicate, err := a.GeneratePredicate(config)
		require.NoError(t, err)
		evaluation := asPredicate(t, predicate).ReviewPolicy.Evaluation
		assert.False(t, evaluation.Available)
		require.NotNil(t, evaluation.HTTPStatus)
		assert.Equal(t, http.StatusNotFound, *evaluation.HTTPStatus)
		assert.Empty(t, evaluation.Suites)
	})

	t.Run("available suites filtered to landed commit", func(t *testing.T) {
		f := loadFixture(t, sample1)
		landed, _ := f.pullRequest["merge_commit_sha"].(string)
		f.ruleSuites = github.Object{
			"available": true,
			"suites": []any{
				map[string]any{"id": "1", "after_sha": landed, "result": "pass"},
				map[string]any{"id": "2", "after_sha": "0000000000000000000000000000000000000000", "result": "fail"},
				map[string]any{"id": "3", "after_sha": landed, "result": "bypass"},
			},
		}
		a, m, config := newTestAttestor(t, f)
		f.expect(t, m)

		_, err := runAttestor(t, a, config)
		require.NoError(t, err)
		predicate, err := a.GeneratePredicate(config)
		require.NoError(t, err)
		evaluation := asPredicate(t, predicate).ReviewPolicy.Evaluation
		assert.True(t, evaluation.Available)
		assert.Nil(t, evaluation.HTTPStatus)
		require.Len(t, evaluation.Suites, 2)
		assert.Equal(t, "pass", evaluation.Suites[0]["result"])
		assert.Equal(t, "bypass", evaluation.Suites[1]["result"])
	})

	t.Run("other errors stop the run", func(t *testing.T) {
		f := loadFixture(t, sample1)
		a, m, config := newTestAttestor(t, f)
		forbidden := &github.APIError{Method: http.MethodGet, Path: "/rule-suites", StatusCode: http.StatusForbidden}
		m.On("ListRuleSuites", mock.Anything, fixtureOwner, fixtureRepo, "refs/heads/main").Return(nil, forbidden).Once()
		f.expect(t, m)

		_, err := runAttestor(t, a, config)
		require.Error(t, err)
		var apiErr *github.APIError
		require.ErrorAs(t, err, &apiErr)
		assert.Equal(t, http.StatusForbidden, apiErr.StatusCode)
		assert.Nil(t, a.evidence)
	})
}

func TestAttestAPIErrorStopsRun(t *testing.T) {
	f := loadFixture(t, sample1)
	a, m, config := newTestAttestor(t, f)
	boom := errors.New("boom")
	m.On("ListIssueTimeline", mock.Anything, fixtureOwner, fixtureRepo, sample1PR).Return(nil, boom).Once()
	f.expect(t, m)

	_, err := runAttestor(t, a, config)
	require.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), "list timeline")
}

func TestAttestRulesetFiltering(t *testing.T) {
	f := loadFixture(t, sample1)
	f.rulesets = append(f.rulesets,
		github.Object{
			"id": json64(1), "name": "evaluate-only", "target": "branch", "enforcement": "evaluate",
			"conditions": map[string]any{"ref_name": map[string]any{"include": []any{"~ALL"}, "exclude": []any{}}},
			"rules":      []any{prRule(5)},
		},
		github.Object{
			"id": json64(2), "name": "other-branch", "target": "branch", "enforcement": "active",
			"conditions": map[string]any{"ref_name": map[string]any{"include": []any{"refs/heads/dev"}, "exclude": []any{}}},
			"rules":      []any{prRule(5)},
		},
		github.Object{
			"id": json64(3), "name": "tags", "target": "tag", "enforcement": "active",
			"conditions": map[string]any{"ref_name": map[string]any{"include": []any{"~ALL"}, "exclude": []any{}}},
			"rules":      []any{prRule(5)},
		},
		github.Object{
			"id": json64(4), "name": "excluded", "target": "branch", "enforcement": "active",
			"conditions": map[string]any{"ref_name": map[string]any{"include": []any{"~ALL"}, "exclude": []any{"main"}}},
			"rules":      []any{prRule(5)},
		},
		github.Object{
			"id": json64(5), "name": "applies", "target": "branch", "enforcement": "active",
			"conditions": map[string]any{"ref_name": map[string]any{"include": []any{"refs/heads/main"}, "exclude": []any{}}},
			"rules":      []any{prRule(3)},
		},
	)
	a, m, config := newTestAttestor(t, f)
	f.expect(t, m)

	_, err := runAttestor(t, a, config)
	require.NoError(t, err)
	predicate, err := a.GeneratePredicate(config)
	require.NoError(t, err)

	var names []string
	for _, req := range asPredicate(t, predicate).ReviewPolicy.Requirements {
		names = append(names, req.RulesetName)
	}
	// Sorted by ruleset ID.
	assert.Equal(t, []string{"applies", "main-branch-protection", "audit-ruleset"}, names)
}

func TestAttestResolvesUserReviewer(t *testing.T) {
	f := loadFixture(t, sample1)
	f.rulesets = append(f.rulesets, github.Object{
		"id": json64(5), "name": "user-reviewer", "target": "branch", "enforcement": "active",
		"conditions": map[string]any{"ref_name": map[string]any{"include": []any{"~DEFAULT_BRANCH"}}},
		"rules": []any{map[string]any{
			"type": "pull_request",
			"parameters": map[string]any{
				"required_approving_review_count": json64(1),
				"required_reviewers": []any{
					map[string]any{"reviewer": map[string]any{"id": json64(42), "type": "User"}},
					map[string]any{"minimum_approvals": json64(1), "reviewer": map[string]any{"id": json64(sampleTeamID), "type": "Team"}},
				},
			},
		}},
	})
	f.users = []github.Object{{"id": json64(42), "node_id": "U_42", "login": "erin-example", "type": "User"}}
	a, m, config := newTestAttestor(t, f)
	f.expect(t, m)

	_, err := runAttestor(t, a, config)
	require.NoError(t, err)
	predicate, err := a.GeneratePredicate(config)
	require.NoError(t, err)

	requirements := asPredicate(t, predicate).ReviewPolicy.Requirements
	require.Len(t, requirements, 3)
	reviewers := requirements[0].Reviewers
	require.Len(t, reviewers, 2)
	assert.Nil(t, reviewers[0].MinimumApprovals)
	assert.Equal(t, &prpredicate.Actor{ID: 42, NodeID: "U_42", Login: "erin-example", Type: "User"}, reviewers[0].User)
	assert.Equal(t, "service-maintainers", reviewers[1].Team.Slug)
	// The shared team is looked up once.
	m.AssertNumberOfCalls(t, "GetTeamByID", 1)
}
