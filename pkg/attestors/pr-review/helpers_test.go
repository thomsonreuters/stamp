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
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/clients/github"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/logger"
	prpredicate "github.com/thomsonreuters/stamp/pkg/predicates/pr-review/v1"
)

const (
	fixtureRepository = "example-org/example-service"
	fixtureOwner      = "example-org"
	fixtureRepo       = "example-service"
	testToken         = "ghs_testinstallationtoken"

	// sample1 is a squash merge through a merge queue with a team reviewer and no rule-suite access.
	sample1   = "sample-1"
	sample1PR = 101
	// sample2 is a merge commit with team and user reviewers and readable rule suites.
	sample2 = "sample-2"

	sampleTeamID = 3001
)

// fixture holds synthetic GitHub responses in the layout produced by the pr-review predicate pilot.
type fixture struct {
	number      int
	collectedAt time.Time
	repository  github.Object
	pullRequest github.Object
	reviews     []github.Object
	timeline    []github.Object
	commit      github.Object
	rulesets    []github.Object
	teams       []github.Object
	users       []github.Object
	ruleSuites  github.Object
	golden      []byte
}

func decodeJSON(t *testing.T, data []byte, out any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(out))
}

func readFixtureFile(t *testing.T, dir, name string, out any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", dir, name))
	require.NoError(t, err)
	decodeJSON(t, data, out)
}

func loadFixture(t *testing.T, dir string) *fixture {
	t.Helper()
	f := &fixture{}

	var manifest struct {
		CollectedAt string `json:"collectedAt"`
		PullRequest int    `json:"pullRequest"`
	}
	readFixtureFile(t, dir, "manifest.json", &manifest)
	collectedAt, err := time.Parse(time.RFC3339, manifest.CollectedAt)
	require.NoError(t, err)
	f.collectedAt = collectedAt
	f.number = manifest.PullRequest

	readFixtureFile(t, dir, "repository.json", &f.repository)
	readFixtureFile(t, dir, "pull-request.json", &f.pullRequest)
	readFixtureFile(t, dir, "reviews.json", &f.reviews)
	readFixtureFile(t, dir, "timeline.json", &f.timeline)
	readFixtureFile(t, dir, "landed-commit.json", &f.commit)
	readFixtureFile(t, dir, "rulesets.json", &f.rulesets)
	readFixtureFile(t, dir, "reviewer-teams.json", &f.teams)
	readFixtureFile(t, dir, "reviewer-users.json", &f.users)
	readFixtureFile(t, dir, "rule-suites.json", &f.ruleSuites)

	f.golden, err = os.ReadFile(filepath.Join("testdata", dir, "predicate.json"))
	require.NoError(t, err)
	return f
}

func json64(n int64) json.Number {
	return json.Number(strconv.FormatInt(n, 10))
}

func asObject(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func sub(obj github.Object, key string) github.Object {
	return asObject(obj[key])
}

func asPredicate(t *testing.T, v any) prpredicate.Predicate {
	t.Helper()
	p, ok := v.(prpredicate.Predicate)
	require.True(t, ok, "unexpected predicate type %T", v)
	return p
}

// prRule returns a pull_request rule with no named reviewers.
func prRule(count int64) map[string]any {
	return map[string]any{
		"type":       "pull_request",
		"parameters": map[string]any{"required_approving_review_count": json64(count), "required_reviewers": []any{}},
	}
}

func objectID(t *testing.T, obj github.Object) int64 {
	t.Helper()
	n, ok := toInt64(obj["id"])
	require.True(t, ok, "object has no integer id")
	return n
}

// expect registers mock responses for every GitHub call the attestor makes for this fixture.
func (f *fixture) expect(t *testing.T, m *github.MockRESTClient) {
	t.Helper()
	ctx := mock.Anything
	m.On("GetRepository", ctx, fixtureOwner, fixtureRepo).Return(f.repository, nil)
	m.On("GetPullRequest", ctx, fixtureOwner, fixtureRepo, f.number).Return(f.pullRequest, nil)
	m.On("ListPullRequestReviews", ctx, fixtureOwner, fixtureRepo, f.number).Return(f.reviews, nil)
	m.On("ListIssueTimeline", ctx, fixtureOwner, fixtureRepo, f.number).Return(f.timeline, nil)

	sha, _ := f.pullRequest["merge_commit_sha"].(string)
	m.On("GetCommit", ctx, fixtureOwner, fixtureRepo, sha).Return(f.commit, nil)

	summaries := make([]github.Object, 0, len(f.rulesets))
	for _, ruleset := range f.rulesets {
		rulesetID := objectID(t, ruleset)
		summaries = append(summaries, github.Object{"id": json.Number(strconv.FormatInt(rulesetID, 10)), "name": ruleset["name"]})
		m.On("GetRuleset", ctx, fixtureOwner, fixtureRepo, rulesetID).Return(ruleset, nil)
	}
	m.On("ListRulesets", ctx, fixtureOwner, fixtureRepo).Return(summaries, nil)

	orgID := objectID(t, sub(f.repository, "owner"))
	for _, team := range f.teams {
		m.On("GetTeamByID", ctx, orgID, objectID(t, team)).Return(team, nil)
	}
	for _, user := range f.users {
		m.On("GetUserByID", ctx, objectID(t, user)).Return(user, nil)
	}

	base, _ := f.pullRequest["base"].(map[string]any)
	baseRef, _ := base["ref"].(string)
	if available, _ := f.ruleSuites["available"].(bool); available {
		suites := []github.Object{}
		for _, s := range asSlice(f.ruleSuites["suites"]) {
			suites = append(suites, asObject(s))
		}
		m.On("ListRuleSuites", ctx, fixtureOwner, fixtureRepo, refsHeadsPrefix+baseRef).Return(suites, nil)
	} else {
		m.On("ListRuleSuites", ctx, fixtureOwner, fixtureRepo, refsHeadsPrefix+baseRef).
			Return(nil, &github.APIError{Method: http.MethodGet, Path: "/rule-suites", StatusCode: http.StatusNotFound})
	}
}

// newTestAttestor returns an attestor wired to a mock client and a fixed clock.
func newTestAttestor(t *testing.T, f *fixture) (*Attestor, *github.MockRESTClient, core.Config) {
	t.Helper()
	m := github.SetupMockRESTClient(t)
	t.Setenv(DefaultTokenEnv, testToken)
	a := &Attestor{logger: logger.NewNoop(), now: func() time.Time { return f.collectedAt }}
	config := core.Config{configRepository: fixtureRepository, configPullRequest: f.number}
	return a, m, config
}

// evidence returns evidence equivalent to what collect produces for the fixture.
func (f *fixture) evidence(t *testing.T) *evidence {
	t.Helper()
	ev := &evidence{
		collectedAt: f.collectedAt,
		repository:  f.repository,
		pullRequest: f.pullRequest,
		reviews:     f.reviews,
		timeline:    f.timeline,
		commit:      f.commit,
		rulesets:    f.rulesets,
		teams:       map[int64]github.Object{},
		users:       map[int64]github.Object{},
	}
	for _, team := range f.teams {
		ev.teams[objectID(t, team)] = team
	}
	for _, user := range f.users {
		ev.users[objectID(t, user)] = user
	}
	if available, _ := f.ruleSuites["available"].(bool); available {
		ev.ruleSuites = []github.Object{}
		for _, s := range asSlice(f.ruleSuites["suites"]) {
			ev.ruleSuites = append(ev.ruleSuites, asObject(s))
		}
	} else {
		ev.ruleSuitesStatus = http.StatusNotFound
	}
	return ev
}
