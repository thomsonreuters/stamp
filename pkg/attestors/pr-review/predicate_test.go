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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/clients/github"
	prpredicate "github.com/thomsonreuters/stamp/pkg/predicates/pr-review/v1"
)

func TestLandingMethod(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(f *fixture)
		want   string
	}{
		{name: "squash", mutate: func(*fixture) {}, want: prpredicate.LandingMethodSquash},
		{
			name: "merge commit",
			mutate: func(f *fixture) {
				f.commit["parents"] = append(asSlice(f.commit["parents"]), map[string]any{"sha": "abc"})
			},
			want: prpredicate.LandingMethodMerge,
		},
		{
			name: "fast-forward",
			mutate: func(f *fixture) {
				sub(f.pullRequest, "head")["sha"] = f.pullRequest["merge_commit_sha"]
			},
			want: prpredicate.LandingMethodFastForward,
		},
		{
			name: "pr number only in body",
			mutate: func(f *fixture) {
				sub(f.commit, "commit")["message"] = "Rebased change\n\nSee (#101)"
			},
			want: "",
		},
		{
			name: "pr number in title with CRLF",
			mutate: func(f *fixture) {
				sub(f.commit, "commit")["message"] = "Change (#101)\r\n\r\nbody"
			},
			want: prpredicate.LandingMethodSquash,
		},
		{
			name: "different pr number",
			mutate: func(f *fixture) {
				sub(f.commit, "commit")["message"] = "Change (#10)"
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := loadFixture(t, sample1)
			tt.mutate(f)
			predicate, _, err := buildPredicate(f.evidence(t))
			require.NoError(t, err)
			assert.Equal(t, tt.want, predicate.Landing.Method)

			data, err := json.Marshal(predicate.Landing)
			require.NoError(t, err)
			if tt.want == "" {
				assert.NotContains(t, string(data), `"method"`)
			}
		})
	}
}

func TestMergeQueueUsed(t *testing.T) {
	f := loadFixture(t, sample1)
	predicate, _, err := buildPredicate(f.evidence(t))
	require.NoError(t, err)
	assert.True(t, predicate.Landing.MergeQueueUsed)

	f.timeline = []github.Object{{"event": "merged"}, {"event": "removed_from_merge_queue"}, {}}
	predicate, _, err = buildPredicate(f.evidence(t))
	require.NoError(t, err)
	assert.False(t, predicate.Landing.MergeQueueUsed)
}

func TestReviewSorting(t *testing.T) {
	f := loadFixture(t, sample1)
	review := func(reviewID int64, submittedAt any) github.Object {
		r := github.Object{
			"id": json64(reviewID), "node_id": "PRR", "html_url": "https://example/r", "state": "APPROVED", "commit_id": "abc",
			"user": map[string]any{"id": json64(1), "node_id": "U", "login": "u", "type": "User"},
		}
		if submittedAt != nil {
			r["submitted_at"] = submittedAt
		}
		return r
	}
	f.reviews = []github.Object{
		review(30, "2026-01-02T00:00:00Z"),
		review(20, "2026-01-01T00:00:00Z"),
		review(10, "2026-01-02T00:00:00Z"),
		review(40, nil),
	}

	predicate, _, err := buildPredicate(f.evidence(t))
	require.NoError(t, err)
	var ids []int64
	for _, r := range predicate.Reviews {
		ids = append(ids, r.ID)
	}
	assert.Equal(t, []int64{40, 20, 10, 30}, ids)
	assert.Empty(t, predicate.Reviews[0].SubmittedAt)
}

func TestMissingRequiredField(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(f *fixture)
		field  string
	}{
		{name: "repository id", mutate: func(f *fixture) { delete(f.repository, "id") }, field: "repository.id"},
		{name: "repository html_url", mutate: func(f *fixture) { delete(f.repository, "html_url") }, field: "repository.html_url"},
		{name: "merged_at", mutate: func(f *fixture) { f.pullRequest["merged_at"] = nil }, field: "pull_request.merged_at"},
		{name: "merged_by", mutate: func(f *fixture) { delete(f.pullRequest, "merged_by") }, field: "pull_request.merged_by"},
		{name: "requestor login", mutate: func(f *fixture) { delete(sub(f.pullRequest, "user"), "login") }, field: "pull_request.user.login"},
		{name: "head sha", mutate: func(f *fixture) { sub(f.pullRequest, "head")["sha"] = "" }, field: "pull_request.head.sha"},
		{
			name:   "verification reason",
			mutate: func(f *fixture) { delete(sub(sub(f.commit, "commit"), "verification"), "reason") },
			field:  "commit.commit.verification.reason",
		},
		{name: "review commit_id", mutate: func(f *fixture) { delete(f.reviews[1], "commit_id") }, field: "reviews[1].commit_id"},
		{
			name: "required_approving_review_count",
			mutate: func(f *fixture) {
				for _, rs := range f.rulesets {
					if rs["name"] == "audit-ruleset" {
						delete(prParams(rs), "required_approving_review_count")
					}
				}
			},
			field: "ruleset[20002].parameters.required_approving_review_count",
		},
		{name: "team slug", mutate: func(f *fixture) { delete(f.teams[0], "slug") }, field: "team[3001].slug"},
		{name: "parent sha", mutate: func(f *fixture) { f.commit["parents"] = []any{map[string]any{}} }, field: "commit.parents[0].sha"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := loadFixture(t, sample1)
			tt.mutate(f)
			a := &Attestor{evidence: f.evidence(t)}
			predicate, err := a.GeneratePredicate(nil)
			require.ErrorIs(t, err, ErrMissingField)
			assert.Contains(t, err.Error(), tt.field)
			assert.Nil(t, predicate)
			assert.Nil(t, a.Subjects(nil))
		})
	}
}

func TestInvalidFieldType(t *testing.T) {
	f := loadFixture(t, sample1)
	f.repository["id"] = "not-a-number"
	_, _, err := buildPredicate(f.evidence(t))
	require.ErrorIs(t, err, ErrInvalidField)
	assert.Contains(t, err.Error(), "repository.id")
}

func TestOptionalFieldsMayBeAbsent(t *testing.T) {
	f := loadFixture(t, sample1)
	delete(sub(sub(f.commit, "commit"), "verification"), "verified_at")
	f.reviews[0]["submitted_at"] = nil
	for _, rs := range f.rulesets {
		for _, rule := range asSlice(rs["rules"]) {
			params := asObject(asObject(rule)["parameters"])
			for _, rr := range asSlice(params["required_reviewers"]) {
				delete(asObject(rr), "minimum_approvals")
			}
		}
	}

	predicate, _, err := buildPredicate(f.evidence(t))
	require.NoError(t, err)
	assert.Empty(t, predicate.Landing.CommitSignature.VerifiedAt)
	assert.Empty(t, predicate.Reviews[0].SubmittedAt)
	assert.Nil(t, predicate.ReviewPolicy.Requirements[0].Reviewers[0].MinimumApprovals)

	data, err := json.Marshal(predicate)
	require.NoError(t, err)
	assert.NotContains(t, string(data), `"verifiedAt"`)
	assert.Contains(t, string(data), `"minimumApprovals":null`)
}

// prParams returns the parameters of the ruleset's pull_request rule.
func prParams(rs github.Object) map[string]any {
	for _, rule := range asSlice(rs["rules"]) {
		if r := asObject(rule); r["type"] == "pull_request" {
			return asObject(r["parameters"])
		}
	}
	return nil
}

func TestCoercedBooleans(t *testing.T) {
	f := loadFixture(t, sample1)
	for _, rs := range f.rulesets {
		for _, rule := range asSlice(rs["rules"]) {
			if params := asObject(asObject(rule)["parameters"]); params != nil {
				delete(params, "require_code_owner_review")
				params["require_last_push_approval"] = nil
			}
		}
	}
	predicate, _, err := buildPredicate(f.evidence(t))
	require.NoError(t, err)
	for _, req := range predicate.ReviewPolicy.Requirements {
		assert.False(t, req.RequireCodeOwnerReview)
		assert.False(t, req.RequireLastPushApproval)
	}
}

func TestReviewerResolution(t *testing.T) {
	setReviewer := func(f *fixture, reviewer map[string]any) {
		for _, rs := range f.rulesets {
			if rs["name"] == "main-branch-protection" {
				prParams(rs)["required_reviewers"] = []any{map[string]any{"minimum_approvals": json64(1), "reviewer": reviewer}}
			}
		}
	}

	t.Run("unresolved team", func(t *testing.T) {
		f := loadFixture(t, sample1)
		f.teams = nil
		_, _, err := buildPredicate(f.evidence(t))
		require.ErrorIs(t, err, ErrUnresolvedReviewer)
		assert.Contains(t, err.Error(), "team 3001")
	})

	t.Run("unresolved user", func(t *testing.T) {
		f := loadFixture(t, sample1)
		setReviewer(f, map[string]any{"id": json64(7), "type": "User"})
		_, _, err := buildPredicate(f.evidence(t))
		require.ErrorIs(t, err, ErrUnresolvedReviewer)
		assert.Contains(t, err.Error(), "user 7")
	})

	t.Run("unsupported type", func(t *testing.T) {
		f := loadFixture(t, sample1)
		setReviewer(f, map[string]any{"id": json64(7), "type": "Integration"})
		_, _, err := buildPredicate(f.evidence(t))
		require.ErrorIs(t, err, ErrUnresolvedReviewer)
		assert.Contains(t, err.Error(), `"Integration"`)
	})

	t.Run("resolved by numeric id", func(t *testing.T) {
		f := loadFixture(t, sample1)
		predicate, _, err := buildPredicate(f.evidence(t))
		require.NoError(t, err)
		team := predicate.ReviewPolicy.Requirements[0].Reviewers[0].Team
		assert.Equal(t, &prpredicate.Team{ID: sampleTeamID, Slug: "service-maintainers", Name: "Service Maintainers"}, team)
	})
}

func TestRefPatternMatches(t *testing.T) {
	tests := []struct {
		pattern, base string
		want          bool
	}{
		{pattern: "~ALL", base: "feature/x", want: true},
		{pattern: "~DEFAULT_BRANCH", base: "main", want: true},
		{pattern: "~DEFAULT_BRANCH", base: "dev", want: false},
		{pattern: "refs/heads/dev", base: "dev", want: true},
		{pattern: "dev", base: "dev", want: true},
		{pattern: "refs/heads/release/*", base: "release/1.0", want: false},
		{pattern: "refs/heads/main", base: "dev", want: false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, refPatternMatches(tt.pattern, tt.base, "main"), "%s vs %s", tt.pattern, tt.base)
	}
}

func TestRulesetApplies(t *testing.T) {
	ruleset := func(target, enforcement string, include, exclude []any) github.Object {
		rs := github.Object{"id": json64(1), "target": target, "enforcement": enforcement}
		if include != nil || exclude != nil {
			rs["conditions"] = map[string]any{"ref_name": map[string]any{"include": include, "exclude": exclude}}
		}
		return rs
	}
	tests := []struct {
		name    string
		ruleset github.Object
		want    bool
	}{
		{name: "active default branch", ruleset: ruleset("branch", "active", []any{"~DEFAULT_BRANCH"}, []any{}), want: true},
		{name: "excluded", ruleset: ruleset("branch", "active", []any{"~ALL"}, []any{"refs/heads/main"}), want: false},
		{name: "evaluate mode", ruleset: ruleset("branch", "evaluate", []any{"~ALL"}, nil), want: false},
		{name: "disabled", ruleset: ruleset("branch", "disabled", []any{"~ALL"}, nil), want: false},
		{name: "tag target", ruleset: ruleset("tag", "active", []any{"~ALL"}, nil), want: false},
		{name: "push target", ruleset: ruleset("push", "active", []any{"~ALL"}, nil), want: false},
		{name: "no conditions", ruleset: ruleset("branch", "active", nil, nil), want: false},
		{name: "no match", ruleset: ruleset("branch", "active", []any{"refs/heads/dev"}, nil), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &fieldReader{}
			assert.Equal(t, tt.want, rulesetApplies(r, tt.ruleset, "ruleset[1]", "main", "main"))
			require.NoError(t, r.err)
		})
	}

	t.Run("missing target fails", func(t *testing.T) {
		r := &fieldReader{}
		assert.False(t, rulesetApplies(r, github.Object{"enforcement": "active"}, "ruleset[1]", "main", "main"))
		require.ErrorIs(t, r.err, ErrMissingField)
		assert.Contains(t, r.err.Error(), "ruleset[1].target")
	})
}

func TestSubjects(t *testing.T) {
	f := loadFixture(t, sample2)
	a := &Attestor{evidence: f.evidence(t)}
	_, err := a.GeneratePredicate(nil)
	require.NoError(t, err)
	subjects := a.Subjects(nil)
	require.Len(t, subjects, 1)
	assert.Equal(t, "https://github.com/example-org/example-service", subjects[0].Name)
	landed, _ := f.pullRequest["merge_commit_sha"].(string)
	assert.Equal(t, map[string]string{"gitCommit": landed}, subjects[0].Digest)
}
