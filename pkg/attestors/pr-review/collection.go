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
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/thomsonreuters/stamp/pkg/clients/github"
	"golang.org/x/sync/errgroup"
)

// evidence holds the raw GitHub responses the predicate is derived from.
type evidence struct {
	collectedAt time.Time
	repository  github.Object
	pullRequest github.Object
	reviews     []github.Object
	timeline    []github.Object
	commit      github.Object
	// rulesets holds the full rulesets that apply to the base branch, sorted by ID.
	rulesets []github.Object
	teams    map[int64]github.Object
	users    map[int64]github.Object
	// ruleSuites holds the suites for the landed commit; nil when ruleSuitesStatus is set.
	ruleSuites       []github.Object
	ruleSuitesStatus int
}

// pullRequestRule is one pull_request rule within an applicable ruleset.
type pullRequestRule struct {
	ruleset    github.Object
	src        string
	parameters github.Object
}

// collect calls the GitHub REST API in dependency order, running independent calls in parallel.
func (a *Attestor) collect(ctx context.Context) (*evidence, error) {
	ev := &evidence{collectedAt: a.now().UTC()}
	owner, repo, number := a.config.Owner, a.config.Repo, a.config.PullRequest

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		var err error
		ev.repository, err = a.client.GetRepository(gctx, owner, repo)
		return wrapCall(err, "get repository")
	})
	g.Go(func() error {
		var err error
		ev.pullRequest, err = a.client.GetPullRequest(gctx, owner, repo, number)
		return wrapCall(err, "get pull request")
	})
	g.Go(func() error {
		var err error
		ev.reviews, err = a.client.ListPullRequestReviews(gctx, owner, repo, number)
		return wrapCall(err, "list reviews")
	})
	g.Go(func() error {
		var err error
		ev.timeline, err = a.client.ListIssueTimeline(gctx, owner, repo, number)
		return wrapCall(err, "list timeline")
	})
	if err := g.Wait(); err != nil {
		return nil, err
	}

	r := &fieldReader{}
	merged := r.boolean(ev.pullRequest, "pull_request", "merged")
	if r.err != nil {
		return nil, r.err
	}
	if !merged {
		return nil, fmt.Errorf("%w: %s#%d", ErrNotMerged, a.config.Repository, number)
	}
	landedSHA := r.str(ev.pullRequest, "pull_request", "merge_commit_sha")
	baseRef := r.str(r.object(ev.pullRequest, "pull_request", "base"), "pull_request.base", "ref")
	defaultBranch := r.str(ev.repository, "repository", "default_branch")
	orgID := r.integer(r.object(ev.repository, "repository", "owner"), "repository.owner", "id")
	if r.err != nil {
		return nil, r.err
	}

	g, gctx = errgroup.WithContext(ctx)
	g.Go(func() error {
		var err error
		ev.commit, err = a.client.GetCommit(gctx, owner, repo, landedSHA)
		return wrapCall(err, "get landed commit")
	})
	g.Go(func() error {
		var err error
		ev.rulesets, err = a.applicableRulesets(gctx, baseRef, defaultBranch)
		return err
	})
	g.Go(func() error {
		return a.collectRuleSuites(gctx, ev, baseRef, landedSHA)
	})
	if err := g.Wait(); err != nil {
		return nil, err
	}

	if err := a.resolveReviewers(ctx, ev, orgID); err != nil {
		return nil, err
	}
	return ev, nil
}

// applicableRulesets fetches every ruleset by ID and keeps active branch rulesets that target baseRef.
func (a *Attestor) applicableRulesets(ctx context.Context, baseRef, defaultBranch string) ([]github.Object, error) {
	summaries, err := a.client.ListRulesets(ctx, a.config.Owner, a.config.Repo)
	if err != nil {
		return nil, wrapCall(err, "list rulesets")
	}

	r := &fieldReader{}
	ids := make([]int64, 0, len(summaries))
	for i, summary := range summaries {
		ids = append(ids, r.integer(summary, fmt.Sprintf("rulesets[%d]", i), "id"))
	}
	if r.err != nil {
		return nil, r.err
	}

	full := make([]github.Object, len(ids))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)
	for i, rulesetID := range ids {
		g.Go(func() error {
			var err error
			full[i], err = a.client.GetRuleset(gctx, a.config.Owner, a.config.Repo, rulesetID)
			return wrapCall(err, fmt.Sprintf("get ruleset %d", rulesetID))
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	applicable := make([]github.Object, 0, len(full))
	for i, ruleset := range full {
		if rulesetApplies(r, ruleset, fmt.Sprintf("ruleset[%d]", ids[i]), baseRef, defaultBranch) {
			applicable = append(applicable, ruleset)
		}
	}
	if r.err != nil {
		return nil, r.err
	}

	slices.SortStableFunc(applicable, func(x, y github.Object) int {
		xi, _ := toInt64(x["id"])
		yi, _ := toInt64(y["id"])
		return cmp.Compare(xi, yi)
	})
	return applicable, nil
}

func rulesetApplies(r *fieldReader, ruleset github.Object, src, baseRef, defaultBranch string) bool {
	target := r.str(ruleset, src, "target")
	enforcement := r.str(ruleset, src, "enforcement")
	if r.err != nil || target != rulesetTargetBranch || enforcement != rulesetEnforcementActive {
		return false
	}

	conditions := r.optObject(ruleset, src, "conditions")
	refName := r.optObject(conditions, src+".conditions", "ref_name")
	refSrc := src + ".conditions.ref_name"
	include := r.stringList(r.optArray(refName, refSrc, "include"), refSrc+".include")
	exclude := r.stringList(r.optArray(refName, refSrc, "exclude"), refSrc+".exclude")
	if r.err != nil {
		return false
	}

	matches := func(pattern string) bool { return refPatternMatches(pattern, baseRef, defaultBranch) }
	return slices.ContainsFunc(include, matches) && !slices.ContainsFunc(exclude, matches)
}

// refPatternMatches implements exact ref matching only; glob patterns such as refs/heads/release/* never match.
func refPatternMatches(pattern, baseRef, defaultBranch string) bool {
	return pattern == refPatternAll ||
		(pattern == refPatternDefaultBranch && baseRef == defaultBranch) ||
		pattern == refsHeadsPrefix+baseRef ||
		pattern == baseRef
}

// collectRuleSuites records the rule suites for the landed commit. A 404 marks the evaluation unavailable.
func (a *Attestor) collectRuleSuites(ctx context.Context, ev *evidence, baseRef, landedSHA string) error {
	suites, err := a.client.ListRuleSuites(ctx, a.config.Owner, a.config.Repo, refsHeadsPrefix+baseRef)
	if errors.Is(err, github.ErrNotFound) {
		a.logger.WarnContext(ctx, "rule suites are not readable with this token; recording evaluation as unavailable",
			"repository", a.config.Repository)
		ev.ruleSuitesStatus = http.StatusNotFound
		return nil
	}
	if err != nil {
		return wrapCall(err, "list rule suites")
	}

	ev.ruleSuites = []github.Object{}
	for _, suite := range suites {
		if afterSHA, _ := suite["after_sha"].(string); afterSHA == landedSHA {
			ev.ruleSuites = append(ev.ruleSuites, suite)
		}
	}
	return nil
}

// pullRequestRules returns every pull_request rule of the applicable rulesets in ruleset order.
func pullRequestRules(r *fieldReader, rulesets []github.Object) []pullRequestRule {
	var rules []pullRequestRule
	for i, ruleset := range rulesets {
		src := fmt.Sprintf("rulesets[%d]", i)
		if rulesetID, ok := toInt64(ruleset["id"]); ok {
			src = fmt.Sprintf("ruleset[%d]", rulesetID)
		}
		for j, rule := range r.objects(r.optArray(ruleset, src, "rules"), src+".rules") {
			ruleSrc := fmt.Sprintf("%s.rules[%d]", src, j)
			ruleType, _ := rule["type"].(string)
			if ruleType != ruleTypePullRequest {
				continue
			}
			rules = append(rules, pullRequestRule{
				ruleset:    ruleset,
				src:        src,
				parameters: r.optObject(rule, ruleSrc, "parameters"),
			})
		}
	}
	return rules
}

// resolveReviewers looks up every Team and User named by a required_reviewers entry, by numeric ID.
func (a *Attestor) resolveReviewers(ctx context.Context, ev *evidence, orgID int64) error {
	r := &fieldReader{}
	var teamIDs, userIDs []int64
	for _, rule := range pullRequestRules(r, ev.rulesets) {
		paramSrc := rule.src + ".parameters"
		for i, required := range r.objects(r.optArray(rule.parameters, paramSrc, "required_reviewers"), paramSrc+".required_reviewers") {
			src := fmt.Sprintf("%s.required_reviewers[%d].reviewer", paramSrc, i)
			reviewer := r.object(required, src, "reviewer")
			reviewerID := r.integer(reviewer, src, "id")
			switch reviewerType, _ := reviewer["type"].(string); reviewerType {
			case reviewerTypeTeam:
				teamIDs = append(teamIDs, reviewerID)
			case reviewerTypeUser:
				userIDs = append(userIDs, reviewerID)
			}
		}
	}
	if r.err != nil {
		return r.err
	}
	slices.Sort(teamIDs)
	slices.Sort(userIDs)
	teamIDs, userIDs = slices.Compact(teamIDs), slices.Compact(userIDs)

	ev.teams = make(map[int64]github.Object, len(teamIDs))
	ev.users = make(map[int64]github.Object, len(userIDs))
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)
	for _, teamID := range teamIDs {
		g.Go(func() error {
			team, err := a.client.GetTeamByID(gctx, orgID, teamID)
			if err != nil {
				return wrapCall(err, fmt.Sprintf("get team %d", teamID))
			}
			mu.Lock()
			defer mu.Unlock()
			ev.teams[teamID] = team
			return nil
		})
	}
	for _, userID := range userIDs {
		g.Go(func() error {
			user, err := a.client.GetUserByID(gctx, userID)
			if err != nil {
				return wrapCall(err, fmt.Sprintf("get user %d", userID))
			}
			mu.Lock()
			defer mu.Unlock()
			ev.users[userID] = user
			return nil
		})
	}
	return g.Wait()
}

func wrapCall(err error, call string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", call, err)
}
