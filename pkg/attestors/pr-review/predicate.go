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
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/thomsonreuters/stamp/pkg/clients/github"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	prpredicate "github.com/thomsonreuters/stamp/pkg/predicates/pr-review/v1"
)

// buildPredicate derives the predicate and subjects from collected evidence, field by field.
func buildPredicate(ev *evidence) (prpredicate.Predicate, []intoto.Subject, error) {
	r := &fieldReader{}
	repo, pr, commit := ev.repository, ev.pullRequest, ev.commit

	head := r.object(pr, "pull_request", "head")
	base := r.object(pr, "pull_request", "base")
	landedSHA := r.str(pr, "pull_request", "merge_commit_sha")
	headSHA := r.str(head, "pull_request.head", "sha")
	number := r.integer(pr, "pull_request", "number")

	commitData := r.object(commit, "commit", "commit")
	verification := r.object(commitData, "commit.commit", "verification")
	parentObjs := r.objects(r.array(commit, "commit", "parents"), "commit.parents")
	parents := make([]string, 0, len(parentObjs))
	for i, parent := range parentObjs {
		parents = append(parents, r.str(parent, fmt.Sprintf("commit.parents[%d]", i), "sha"))
	}

	predicate := prpredicate.Predicate{
		Repository: prpredicate.Repository{
			ID:            r.integer(repo, "repository", "id"),
			NodeID:        r.str(repo, "repository", "node_id"),
			FullName:      r.str(repo, "repository", "full_name"),
			DefaultBranch: r.str(repo, "repository", "default_branch"),
		},
		PullRequest: prpredicate.PullRequest{
			ID:               r.integer(pr, "pull_request", "id"),
			NodeID:           r.str(pr, "pull_request", "node_id"),
			Number:           number,
			URL:              r.str(pr, "pull_request", "html_url"),
			Requestor:        r.actor(r.object(pr, "pull_request", "user"), "pull_request.user"),
			BaseRef:          r.str(base, "pull_request.base", "ref"),
			ReviewedRevision: prpredicate.Revision{GitCommit: headSHA},
		},
		Landing: prpredicate.Landing{
			Revision:       prpredicate.Revision{GitCommit: landedSHA},
			Parents:        parents,
			MergedAt:       r.str(pr, "pull_request", "merged_at"),
			MergedBy:       r.actor(r.object(pr, "pull_request", "merged_by"), "pull_request.merged_by"),
			MergeQueueUsed: mergeQueueUsed(ev.timeline),
			CommitSignature: prpredicate.CommitSignature{
				Verified:   r.boolean(verification, "commit.commit.verification", "verified"),
				Reason:     r.str(verification, "commit.commit.verification", "reason"),
				VerifiedAt: r.optStr(verification, "commit.commit.verification", "verified_at"),
			},
		},
		ReviewPolicy: prpredicate.ReviewPolicy{
			Source:       prpredicate.ReviewPolicySourceGitHubRuleset,
			Requirements: r.requirements(ev),
			Evaluation:   evaluation(ev),
		},
		Reviews: r.reviews(ev.reviews),
		Collection: prpredicate.Collection{
			Mode:        prpredicate.CollectionModePostHocGitHubAPI,
			CollectedAt: ev.collectedAt.UTC().Format(time.RFC3339),
		},
	}
	predicate.Landing.Method = r.landingMethod(len(parents), landedSHA, headSHA, number, commitData)

	subjects := []intoto.Subject{{
		Name:   r.str(repo, "repository", "html_url"),
		Digest: map[string]string{"gitCommit": landedSHA},
	}}

	if r.err != nil {
		return prpredicate.Predicate{}, nil, r.err
	}
	return predicate, subjects, nil
}

func (r *fieldReader) actor(obj github.Object, src string) prpredicate.Actor {
	return prpredicate.Actor{
		ID:     r.integer(obj, src, "id"),
		NodeID: r.str(obj, src, "node_id"),
		Login:  r.str(obj, src, "login"),
		Type:   r.str(obj, src, "type"),
	}
}

// landingMethod classifies the merge only when GitHub's response makes it unambiguous; otherwise it returns "".
func (r *fieldReader) landingMethod(parentCount int, landedSHA, headSHA string, number int64, commitData github.Object) string {
	if r.err != nil {
		return ""
	}
	if parentCount >= 2 {
		return prpredicate.LandingMethodMerge
	}
	if landedSHA == headSHA {
		return prpredicate.LandingMethodFastForward
	}
	message := r.str(commitData, "commit.commit", "message")
	title, _, _ := strings.Cut(message, "\n")
	if parentCount == 1 && strings.Contains(strings.TrimSuffix(title, "\r"), fmt.Sprintf("(#%d)", number)) {
		return prpredicate.LandingMethodSquash
	}
	return ""
}

func mergeQueueUsed(timeline []github.Object) bool {
	return slices.ContainsFunc(timeline, func(item github.Object) bool {
		event, _ := item["event"].(string)
		return event == timelineMergeQueueEvent
	})
}

func (r *fieldReader) requirements(ev *evidence) []prpredicate.Requirement {
	requirements := []prpredicate.Requirement{}
	for _, rule := range pullRequestRules(r, ev.rulesets) {
		paramSrc := rule.src + ".parameters"
		requirement := prpredicate.Requirement{
			RulesetID:                    r.integer(rule.ruleset, rule.src, "id"),
			RulesetName:                  r.str(rule.ruleset, rule.src, "name"),
			RequiredApprovingReviewCount: r.integer(rule.parameters, paramSrc, "required_approving_review_count"),
			RequireCodeOwnerReview:       r.coerceBool(rule.parameters, paramSrc, "require_code_owner_review"),
			RequireLastPushApproval:      r.coerceBool(rule.parameters, paramSrc, "require_last_push_approval"),
			Reviewers:                    []prpredicate.Reviewer{},
		}
		reviewersSrc := paramSrc + ".required_reviewers"
		for i, required := range r.objects(r.optArray(rule.parameters, paramSrc, "required_reviewers"), reviewersSrc) {
			requirement.Reviewers = append(requirement.Reviewers,
				r.reviewer(required, fmt.Sprintf("%s[%d]", reviewersSrc, i), ev.teams, ev.users))
		}
		requirements = append(requirements, requirement)
	}
	return requirements
}

func (r *fieldReader) reviewer(required github.Object, src string, teams, users map[int64]github.Object) prpredicate.Reviewer {
	ref := r.object(required, src, "reviewer")
	refSrc := src + ".reviewer"
	reviewerID := r.integer(ref, refSrc, "id")
	reviewerType := r.str(ref, refSrc, "type")
	out := prpredicate.Reviewer{MinimumApprovals: r.optInteger(required, src, "minimum_approvals")}
	if r.err != nil {
		return out
	}

	switch reviewerType {
	case reviewerTypeTeam:
		team, ok := teams[reviewerID]
		if !ok {
			r.err = fmt.Errorf("%w: team %d (%s)", ErrUnresolvedReviewer, reviewerID, refSrc)
			return out
		}
		teamSrc := fmt.Sprintf("team[%d]", reviewerID)
		out.Team = &prpredicate.Team{
			ID:   r.integer(team, teamSrc, "id"),
			Slug: r.str(team, teamSrc, "slug"),
			Name: r.str(team, teamSrc, "name"),
		}
	case reviewerTypeUser:
		user, ok := users[reviewerID]
		if !ok {
			r.err = fmt.Errorf("%w: user %d (%s)", ErrUnresolvedReviewer, reviewerID, refSrc)
			return out
		}
		actor := r.actor(user, fmt.Sprintf("user[%d]", reviewerID))
		out.User = &actor
	default:
		r.err = fmt.Errorf("%w: unsupported reviewer type %q for id %d (%s)", ErrUnresolvedReviewer, reviewerType, reviewerID, refSrc)
	}
	return out
}

func evaluation(ev *evidence) prpredicate.Evaluation {
	if ev.ruleSuitesStatus != 0 {
		status := ev.ruleSuitesStatus
		return prpredicate.Evaluation{Available: false, HTTPStatus: &status, Suites: []map[string]any{}}
	}
	suites := ev.ruleSuites
	if suites == nil {
		suites = []github.Object{}
	}
	return prpredicate.Evaluation{Available: true, Suites: suites}
}

// reviews maps every review and orders them by (submitted_at, id), with missing submitted_at first.
func (r *fieldReader) reviews(raw []github.Object) []prpredicate.Review {
	reviews := make([]prpredicate.Review, 0, len(raw))
	for i, review := range raw {
		src := fmt.Sprintf("reviews[%d]", i)
		reviews = append(reviews, prpredicate.Review{
			ID:               r.integer(review, src, "id"),
			NodeID:           r.str(review, src, "node_id"),
			URL:              r.str(review, src, "html_url"),
			Reviewer:         r.actor(r.object(review, src, "user"), src+".user"),
			State:            r.str(review, src, "state"),
			SubmittedAt:      r.optStr(review, src, "submitted_at"),
			ReviewedRevision: prpredicate.Revision{GitCommit: r.str(review, src, "commit_id")},
		})
	}
	slices.SortStableFunc(reviews, func(x, y prpredicate.Review) int {
		return cmp.Or(cmp.Compare(x.SubmittedAt, y.SubmittedAt), cmp.Compare(x.ID, y.ID))
	})
	return reviews
}
