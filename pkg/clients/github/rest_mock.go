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

package github

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
)

// MockRESTClient is a mock implementation of RESTClientIface.
type MockRESTClient struct {
	mock.Mock
}

func (m *MockRESTClient) object(args mock.Arguments) (Object, error) {
	obj, _ := args.Get(0).(Object)
	return obj, args.Error(1)
}

func (m *MockRESTClient) objects(args mock.Arguments) ([]Object, error) {
	objs, _ := args.Get(0).([]Object)
	return objs, args.Error(1)
}

// GetRepository mocks GET /repos/{owner}/{repo}.
func (m *MockRESTClient) GetRepository(ctx context.Context, owner, repo string) (Object, error) {
	return m.object(m.Called(ctx, owner, repo))
}

// GetPullRequest mocks GET /repos/{owner}/{repo}/pulls/{number}.
func (m *MockRESTClient) GetPullRequest(ctx context.Context, owner, repo string, number int) (Object, error) {
	return m.object(m.Called(ctx, owner, repo, number))
}

// ListPullRequestReviews mocks GET /repos/{owner}/{repo}/pulls/{number}/reviews.
func (m *MockRESTClient) ListPullRequestReviews(ctx context.Context, owner, repo string, number int) ([]Object, error) {
	return m.objects(m.Called(ctx, owner, repo, number))
}

// ListIssueTimeline mocks GET /repos/{owner}/{repo}/issues/{number}/timeline.
func (m *MockRESTClient) ListIssueTimeline(ctx context.Context, owner, repo string, number int) ([]Object, error) {
	return m.objects(m.Called(ctx, owner, repo, number))
}

// GetCommit mocks GET /repos/{owner}/{repo}/commits/{sha}.
func (m *MockRESTClient) GetCommit(ctx context.Context, owner, repo, sha string) (Object, error) {
	return m.object(m.Called(ctx, owner, repo, sha))
}

// ListRulesets mocks GET /repos/{owner}/{repo}/rulesets.
func (m *MockRESTClient) ListRulesets(ctx context.Context, owner, repo string) ([]Object, error) {
	return m.objects(m.Called(ctx, owner, repo))
}

// GetRuleset mocks GET /repos/{owner}/{repo}/rulesets/{id}.
func (m *MockRESTClient) GetRuleset(ctx context.Context, owner, repo string, rulesetID int64) (Object, error) {
	return m.object(m.Called(ctx, owner, repo, rulesetID))
}

// GetTeamByID mocks GET /organizations/{org_id}/team/{team_id}.
func (m *MockRESTClient) GetTeamByID(ctx context.Context, orgID, teamID int64) (Object, error) {
	return m.object(m.Called(ctx, orgID, teamID))
}

// GetUserByID mocks GET /user/{user_id}.
func (m *MockRESTClient) GetUserByID(ctx context.Context, userID int64) (Object, error) {
	return m.object(m.Called(ctx, userID))
}

// ListRuleSuites mocks GET /repos/{owner}/{repo}/rulesets/rule-suites.
func (m *MockRESTClient) ListRuleSuites(ctx context.Context, owner, repo, ref string) ([]Object, error) {
	return m.objects(m.Called(ctx, owner, repo, ref))
}

// SetupMockRESTClient replaces the global NewREST function with a mock for testing.
func SetupMockRESTClient(t *testing.T) *MockRESTClient {
	t.Helper()

	mockClient := &MockRESTClient{}

	original := NewREST
	NewREST = func(_ context.Context, _ RESTOptions) (RESTClientIface, error) {
		return mockClient, nil
	}

	t.Cleanup(func() {
		NewREST = original
	})

	return mockClient
}
