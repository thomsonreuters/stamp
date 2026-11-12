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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testInstallationToken = "ghs_testtoken"

// recordingServer serves canned responses and records every request.
type recordingServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*http.Request
}

func newRecordingServer(t *testing.T, handler http.HandlerFunc) *recordingServer {
	t.Helper()
	rs := &recordingServer{}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		rs.requests = append(rs.requests, r.Clone(context.Background()))
		rs.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(rs.Close)
	return rs
}

func newTestREST(t *testing.T, baseURL string) RESTClientIface {
	t.Helper()
	c, err := NewREST(context.Background(), RESTOptions{BaseURL: baseURL, Token: testInstallationToken})
	require.NoError(t, err)
	return c
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	assert.NoError(t, json.NewEncoder(w).Encode(v))
}

func TestNewRESTTokenValidation(t *testing.T) {
	_, err := NewREST(context.Background(), RESTOptions{})
	require.ErrorIs(t, err, ErrMissingInstallationToken)

	for _, token := range []string{"ghp_abc", "github_pat_abc", "gho_abc", "ghu_abc", "plain"} {
		_, err = NewREST(context.Background(), RESTOptions{Token: token})
		require.ErrorIs(t, err, ErrNotInstallationToken, token)
	}

	_, err = NewREST(context.Background(), RESTOptions{Token: testInstallationToken, BaseURL: "not a url"})
	require.Error(t, err)

	c, err := NewREST(context.Background(), RESTOptions{Token: testInstallationToken})
	require.NoError(t, err)
	rest, ok := c.(*RESTClient)
	require.True(t, ok)
	assert.Equal(t, DefaultAPIURL, rest.baseURL.String())
}

func TestRESTEndpoints(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"path": r.URL.Path, "id": 9007199254740993})
	})
	c := newTestREST(t, srv.URL+"/")
	ctx := context.Background()

	calls := []struct {
		path string
		call func() (Object, error)
	}{
		{"/repos/acme/widget", func() (Object, error) { return c.GetRepository(ctx, "acme", "widget") }},
		{"/repos/acme/widget/pulls/12", func() (Object, error) { return c.GetPullRequest(ctx, "acme", "widget", 12) }},
		{"/repos/acme/widget/commits/abc123", func() (Object, error) { return c.GetCommit(ctx, "acme", "widget", "abc123") }},
		{"/repos/acme/widget/rulesets/77", func() (Object, error) { return c.GetRuleset(ctx, "acme", "widget", 77) }},
		{"/organizations/5/team/6", func() (Object, error) { return c.GetTeamByID(ctx, 5, 6) }},
		{"/user/8", func() (Object, error) { return c.GetUserByID(ctx, 8) }},
	}
	for _, tc := range calls {
		obj, err := tc.call()
		require.NoError(t, err, tc.path)
		assert.Equal(t, tc.path, obj["path"])
		// Large IDs keep full precision.
		assert.Equal(t, json.Number("9007199254740993"), obj["id"])
	}

	require.Len(t, srv.requests, len(calls))
	for _, req := range srv.requests {
		assert.Equal(t, http.MethodGet, req.Method)
		assert.Equal(t, "Bearer "+testInstallationToken, req.Header.Get("Authorization"))
		assert.Equal(t, "application/vnd.github+json", req.Header.Get("Accept"))
		assert.Equal(t, "2022-11-28", req.Header.Get("X-Github-Api-Version"))
	}
}

func TestRESTPathEscaping(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{})
	})
	c := newTestREST(t, srv.URL)
	_, err := c.GetCommit(context.Background(), "acme", "widget", "../../user")
	require.NoError(t, err)
	assert.Equal(t, "/repos/acme/widget/commits/..%2F..%2Fuser", srv.requests[0].URL.EscapedPath())
}

func TestRESTPagination(t *testing.T) {
	var srv *recordingServer
	srv = newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		assert.Equal(t, "100", r.URL.Query().Get("per_page"))
		switch page {
		case "":
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?per_page=100&page=2>; rel="next", <%s%s?per_page=100&page=3>; rel="last"`,
				srv.URL, r.URL.Path, srv.URL, r.URL.Path))
			writeJSON(t, w, []map[string]any{{"id": 1}, {"id": 2}})
		case "2":
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?per_page=100&page=3>; rel="next"`, srv.URL, r.URL.Path))
			writeJSON(t, w, []map[string]any{{"id": 3}})
		default:
			writeJSON(t, w, []map[string]any{{"id": 4}})
		}
	})
	c := newTestREST(t, srv.URL)
	ctx := context.Background()

	lists := map[string]func() ([]Object, error){
		"/repos/acme/widget/pulls/3/reviews":   func() ([]Object, error) { return c.ListPullRequestReviews(ctx, "acme", "widget", 3) },
		"/repos/acme/widget/issues/3/timeline": func() ([]Object, error) { return c.ListIssueTimeline(ctx, "acme", "widget", 3) },
		"/repos/acme/widget/rulesets":          func() ([]Object, error) { return c.ListRulesets(ctx, "acme", "widget") },
	}
	for path, list := range lists {
		srv.requests = nil
		items, err := list()
		require.NoError(t, err, path)
		require.Len(t, items, 4, path)
		assert.Equal(t, json.Number("4"), items[3]["id"])
		require.Len(t, srv.requests, 3)
		for _, req := range srv.requests {
			assert.Equal(t, path, req.URL.Path)
		}
	}
}

func TestRESTPaginationEmpty(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, []any{})
	})
	items, err := newTestREST(t, srv.URL).ListRulesets(context.Background(), "acme", "widget")
	require.NoError(t, err)
	assert.NotNil(t, items)
	assert.Empty(t, items)
}

func TestRESTPaginationRejectsForeignOrigin(t *testing.T) {
	foreign := newRecordingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, []any{})
	})
	srv := newRecordingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", fmt.Sprintf(`<%s/steal?page=2>; rel="next"`, foreign.URL))
		writeJSON(t, w, []map[string]any{{"id": 1}})
	})

	_, err := newTestREST(t, srv.URL).ListRulesets(context.Background(), "acme", "widget")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match GitHub API origin")
	assert.Empty(t, foreign.requests, "token must not be sent to a foreign origin")
}

func TestRESTErrors(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user/404":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		case "/user/500":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`oops`))
		default:
			_, _ = w.Write([]byte(`{not json`))
		}
	})
	c := newTestREST(t, srv.URL)
	ctx := context.Background()

	_, err := c.GetUserByID(ctx, 404)
	require.ErrorIs(t, err, ErrNotFound)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusNotFound, apiErr.StatusCode)
	assert.Contains(t, err.Error(), "Not Found")

	_, err = c.GetUserByID(ctx, 500)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNotFound)
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusInternalServerError, apiErr.StatusCode)

	_, err = c.GetUserByID(ctx, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON")
}

func TestRESTListRuleSuites(t *testing.T) {
	srv := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("ref") == "refs/heads/missing" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(t, w, []map[string]any{{"id": 1, "after_sha": "abc"}})
	})
	c := newTestREST(t, srv.URL)

	suites, err := c.ListRuleSuites(context.Background(), "acme", "widget", "refs/heads/main")
	require.NoError(t, err)
	require.Len(t, suites, 1)
	req := srv.requests[0]
	assert.Equal(t, "/repos/acme/widget/rulesets/rule-suites", req.URL.Path)
	assert.Equal(t, "refs/heads/main", req.URL.Query().Get("ref"))
	assert.Equal(t, "100", req.URL.Query().Get("per_page"))

	_, err = c.ListRuleSuites(context.Background(), "acme", "widget", "refs/heads/missing")
	require.ErrorIs(t, err, ErrNotFound)
}
