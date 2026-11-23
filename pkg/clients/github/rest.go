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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	httpclient "github.com/thomsonreuters/stamp/pkg/http/client"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

const (
	// DefaultAPIURL is the public GitHub REST API base URL.
	DefaultAPIURL = "https://api.github.com"

	// InstallationTokenPrefix is the prefix GitHub assigns to GitHub App installation access tokens.
	InstallationTokenPrefix = "ghs_"

	apiVersion  = "2022-11-28"
	acceptJSON  = "application/vnd.github+json"
	perPage     = "100"
	maxPages    = 100
	maxErrorMsg = 512
)

var linkNextPattern = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// Object is a decoded GitHub REST JSON object. Numbers are decoded as json.Number.
type Object = map[string]any

// RESTClientIface is a read-only GitHub REST API client.
type RESTClientIface interface {
	GetRepository(ctx context.Context, owner, repo string) (Object, error)
	GetPullRequest(ctx context.Context, owner, repo string, number int) (Object, error)
	ListPullRequestReviews(ctx context.Context, owner, repo string, number int) ([]Object, error)
	ListIssueTimeline(ctx context.Context, owner, repo string, number int) ([]Object, error)
	GetCommit(ctx context.Context, owner, repo, sha string) (Object, error)
	ListRulesets(ctx context.Context, owner, repo string) ([]Object, error)
	GetRuleset(ctx context.Context, owner, repo string, rulesetID int64) (Object, error)
	GetTeamByID(ctx context.Context, orgID, teamID int64) (Object, error)
	GetUserByID(ctx context.Context, userID int64) (Object, error)
	// ListRuleSuites returns the first page of rule suites for ref. A 404 is returned as an error matching ErrNotFound.
	ListRuleSuites(ctx context.Context, owner, repo, ref string) ([]Object, error)
}

// RESTOptions configures the GitHub REST client.
type RESTOptions struct {
	// BaseURL is the REST API base URL. Defaults to DefaultAPIURL.
	BaseURL string
	// Token must be a GitHub App installation access token.
	Token  string
	Logger logger.Logger
}

// RESTClient is a read-only GitHub REST API client authenticated with a GitHub App installation token.
type RESTClient struct {
	httpClient *httpclient.Client
	baseURL    *url.URL
}

func newRESTClient(_ context.Context, opts RESTOptions) (RESTClientIface, error) {
	if opts.Token == "" {
		return nil, ErrMissingInstallationToken
	}
	if !strings.HasPrefix(opts.Token, InstallationTokenPrefix) {
		return nil, ErrNotInstallationToken
	}
	if opts.BaseURL == "" {
		opts.BaseURL = DefaultAPIURL
	}
	if opts.Logger == nil {
		opts.Logger = logger.NewNoop()
	}

	base, err := url.Parse(strings.TrimRight(opts.BaseURL, "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("invalid GitHub API URL %q", opts.BaseURL)
	}

	httpClient := httpclient.New(opts.Logger).
		SetTimeout(DefaultTimeout).
		SetBaseURL(base.String()).
		SetAuthToken(opts.Token).
		SetHeader("Accept", acceptJSON).
		SetHeader("X-GitHub-Api-Version", apiVersion)

	return &RESTClient{httpClient: httpClient, baseURL: base}, nil
}

// NewREST creates a GitHub REST client. This variable can be replaced in tests for mocking.
var NewREST = newRESTClient

func repoPath(owner, repo string) string {
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)
}

// GetRepository returns GET /repos/{owner}/{repo}.
func (c *RESTClient) GetRepository(ctx context.Context, owner, repo string) (Object, error) {
	return c.getObject(ctx, repoPath(owner, repo))
}

// GetPullRequest returns GET /repos/{owner}/{repo}/pulls/{number}.
func (c *RESTClient) GetPullRequest(ctx context.Context, owner, repo string, number int) (Object, error) {
	return c.getObject(ctx, repoPath(owner, repo)+"/pulls/"+strconv.Itoa(number))
}

// ListPullRequestReviews returns all pages of GET /repos/{owner}/{repo}/pulls/{number}/reviews.
func (c *RESTClient) ListPullRequestReviews(ctx context.Context, owner, repo string, number int) ([]Object, error) {
	return c.getAll(ctx, repoPath(owner, repo)+"/pulls/"+strconv.Itoa(number)+"/reviews")
}

// ListIssueTimeline returns all pages of GET /repos/{owner}/{repo}/issues/{number}/timeline.
func (c *RESTClient) ListIssueTimeline(ctx context.Context, owner, repo string, number int) ([]Object, error) {
	return c.getAll(ctx, repoPath(owner, repo)+"/issues/"+strconv.Itoa(number)+"/timeline")
}

// GetCommit returns GET /repos/{owner}/{repo}/commits/{sha}.
func (c *RESTClient) GetCommit(ctx context.Context, owner, repo, sha string) (Object, error) {
	return c.getObject(ctx, repoPath(owner, repo)+"/commits/"+url.PathEscape(sha))
}

// ListRulesets returns all pages of GET /repos/{owner}/{repo}/rulesets (summaries only).
func (c *RESTClient) ListRulesets(ctx context.Context, owner, repo string) ([]Object, error) {
	return c.getAll(ctx, repoPath(owner, repo)+"/rulesets")
}

// GetRuleset returns GET /repos/{owner}/{repo}/rulesets/{id}.
func (c *RESTClient) GetRuleset(ctx context.Context, owner, repo string, rulesetID int64) (Object, error) {
	return c.getObject(ctx, repoPath(owner, repo)+"/rulesets/"+strconv.FormatInt(rulesetID, 10))
}

// GetTeamByID returns GET /organizations/{org_id}/team/{team_id}.
func (c *RESTClient) GetTeamByID(ctx context.Context, orgID, teamID int64) (Object, error) {
	return c.getObject(ctx, "/organizations/"+strconv.FormatInt(orgID, 10)+"/team/"+strconv.FormatInt(teamID, 10))
}

// GetUserByID returns GET /user/{user_id}.
func (c *RESTClient) GetUserByID(ctx context.Context, userID int64) (Object, error) {
	return c.getObject(ctx, "/user/"+strconv.FormatInt(userID, 10))
}

// ListRuleSuites returns GET /repos/{owner}/{repo}/rulesets/rule-suites?ref={ref}&per_page=100.
func (c *RESTClient) ListRuleSuites(ctx context.Context, owner, repo, ref string) ([]Object, error) {
	var items []Object
	if _, err := c.get(ctx, repoPath(owner, repo)+"/rulesets/rule-suites", map[string]string{"ref": ref, "per_page": perPage}, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func (c *RESTClient) getObject(ctx context.Context, path string) (Object, error) {
	var obj Object
	if _, err := c.get(ctx, path, nil, &obj); err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, fmt.Errorf("GitHub API GET %s returned an empty body", path)
	}
	return obj, nil
}

// getAll follows Link rel="next" headers and concatenates every page.
func (c *RESTClient) getAll(ctx context.Context, path string) ([]Object, error) {
	var all []Object
	next := path
	query := map[string]string{"per_page": perPage}

	for page := 0; next != ""; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("GitHub API GET %s exceeded %d pages", path, maxPages)
		}

		var items []Object
		header, err := c.get(ctx, next, query, &items)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)

		next, err = c.nextPage(header)
		if err != nil {
			return nil, err
		}
		// The next link already carries the query string.
		query = nil
	}

	if all == nil {
		all = []Object{}
	}
	return all, nil
}

// nextPage returns the rel="next" URL, refusing links that leave the configured API origin
// so the installation token is never sent to another host.
func (c *RESTClient) nextPage(header http.Header) (string, error) {
	match := linkNextPattern.FindStringSubmatch(header.Get("Link"))
	if match == nil {
		return "", nil
	}
	next, err := url.Parse(match[1])
	if err != nil {
		return "", fmt.Errorf("invalid pagination link %q: %w", match[1], err)
	}
	if next.Scheme != c.baseURL.Scheme || next.Host != c.baseURL.Host {
		return "", fmt.Errorf("pagination link %q does not match GitHub API origin %s://%s", match[1], c.baseURL.Scheme, c.baseURL.Host)
	}
	return next.String(), nil
}

func (c *RESTClient) get(ctx context.Context, path string, query map[string]string, out any) (http.Header, error) {
	resp, err := c.httpClient.R().SetContext(ctx).SetQueryParams(query).Get(path)
	if err != nil {
		return nil, fmt.Errorf("GitHub API GET %s: %w", path, err)
	}
	defer func() { _ = resp.Close() }()

	body, err := resp.Bytes()
	if err != nil {
		return nil, fmt.Errorf("GitHub API GET %s: %w", path, err)
	}

	if !resp.IsSuccess() {
		return nil, &APIError{Method: http.MethodGet, Path: path, StatusCode: resp.StatusCode(), Message: errorMessage(body)}
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(out); err != nil {
		return nil, fmt.Errorf("GitHub API GET %s: invalid JSON response: %w", path, err)
	}
	return resp.Header(), nil
}

func errorMessage(body []byte) string {
	var payload struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return ""
	}
	if len(payload.Message) > maxErrorMsg {
		return payload.Message[:maxErrorMsg]
	}
	return payload.Message
}
