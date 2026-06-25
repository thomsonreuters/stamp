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

// Package http provides a simplified HTTP client.
//
// Basic Usage:
//
//	client := http.New()
//	resp, err := client.R().
//		SetHeader("Accept", "application/json").
//		SetAuthToken("your-token").
//		Get("https://api.example.com/users")
//
// Client Configuration:
//
//	client := http.New().
//		SetTimeout(60 * time.Second).
//		SetBaseURL("https://api.example.com").
//		SetHeader("User-Agent", "example-app/1.0")
package http

import (
	"context"
	"crypto/tls"
	"maps"
	"net"
	"net/http"
	"net/url"
	"time"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

const (
	// DefaultTimeout is the maximum time allowed for the entire request-response cycle,
	// including connection establishment, request sending, and response reading.
	DefaultTimeout = 30 * time.Second

	// DefaultMaxIdleConns controls the total number of idle connections across all hosts.
	// Higher values improve performance for multi-host scenarios but consume more resources.
	DefaultMaxIdleConns = 100

	// DefaultMaxIdleConnsPerHost limits idle connections per host to prevent resource exhaustion.
	// Increase this value if you make many concurrent requests to the same host.
	DefaultMaxIdleConnsPerHost = 10

	// DefaultIdleConnTimeout defines how long an idle connection remains in the pool before closing.
	// Connections idle longer than this are automatically closed and removed from the pool.
	DefaultIdleConnTimeout = 90 * time.Second

	// DefaultTLSHandshakeTimeout is the maximum time allowed for the TLS handshake.
	// Requests fail if the handshake takes longer than this duration.
	DefaultTLSHandshakeTimeout = 10 * time.Second

	// DefaultExpectContinueTimeout limits wait time for a server's "100 Continue" response.
	// Used when sending requests with "Expect: 100-continue" header.
	DefaultExpectContinueTimeout = 1 * time.Second

	// DefaultMinVersion enforces TLS 1.2 as the minimum supported version for security.
	// TLS 1.0 and 1.1 are deprecated due to known vulnerabilities.
	DefaultMinVersion = tls.VersionTLS12
)

func createTransport(insecure bool) *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   DefaultTimeout,
			KeepAlive: DefaultIdleConnTimeout,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          DefaultMaxIdleConns,
		MaxIdleConnsPerHost:   DefaultMaxIdleConnsPerHost,
		IdleConnTimeout:       DefaultIdleConnTimeout,
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ExpectContinueTimeout: DefaultExpectContinueTimeout,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure, //nolint:gosec // insecure mode is intentional in required cases.
			MinVersion:         DefaultMinVersion,
		},
	}
}

// Client represents a simplified HTTP client with fluent API.
// Note: This client is NOT safe for concurrent configuration changes.
// Configure the client before making requests, or create separate clients.
type Client struct {
	// HTTP clients
	logger         logger.Logger
	httpClient     *http.Client
	insecureClient *http.Client

	// Configuration
	baseURL   string
	userAgent string
	headers   map[string]string
	debug     bool
}

// New creates a new HTTP client with sensible defaults.
func New(logger logger.Logger) *Client {
	secureTransport := createTransport(false)
	insecureTransport := createTransport(true)

	return &Client{
		logger: logger.With("client", "http"),
		httpClient: &http.Client{
			Timeout:   DefaultTimeout,
			Transport: secureTransport,
		},
		insecureClient: &http.Client{
			Timeout:   DefaultTimeout,
			Transport: insecureTransport,
		},
		userAgent: "attestation-framework/1.0",
		headers:   make(map[string]string),
	}
}

// R creates a new request.
func (c *Client) R() *Request {
	return &Request{
		client:      c,
		headers:     maps.Clone(c.headers),
		queryParams: make(map[string]string),
		ctx:         context.Background(),
	}
}

// SetBaseURL sets the base URL for all requests.
func (c *Client) SetBaseURL(baseURL string) *Client {
	c.baseURL = baseURL
	return c
}

// SetTimeout sets the timeout for all requests.
func (c *Client) SetTimeout(timeout time.Duration) *Client {
	c.httpClient.Timeout = timeout
	c.insecureClient.Timeout = timeout
	return c
}

// SetUserAgent sets the User-Agent header.
func (c *Client) SetUserAgent(ua string) *Client {
	c.userAgent = ua
	return c
}

// SetHeader sets a header for all requests.
func (c *Client) SetHeader(key, value string) *Client {
	c.headers[key] = value
	return c
}

// SetHeaders sets multiple headers for all requests without overriding existing ones.
func (c *Client) SetHeaders(headers map[string]string) *Client {
	maps.Copy(c.headers, headers)
	return c
}

// SetAuthToken sets Bearer token authentication.
func (c *Client) SetAuthToken(token string) *Client {
	return c.SetHeader("Authorization", "Bearer "+token)
}

// SetDebug enables debug logging.
func (c *Client) SetDebug(debug bool) *Client {
	c.debug = debug
	return c
}

// SetTLSClientConfig sets custom TLS configuration.
func (c *Client) SetTLSClientConfig(config *tls.Config) *Client {
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.TLSClientConfig = config
	}
	return c
}

// Close closes idle connections. Call when client is no longer needed.
func (c *Client) Close() {
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	if transport, ok := c.insecureClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (c *Client) execute(req *Request) (*Response, error) {
	fullURL, err := c.buildURL(req.url, req.queryParams)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "http_client_v2", "build_url",
			"failed to build URL")
	}

	if prepareErr := req.prepareBody(); prepareErr != nil {
		return nil, pkgerrors.WrapWithContext(prepareErr, "http_client_v2", "prepare_body",
			"failed to prepare request body")
	}

	httpReq, err := http.NewRequestWithContext(req.ctx, req.method, fullURL, req.body)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "http_client_v2", "create_request",
			"failed to create HTTP request")
	}

	httpReq.Header.Set("User-Agent", c.userAgent)
	for k, v := range req.headers {
		httpReq.Header.Set(k, v)
	}

	client := c.httpClient
	if req.insecure {
		client = c.insecureClient
	}

	start := time.Now()
	httpResp, err := client.Do(httpReq) //nolint:bodyclose // response body is wrapped in Response and closed via resp.Close()
	duration := time.Since(start)

	if err != nil {
		c.logger.Error("request failed",
			"method", req.method,
			"url", fullURL,
			"error", err,
			"duration_ms", duration.Milliseconds())
		return nil, pkgerrors.WrapWithContext(err, "http_client_v2", "execute",
			"HTTP request failed")
	}

	if c.debug {
		c.logger.Info("request completed",
			"method", req.method,
			"url", fullURL,
			"status", httpResp.StatusCode,
			"duration_ms", duration.Milliseconds())
	}

	resp := &Response{
		request:     req,
		rawResponse: httpResp,
		body:        httpResp.Body,
		statusCode:  httpResp.StatusCode,
		status:      httpResp.Status,
		header:      httpResp.Header,
		duration:    duration,
	}

	return resp, nil
}

// buildURL constructs the full URL with base URL and query parameters.
func (c *Client) buildURL(reqURL string, queryParams map[string]string) (string, error) {
	fullURL := reqURL
	if c.baseURL != "" && !utils.IsAbsoluteURL(reqURL) {
		fullURL = c.baseURL + reqURL
	}

	if len(queryParams) == 0 {
		return fullURL, nil
	}

	u, err := url.Parse(fullURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	for k, v := range queryParams {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}
