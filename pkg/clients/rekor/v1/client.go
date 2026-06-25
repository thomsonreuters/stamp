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

package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	httpclient "github.com/thomsonreuters/stamp/pkg/http/client"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

const (
	// DefaultRekorURL is the default public Rekor instance URL.
	DefaultRekorURL = "https://rekor.sigstore.dev"

	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 30 * time.Second

	// API endpoints.
	logInfoEndpoint            = "/api/v1/log"
	logEntriesEndpoint         = "/api/v1/log/entries"
	logEntriesRetrieveEndpoint = "/api/v1/log/entries/retrieve"
	indexRetrieveEndpoint      = "/api/v1/index/retrieve"
)

// DefaultRetryPolicy is the default retry policy for CreateEntry.
var DefaultRetryPolicy = RetryPolicy{
	MaxAttempts:  3,
	InitialDelay: time.Second,
	MaxDelay:     30 * time.Second,
	Multiplier:   2.0,
}

// ClientIface defines the interface for the Rekor client.
type ClientIface interface {
	// GetLogInfo returns the current state of the transparency log.
	GetLogInfo(ctx context.Context) (*LogInfo, error)

	// GetEntry retrieves an entry by UUID.
	GetEntry(ctx context.Context, uuid string) (*LogEntry, error)

	// GetEntryByLogIndex retrieves an entry by its log index.
	GetEntryByLogIndex(ctx context.Context, logIndex int64) (*LogEntry, error)

	// SearchByHash searches for entries by hash.
	// Returns a list of UUIDs matching the hash.
	SearchByHash(ctx context.Context, hash string) ([]string, error)

	// CreateEntry creates a new entry in the transparency log with optional retry.
	// If retry is nil, DefaultRetryPolicy is used.
	CreateEntry(ctx context.Context, entry *ProposedEntry, retry *RetryPolicy) (*LogEntry, error)

	// GetInclusionProof retrieves the inclusion proof for an entry.
	GetInclusionProof(ctx context.Context, uuid string) (*InclusionProof, error)
}

// Client is the Rekor client that interacts with the transparency log.
type Client struct {
	httpClient *httpclient.Client
	opts       Options
}

// Options configures the Rekor client.
type Options struct {
	// URL is the Rekor server URL.
	// If empty, DefaultRekorURL is used.
	URL string

	// Timeout is the HTTP request timeout.
	// If zero, DefaultTimeout is used.
	Timeout time.Duration

	// Insecure allows insecure HTTPS connections (skip TLS verification).
	// Should only be used for testing.
	Insecure bool

	// Logger is the logger to use. If nil, a noop logger is used.
	Logger logger.Logger
}

// GetLogInfo returns the current state of the transparency log.
func (c *Client) GetLogInfo(ctx context.Context) (*LogInfo, error) {
	requestURL := c.opts.URL + logInfoEndpoint

	resp, err := c.httpClient.R().
		SetContext(ctx).
		SetHeader("Accept", "application/json").
		SetInsecure(c.opts.Insecure).
		Get(requestURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Close() }()

	body, err := resp.Bytes()
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		return nil, ErrNonSuccessfulResponse
	}

	var logInfo LogInfo
	if err := json.Unmarshal(body, &logInfo); err != nil {
		return nil, err
	}

	return &logInfo, nil
}

// GetEntry retrieves an entry by UUID.
func (c *Client) GetEntry(ctx context.Context, uuid string) (*LogEntry, error) {
	requestURL := c.opts.URL + logEntriesEndpoint + "/" + uuid

	resp, err := c.httpClient.R().
		SetContext(ctx).
		SetHeader("Accept", "application/json").
		SetInsecure(c.opts.Insecure).
		Get(requestURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Close() }()

	body, err := resp.Bytes()
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		return nil, ErrNonSuccessfulResponse
	}

	// Rekor returns a map with UUID as key
	var entryResponse LogEntryResponse
	if err := json.Unmarshal(body, &entryResponse); err != nil {
		return nil, err
	}

	entry, exists := entryResponse[uuid]
	if !exists {
		return nil, ErrEntryNotFound
	}

	entry.UUID = uuid
	return &entry, nil
}

// GetEntryByLogIndex retrieves an entry by its log index.
func (c *Client) GetEntryByLogIndex(ctx context.Context, logIndex int64) (*LogEntry, error) {
	requestURL := c.opts.URL + logEntriesRetrieveEndpoint

	payload := LogEntryRequest{
		LogIndexes: []int64{logIndex},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetHeader("Accept", "application/json").
		SetInsecure(c.opts.Insecure).
		SetBody(payloadBytes).
		Post(requestURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Close() }()

	body, err := resp.Bytes()
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		return nil, ErrNonSuccessfulResponse
	}

	// Response is an array of entries
	var responseArray LogEntriesResponse
	if err := json.Unmarshal(body, &responseArray); err != nil {
		return nil, err
	}

	if len(responseArray) == 0 {
		return nil, ErrEntryNotFound
	}

	// Extract UUID and entry from the first result
	for uuid, entry := range responseArray[0] {
		entry.UUID = uuid
		return &entry, nil
	}

	return nil, ErrEntryNotFound
}

// SearchByHash searches for entries by hash.
func (c *Client) SearchByHash(ctx context.Context, hash string) ([]string, error) {
	requestURL := c.opts.URL + indexRetrieveEndpoint

	payload := SearchIndexRequest{
		Hash: fmt.Sprintf("sha256:%s", hash),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetHeader("Accept", "application/json").
		SetInsecure(c.opts.Insecure).
		SetBody(payloadBytes).
		Post(requestURL)

	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Close() }()

	body, err := resp.Bytes()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() == http.StatusNotFound {
		return []string{}, nil
	}

	if !resp.IsSuccess() {
		return nil, ErrNonSuccessfulResponse
	}

	var uuids []string
	if err := json.Unmarshal(body, &uuids); err != nil {
		return nil, err
	}

	return uuids, nil
}

// CreateEntry creates a new entry in the transparency log with automatic retry.
// If retry is nil, DefaultRetryPolicy is used.
func (c *Client) CreateEntry(ctx context.Context, entry *ProposedEntry, retry *RetryPolicy) (*LogEntry, error) {
	if retry == nil {
		retry = &DefaultRetryPolicy
	}

	requestURL := c.opts.URL + logEntriesEndpoint
	entryBytes, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}

	var lastErr error
	delay := retry.InitialDelay
	request := c.httpClient.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetHeader("Accept", "application/json").
		SetInsecure(c.opts.Insecure).
		SetBody(entryBytes)

	for attempt := 1; attempt <= retry.MaxAttempts; attempt++ {
		resp, err := request.Post(requestURL)

		if err != nil {
			return nil, err
		}

		body, err := resp.Bytes()
		statusCode := resp.StatusCode()
		_ = resp.Close() // Close immediately to prevent resource leaks in retry loop

		if err != nil {
			return nil, err
		}

		switch statusCode {
		case http.StatusCreated:
			var responseMap map[string]LogEntry
			if err := json.Unmarshal(body, &responseMap); err != nil {
				return nil, err
			}
			for uuid, logEntry := range responseMap {
				logEntry.UUID = uuid
				return &logEntry, nil
			}
			return nil, ErrEntryNotFound
		case http.StatusConflict:
			return nil, ErrEntryAlreadyExists
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return nil, ErrNonSuccessfulResponse
		default:
			lastErr = ErrNonSuccessfulResponse
			if attempt < retry.MaxAttempts {
				delay = time.Duration(float64(delay) * retry.Multiplier)
			}
			if delay > retry.MaxDelay {
				delay = retry.MaxDelay
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
	}

	return nil, lastErr
}

// GetInclusionProof retrieves the inclusion proof for an entry.
func (c *Client) GetInclusionProof(ctx context.Context, uuid string) (*InclusionProof, error) {
	entry, err := c.GetEntry(ctx, uuid)
	if err != nil {
		return nil, err
	}

	if entry.Verification == nil {
		return nil, ErrNoVerificationData
	}

	if entry.Verification.InclusionProof == nil {
		return nil, ErrNoInclusionProof
	}

	return entry.Verification.InclusionProof, nil
}

func newClient(opts Options) (ClientIface, error) {
	if opts.URL == "" {
		opts.URL = DefaultRekorURL
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Logger == nil {
		opts.Logger = logger.NewNoop()
	}

	httpClient := httpclient.New(opts.Logger).SetTimeout(opts.Timeout)

	return &Client{
		httpClient: httpClient,
		opts:       opts,
	}, nil
}

// New is the constructor function for creating a Rekor client.
// This variable can be replaced in tests for mocking.
var New = newClient
