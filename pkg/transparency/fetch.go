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

package transparency

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/thomsonreuters/stamp/pkg/intoto"
)

// FetchFromFile fetches a Rekor entry by searching for the attestation file's hash.
func (c *Client) FetchFromFile(ctx context.Context, filePath string, rawOutput bool) (*FetchResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read attestation file: %w", err)
	}

	var envelope intoto.Envelope
	if unmarshalErr := json.Unmarshal(data, &envelope); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to parse attestation: %w", unmarshalErr)
	}

	hash, err := envelope.SHA256()
	if err != nil {
		return nil, fmt.Errorf("failed to compute hash: %w", err)
	}

	uuids, err := c.client.SearchByHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to search entries: %w", err)
	}

	if len(uuids) == 0 {
		return nil, ErrNoEntryFound
	}

	return c.FetchFromUUID(ctx, uuids[0], rawOutput)
}

// FetchFromUUID fetches a Rekor entry by UUID.
func (c *Client) FetchFromUUID(ctx context.Context, uuid string, rawOutput bool) (*FetchResult, error) {
	entry, err := c.client.GetEntry(ctx, uuid)
	if err != nil {
		return nil, fmt.Errorf("failed to get entry: %w", err)
	}
	return toFetchResult(uuid, entry, rawOutput), nil
}

// FetchFromLogIndex fetches a Rekor entry by log index.
func (c *Client) FetchFromLogIndex(ctx context.Context, logIndexStr string, rawOutput bool) (*FetchResult, error) {
	logIndex, err := strconv.ParseInt(logIndexStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid log index format: %w", err)
	}

	entry, err := c.client.GetEntryByLogIndex(ctx, logIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to get entry: %w", err)
	}
	return toFetchResult(entry.UUID, entry, rawOutput), nil
}

func toFetchResult(uuid string, entry *LogEntry, includeRaw bool) *FetchResult {
	result := &FetchResult{UUID: uuid, LogIndex: &entry.LogIndex}

	if entry.IntegratedTime > 0 {
		ts := time.Unix(entry.IntegratedTime, 0).UTC().Format(time.RFC3339)
		result.Timestamp = &ts
	}

	if entry.Body != "" {
		result.EntryBody = map[string]any{"encoded": entry.Body}
	}

	if includeRaw {
		result.RawResponse = map[string]any{
			uuid: map[string]any{
				"body": entry.Body, "integratedTime": entry.IntegratedTime,
				"logIndex": entry.LogIndex, "logID": entry.LogID, "verification": entry.Verification,
			},
		}
	}

	if entry.Verification != nil && entry.Verification.InclusionProof != nil {
		result.TreeSize = &entry.Verification.InclusionProof.TreeSize
		result.InclusionProof = entry.Verification.InclusionProof
		result.InclusionProofVerified = true
	}

	return result
}
