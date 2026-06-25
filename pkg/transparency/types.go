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

import rekor "github.com/thomsonreuters/stamp/pkg/clients/rekor/v1"

// Type aliases for rekor types used in public APIs.
type (
	LogEntry       = rekor.LogEntry
	InclusionProof = rekor.InclusionProof
)

// FetchResult represents processed Rekor entry data.
type FetchResult struct {
	UUID                   string          `json:"uuid"`
	Timestamp              *string         `json:"timestamp,omitempty"`
	LogIndex               *int64          `json:"logIndex,omitempty"`
	TreeSize               *int64          `json:"treeSize,omitempty"`
	InclusionProof         *InclusionProof `json:"inclusionProof,omitempty"`
	InclusionProofVerified bool            `json:"inclusionProofVerified,omitempty"`
	EntryBody              map[string]any  `json:"entryBody,omitempty"`
	RawResponse            map[string]any  `json:"rawResponse,omitempty"`
}
