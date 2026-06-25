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

// Package rekor provides a client for interacting with Rekor transparency log.
package v1

import "time"

// Entry type constants for Rekor log entries.
const (
	// DSSEEntryKind is the entry kind for DSSE (Dead Simple Signing Envelope) entries.
	DSSEEntryKind = "dsse"

	// DSSEAPIVersion is the API version for DSSE entries.
	DSSEAPIVersion = "0.0.1"
)

// LogInfo represents the current state of the Rekor transparency log.
type LogInfo struct {
	TreeSize int64  `json:"treeSize"`
	RootHash string `json:"rootHash"`
}

// LogEntry represents a Rekor log entry.
type LogEntry struct {
	UUID           string        `json:"uuid"`
	Body           string        `json:"body"`
	IntegratedTime int64         `json:"integratedTime"`
	LogIndex       int64         `json:"logIndex"`
	LogID          string        `json:"logID"`
	Verification   *Verification `json:"verification,omitempty"`
}

// Verification contains verification data for a log entry.
type Verification struct {
	InclusionProof       *InclusionProof `json:"inclusionProof,omitempty"`
	SignedEntryTimestamp string          `json:"signedEntryTimestamp,omitempty"`
}

// InclusionProof contains the Merkle inclusion proof data.
type InclusionProof struct {
	LogIndex   int64    `json:"logIndex"`
	RootHash   string   `json:"rootHash"`
	TreeSize   int64    `json:"treeSize"`
	Hashes     []string `json:"hashes"`
	Checkpoint string   `json:"checkpoint,omitempty"`
}

// ProposedEntry represents a proposed entry for Rekor.
type ProposedEntry struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       any    `json:"spec"`
}

// DSSESpec represents the DSSE entry specification for Rekor.
type DSSESpec struct {
	ProposedContent ProposedContent `json:"proposedContent"`
}

// ProposedContent holds the DSSE envelope and verifiers.
type ProposedContent struct {
	Envelope  string   `json:"envelope"`
	Verifiers []string `json:"verifiers,omitempty"`
	PublicKey string   `json:"publicKey,omitempty"`
}

// RetryPolicy configures retry behavior for operations.
type RetryPolicy struct {
	MaxAttempts  int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
}

type LogEntryRequest struct {
	LogIndexes []int64 `json:"logIndexes"`
}

type LogEntryResponse map[string]LogEntry

type LogEntriesResponse []LogEntryResponse

type SearchIndexRequest struct {
	Hash string `json:"hash"`
}
