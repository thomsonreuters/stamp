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
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/types"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// VerifyInclusionWithPolicyDetails verifies an attestation exists in Rekor with valid inclusion proof.
// Returns (verified, warnings, uuid, error).
func (c *Client) VerifyInclusionWithPolicyDetails(
	ctx context.Context,
	envelope *intoto.Envelope,
	temporalPolicy types.TemporalPolicy,
) (bool, []string, string, error) {
	hash, err := envelope.SHA256()
	if err != nil {
		return false, nil, "", fmt.Errorf("failed to compute hash: %w", err)
	}

	uuids, err := c.client.SearchByHash(ctx, hash)
	if err != nil {
		return false, nil, "", fmt.Errorf("search failed: %w", err)
	}

	if len(uuids) == 0 {
		return false, nil, "", ErrAttestationNotInLog
	}
	if len(uuids) > 1 {
		return false, nil, "", ErrDuplicateEntries
	}

	uuid := uuids[0]
	entry, err := c.client.GetEntry(ctx, uuid)
	if err != nil {
		return false, nil, "", fmt.Errorf("failed to get entry: %w", err)
	}

	if err := c.verifyInclusionProof(ctx, entry); err != nil {
		return false, nil, "", fmt.Errorf("inclusion proof failed: %w", err)
	}

	var warnings []string
	if temporalPolicy != types.TemporalPolicyIgnore {
		if err := c.validateTimestamp(entry, envelope); err != nil {
			if temporalPolicy == types.TemporalPolicyStrict {
				return false, nil, uuid, fmt.Errorf("temporal validation failed: %w", err)
			}
			warnings = append(warnings, fmt.Sprintf("Temporal validation issue: %v", err))
		}
	}

	return true, warnings, uuid, nil
}

func (c *Client) verifyInclusionProof(ctx context.Context, entry *LogEntry) error {
	if entry.Verification == nil {
		return ErrNoVerificationData
	}

	inclusionProof := entry.Verification.InclusionProof
	if inclusionProof == nil {
		return ErrNoInclusionProof
	}

	if inclusionProof.TreeSize == 0 || inclusionProof.RootHash == "" {
		return ErrMissingProofFields
	}

	logInfo, err := c.client.GetLogInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get log info: %w", err)
	}

	if inclusionProof.TreeSize > logInfo.TreeSize {
		return ErrProofTreeSizeExceeds
	}

	if entry.Body == "" {
		return ErrNoBodyInEntry
	}

	bodyBytes, err := base64.StdEncoding.DecodeString(entry.Body)
	if err != nil {
		return fmt.Errorf("failed to decode body: %w", err)
	}

	leafHash := hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(bodyBytes))

	return verifyMerkleProof(leafHash, inclusionProof.LogIndex, inclusionProof.TreeSize, inclusionProof.RootHash, inclusionProof.Hashes)
}

func verifyMerkleProof(leafHex string, logIndex, treeSize int64, rootHex string, proofHex []string) error {
	leaf, err := hex.DecodeString(leafHex)
	if err != nil {
		return fmt.Errorf("invalid leaf hash: %w", err)
	}

	root, err := hex.DecodeString(rootHex)
	if err != nil {
		return fmt.Errorf("invalid root hash: %w", err)
	}

	var proofHashes [][]byte
	for _, h := range proofHex {
		b, err := hex.DecodeString(h)
		if err != nil {
			return fmt.Errorf("invalid proof hash: %w", err)
		}
		proofHashes = append(proofHashes, b)
	}

	return proof.VerifyInclusion(
		rfc6962.DefaultHasher,
		uint64(logIndex),
		uint64(treeSize),
		leaf,
		proofHashes,
		root,
	)
}

func (c *Client) validateTimestamp(entry *LogEntry, envelope *intoto.Envelope) error {
	cert, _ := envelope.ExtractCertificate()
	if cert == nil {
		return nil // No certificate means key-based signing, skip temporal validation
	}

	if entry.IntegratedTime == 0 {
		return ErrNoTimestamp
	}

	ts := time.Unix(entry.IntegratedTime, 0).UTC()
	if ts.After(cert.NotAfter) {
		return ErrCertExpiredBeforeEntry
	}
	if ts.Before(cert.NotBefore) {
		return ErrCertNotYetValid
	}

	return nil
}
