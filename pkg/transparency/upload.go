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
	"fmt"
	"os"

	rekor "github.com/thomsonreuters/stamp/pkg/clients/rekor/v1"
	"github.com/thomsonreuters/stamp/pkg/intoto"
)

// Upload uploads a signed attestation envelope to Rekor.
// If retry is nil, the client's default retry policy is used.
func (c *Client) Upload(ctx context.Context, envelope *intoto.Envelope, publicKeyPath string, retry *rekor.RetryPolicy) (*LogEntry, error) {
	envelopeBytes, err := envelope.ToJSON()
	if err != nil {
		return nil, err
	}

	verifiers, err := extractVerifiers(envelope, publicKeyPath)
	if err != nil {
		return nil, err
	}

	entry := &rekor.ProposedEntry{
		APIVersion: rekor.DSSEAPIVersion,
		Kind:       rekor.DSSEEntryKind,
		Spec: rekor.DSSESpec{
			ProposedContent: rekor.ProposedContent{
				Envelope:  string(envelopeBytes),
				Verifiers: verifiers,
			},
		},
	}

	return c.client.CreateEntry(ctx, entry, retry)
}

func extractVerifiers(envelope *intoto.Envelope, publicKeyPath string) ([]string, error) {
	if publicKeyPath != "" {
		pubKey, err := os.ReadFile(publicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read public key file: %w", err)
		}
		return []string{base64.StdEncoding.EncodeToString(pubKey)}, nil
	}

	var verifiers []string
	for _, sig := range envelope.Signatures {
		if sig.Certificate != "" {
			verifiers = append(verifiers, sig.Certificate)
		}
	}

	if len(verifiers) == 0 {
		return nil, ErrNoVerifiers
	}
	return verifiers, nil
}
