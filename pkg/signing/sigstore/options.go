// Copyright 2025 Thomson Reuters
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

package sigstore

import (
	"crypto"
	"errors"
	"fmt"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
)

// Options for Signer.SignBundle. Exactly one of Key or Fulcio must be set.
// Rekor is optional; nil skips transparency-log upload. TSA is required
// when Rekor.Version == 2.
type Options struct {
	Key    *KeyOptions
	Fulcio *FulcioOptions
	Rekor  *RekorOptions
	TSA    *TSAOptions
}

type KeyOptions struct {
	Signer crypto.Signer
	// Hint is the key id embedded in the DSSE signature so verifiers
	// know which public key to check against.
	Hint []byte
}

type FulcioOptions struct {
	URL string
	// IDToken's issuer must be trusted by the target Fulcio instance.
	IDToken string
}

type RekorOptions struct {
	URL string
	// Version selects the Rekor API. 0/1 = classic Rekor, 2 = rekor-tiles.
	// sigstore-go defaults to 1 when unset; v2 additionally requires a TSA.
	Version uint32
}

// TSAOptions configures an RFC 3161 Timestamp Authority. Required when
// Rekor v2 is in use because v2 entries have integrated_time = 0.
type TSAOptions struct {
	URL string
}

type Result struct {
	Bundle     *protobundle.Bundle
	BundleJSON []byte
}

func (o *Options) Validate() error {
	if o.Key == nil && o.Fulcio == nil {
		return errors.New("sigstore sign: one of Key or Fulcio is required")
	}
	if o.Key != nil && o.Fulcio != nil {
		return errors.New("sigstore sign: Key and Fulcio are mutually exclusive")
	}
	if o.Key != nil && o.Key.Signer == nil {
		return errors.New("sigstore sign: Key.Signer is required")
	}
	if o.Key != nil && len(o.Key.Hint) == 0 {
		return errors.New("sigstore sign: Key.Hint is required (verifier lookup id)")
	}
	if o.Fulcio != nil {
		if o.Fulcio.URL == "" {
			return errors.New("sigstore sign: Fulcio.URL is required")
		}
		if o.Fulcio.IDToken == "" {
			return errors.New("sigstore sign: Fulcio.IDToken is required")
		}
	}
	if o.Rekor != nil && o.Rekor.URL == "" {
		return errors.New("sigstore sign: Rekor.URL is required")
	}
	if o.Rekor != nil && o.Rekor.Version == 2 && (o.TSA == nil || o.TSA.URL == "") {
		return errors.New("sigstore sign: Rekor v2 requires TSA.URL to be set")
	}
	if o.TSA != nil && o.TSA.URL == "" {
		return errors.New("sigstore sign: TSA.URL is required when TSA is set")
	}
	return nil
}

// BuildSigningMaterial returns everything sigstore-go's sign.Bundle
// needs as input: the signing keypair, an optional certificate provider
// (Fulcio), and its runtime options.
func (o *Options) BuildSigningMaterial() (sign.Keypair, sign.CertificateProvider, *sign.CertificateProviderOptions, error) {
	if o.Fulcio != nil {
		kp, err := sign.NewEphemeralKeypair(nil)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("sigstore sign: ephemeral keypair: %w", err)
		}
		provider := sign.NewFulcio(&sign.FulcioOptions{BaseURL: o.Fulcio.URL})
		return kp, provider, &sign.CertificateProviderOptions{IDToken: o.Fulcio.IDToken}, nil
	}
	kp, err := newKeypairAdapter(o.Key.Signer, o.Key.Hint)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sigstore sign: keypair adapter: %w", err)
	}
	return kp, nil, nil, nil
}
