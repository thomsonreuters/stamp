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
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
)

// Options configures Signer.SignBundle. Exactly one of Key or Fulcio must be set.
type Options struct {
	Key           *KeyOptions
	Fulcio        *FulcioOptions
	Rekor         *RekorOptions
	TSA           *TSAOptions
	TrustedRoot   *root.TrustedRoot
	SigningConfig *root.SigningConfig
}

type KeyOptions struct {
	Signer crypto.Signer
	Hint   []byte // key id for verifier lookup
}

type FulcioOptions struct {
	URL     string
	IDToken string
}

type RekorOptions struct {
	URL     string
	Version uint32 // 0/1 = classic Rekor, 2 = rekor-tiles
}

// TSAOptions configures an RFC 3161 Timestamp Authority. Required for Rekor v2.
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
