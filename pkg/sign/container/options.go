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

package container

import (
	"crypto"
	"errors"
	"fmt"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
)

// Options for Signer.Sign. Exactly one of Key or Fulcio must be set.
// Registry and Rekor are optional; a nil Registry falls back to the
// Docker keychain (which handles anonymous pulls of public images).
type Options struct {
	Key      *KeyOptions
	Fulcio   *FulcioOptions
	Rekor    *RekorOptions
	Registry *RegistryOptions
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
}

type RegistryOptions struct {
	Username string
	Password string
}

type Result struct {
	Bundle     *protobundle.Bundle
	BundleJSON []byte
	// Digest is the resolved image manifest digest (e.g. "sha256:abc...").
	Digest string
}

func (o *Options) validate() error {
	if o.Key == nil && o.Fulcio == nil {
		return errors.New("container sign: one of Key or Fulcio is required")
	}
	if o.Key != nil && o.Fulcio != nil {
		return errors.New("container sign: Key and Fulcio are mutually exclusive")
	}
	if o.Key != nil && o.Key.Signer == nil {
		return errors.New("container sign: Key.Signer is required")
	}
	if o.Key != nil && len(o.Key.Hint) == 0 {
		return errors.New("container sign: Key.Hint is required (verifier lookup id)")
	}
	if o.Fulcio != nil {
		if o.Fulcio.URL == "" {
			return errors.New("container sign: Fulcio.URL is required")
		}
		if o.Fulcio.IDToken == "" {
			return errors.New("container sign: Fulcio.IDToken is required")
		}
	}
	if o.Rekor != nil && o.Rekor.URL == "" {
		return errors.New("container sign: Rekor.URL is required")
	}
	// Registry is optional (anonymous / keychain fallback); reject only
	// the half-set case, which would produce a malformed Basic Auth header.
	if o.Registry != nil && (o.Registry.Username == "") != (o.Registry.Password == "") {
		return errors.New("container sign: Registry.Username and Registry.Password must be set together")
	}
	return nil
}

func (o *Options) buildSigningMaterial() (sign.Keypair, sign.CertificateProvider, *sign.CertificateProviderOptions, error) {
	if o.Fulcio != nil {
		kp, err := sign.NewEphemeralKeypair(nil)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("container sign: ephemeral keypair: %w", err)
		}
		provider := sign.NewFulcio(&sign.FulcioOptions{BaseURL: o.Fulcio.URL})
		return kp, provider, &sign.CertificateProviderOptions{IDToken: o.Fulcio.IDToken}, nil
	}
	kp, err := newKeypairAdapter(o.Key.Signer, o.Key.Hint)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("container sign: keypair adapter: %w", err)
	}
	return kp, nil, nil, nil
}
