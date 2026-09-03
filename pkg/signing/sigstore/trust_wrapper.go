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

package sigstore

import (
	"crypto"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
)

// signerKeyTrustedMaterial overrides PublicKeyVerifier(hint) to return the
// user's signing key so sign.Bundle's post-sign self-verify passes for
// user-key signing — public sigstore's trusted_root does not carry user
// keys. Other methods delegate to the embedded base.

type signerKeyTrustedMaterial struct {
	root.TrustedMaterial
	keyMaterial root.TrustedMaterial
}

func (s *signerKeyTrustedMaterial) PublicKeyVerifier(hint string) (root.TimeConstrainedVerifier, error) {
	if s.keyMaterial == nil {
		return s.TrustedMaterial.PublicKeyVerifier(hint)
	}
	return s.keyMaterial.PublicKeyVerifier(hint)
}

// newSignerKeyTrustedMaterial wraps base so PublicKeyVerifier returns a
// verifier for pubKey (any hint). Returns base unchanged when pubKey is nil.
func newSignerKeyTrustedMaterial(base root.TrustedMaterial, pubKey crypto.PublicKey) (root.TrustedMaterial, error) {
	if pubKey == nil {
		return base, nil
	}
	verifier, err := signature.LoadDefaultVerifier(pubKey)
	if err != nil {
		return nil, fmt.Errorf("load verifier for user key: %w", err)
	}
	key := root.NewExpiringKey(verifier, time.Time{}, time.Time{})
	keyMaterial := root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
		return key, nil
	})
	return &signerKeyTrustedMaterial{
		TrustedMaterial: base,
		keyMaterial:     keyMaterial,
	}, nil
}
