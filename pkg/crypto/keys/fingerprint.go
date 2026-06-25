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

package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
)

// Fingerprint computes a unique identifier for a private key based on its public component.
// Returns a hex-encoded SHA256 hash of the DER-encoded public key in PKIX format.
func Fingerprint(privateKey crypto.PrivateKey) (string, error) {
	publicKey, err := ExtractPublicKey(privateKey)
	if err != nil {
		return "", err
	}
	return FingerprintPublicKey(publicKey)
}

// FingerprintPublicKey computes a unique identifier for a public key.
// Returns a hex-encoded SHA256 hash of the DER-encoded public key in PKIX format.
func FingerprintPublicKey(publicKey crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", pkgerrors.WrapWithContext(err, "keys", "fingerprint", "failed to marshal public key")
	}

	hash := sha256.Sum256(der)
	return hex.EncodeToString(hash[:]), nil
}

// ExtractPublicKey extracts the public key from a private key.
func ExtractPublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	default:
		return nil, pkgerrors.NewWithContext("keys", "extract", fmt.Sprintf("unsupported key type: %T", k))
	}
}
