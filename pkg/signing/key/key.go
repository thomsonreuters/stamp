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

package key

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/thomsonreuters/stamp/pkg/crypto/keys"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/signing"
)

const signerID = "key"

// Signer implements key-based signing using local key files.
type Signer struct {
	privateKey crypto.PrivateKey
	keyID      string
	keyPath    string
}

// ID returns the signer identifier.
func (s *Signer) ID() string {
	return signerID
}

// Validate validates the key signer configuration.
func (s *Signer) Validate(base signing.SignerConfig) error {
	config := base.Key

	if config == nil {
		return pkgerrors.NewWithContext("key_signer", "validate", "key configuration is required")
	}

	if config.KeyPath == "" {
		return pkgerrors.NewWithContext("key_signer", "validate", "key-path is required")
	}

	if config.KeyPassword != "" && config.KeyPasswordFile != "" {
		return pkgerrors.NewWithContext("key_signer", "validate", "only one of key-password or key-password-file should be set")
	}

	if base.Provider != signerID {
		return pkgerrors.NewWithContext("key_signer", "validate", fmt.Sprintf("invalid provider: expected %s, got %s", signerID, base.Provider))
	}

	if _, err := os.Stat(config.KeyPath); err != nil {
		return pkgerrors.WrapWithContext(err, "key_signer", "validate", fmt.Sprintf("key file not found: %s", config.KeyPath))
	}

	return nil
}

// PreSign loads the private key from file.
func (s *Signer) PreSign(ctx context.Context, config signing.SignerConfig) error {
	password, err := s.getPassword(*config.Key)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "key_signer", "pre_sign", "failed to get password")
	}

	loaded, err := keys.LoadPrivateKeyFromFile(config.Key.KeyPath, password)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "key_signer", "pre_sign", "failed to load key")
	}

	keyID, err := keys.Fingerprint(loaded.PrivateKey)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "key_signer", "pre_sign", "failed to generate key fingerprint")
	}

	s.privateKey = loaded.PrivateKey
	s.keyID = keyID
	s.keyPath = config.Key.KeyPath

	return nil
}

// Sign signs the payload with the private key.
func (s *Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	hash := sha256.Sum256(payload)

	switch key := s.privateKey.(type) {
	case *rsa.PrivateKey:
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		if err != nil {
			return nil, pkgerrors.WrapWithContext(err, "key_signer", "sign", "RSA signing failed")
		}
		return signature, nil

	case *ecdsa.PrivateKey:
		signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
		if err != nil {
			return nil, pkgerrors.WrapWithContext(err, "key_signer", "sign", "ECDSA signing failed")
		}
		return signature, nil

	default:
		return nil, pkgerrors.NewWithContext("key_signer", "sign", fmt.Sprintf("unsupported key type: %T", key))
	}
}

// PostSign performs cleanup after signing (no-op for key signer).
func (s *Signer) PostSign(ctx context.Context) error {
	return nil
}

// KeyID returns the key identifier.
func (s *Signer) KeyID() (string, error) {
	return s.keyID, nil
}

// PublicKey returns the public key.
func (s *Signer) PublicKey() (crypto.PublicKey, error) {
	return keys.ExtractPublicKey(s.privateKey)
}

func (s *Signer) getPassword(config signing.KeySignerConfig) (string, error) {
	if config.KeyPassword != "" {
		return config.KeyPassword, nil
	}

	if config.KeyPasswordFile != "" {
		data, err := os.ReadFile(config.KeyPasswordFile)
		if err != nil {
			return "", pkgerrors.WrapWithContext(err, "key_signer", "read", fmt.Sprintf("failed to read password file: %s", config.KeyPasswordFile))
		}
		return strings.TrimSpace(string(data)), nil
	}

	return "", nil
}

// New creates a new key-based signer.
func New(ctx context.Context, config signing.SignerConfig) (signing.Signer, error) {
	return &Signer{}, nil
}

func init() {
	if err := signing.Register(signerID, New); err != nil {
		panic(fmt.Sprintf("failed to register key signer: %v", err))
	}
}
