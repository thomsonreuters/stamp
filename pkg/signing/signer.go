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

package signing

import (
	"context"
	"crypto"
	"fmt"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
)

// Signer signs attestation payloads.
type Signer interface {
	// ID returns the unique identifier for this signer type.
	ID() string

	// Validate validates the configuration for this signer.
	Validate(config SignerConfig) error

	// PreSign runs before signing.
	// Use this for setup, key loading, certificate acquisition, etc.
	PreSign(ctx context.Context, config SignerConfig) error

	// Sign signs the payload and returns the signature.
	Sign(ctx context.Context, payload []byte) ([]byte, error)

	// PostSign runs after signing.
	// Use this for cleanup, logging, metrics, etc.
	PostSign(ctx context.Context) error

	// KeyID returns the key identifier.
	KeyID() (string, error)

	// PublicKey returns the public key.
	PublicKey() (crypto.PublicKey, error)
}

// CertificateSigner extends Signer for certificate-based signing.
type CertificateSigner interface {
	Signer
	Certificate() ([]byte, error)
}

// FactoryFunc creates a new Signer instance from configuration.
type FactoryFunc func(ctx context.Context, config SignerConfig) (Signer, error)

// NewSigner creates a new signer using the provider specified in config.
func NewSigner(ctx context.Context, config SignerConfig) (Signer, error) {
	if err := config.Validate(); err != nil {
		return nil, pkgerrors.WrapWithContext(err, "signing", "validate", "invalid config")
	}

	signer, err := Get(ctx, config.Provider, config)
	if err != nil {
		return nil, err
	}

	if err := signer.Validate(config); err != nil {
		return nil, pkgerrors.WrapWithContext(err, "signing", "validate", fmt.Sprintf("invalid config for signer %q", config.Provider))
	}

	return signer, nil
}
