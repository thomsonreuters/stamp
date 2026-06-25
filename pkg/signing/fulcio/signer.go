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

package fulcio

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/thomsonreuters/stamp/pkg/clients/github"
	"github.com/thomsonreuters/stamp/pkg/clients/spire"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/signing"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

const (
	signerID = "fulcio"
)

// Signer implements Fulcio-based signing.
type Signer struct {
	privateKey  *ecdsa.PrivateKey
	certificate *x509.Certificate
	keyID       string
}

// ID returns the signer identifier.
func (s *Signer) ID() string { return signerID }

// Validate validates the Fulcio signer configuration.
func (s *Signer) Validate(base signing.SignerConfig) error {
	config := base.Fulcio

	// Validate token file if specified
	if config.TokenPath != "" {
		if _, err := os.Stat(config.TokenPath); err != nil {
			return pkgerrors.WrapWithContext(err, "fulcio", "validate",
				fmt.Sprintf("token file not accessible: %s", config.TokenPath)).
				Suggest(
					"Verify the token file path is correct",
					"Ensure the file exists and is readable",
				)
		}
	}

	// Validate GitHub Actions environment if explicitly requested
	if config.UseGitHub {
		if !github.IsGitHubActionsEnv() {
			return pkgerrors.NewWithContext("fulcio", "validate",
				"GitHub Actions OIDC requested but not running in GitHub Actions environment").
				Suggest(
					"Remove --github flag if not running in GitHub Actions",
					"Ensure GITHUB_ACTIONS=true is set in the environment",
					"Use --spire or --oidc-token-file for non-GitHub environments",
				)
		}
	}

	// Validate SPIRE socket if specified
	if config.UseSpire || config.SpireAgentSocket != "" {
		socketPath := config.SpireAgentSocket
		if socketPath == "" {
			socketPath = spire.GetSocketPath()
		}

		if err := utils.ValidateSocketPath(socketPath); err != nil {
			return pkgerrors.WrapWithContext(err, "fulcio", "validate",
				"SPIRE workload API not accessible").
				Suggest(
					"Ensure SPIRE agent is running",
					"Provide correct socket path with --socket",
					"Set SPIFFE_ENDPOINT_SOCKET environment variable",
					"Verify SPIRE is supported on this platform")
		}
	}

	return nil
}

// PreSign generates ephemeral key pair and obtains certificate from Fulcio.
func (s *Signer) PreSign(ctx context.Context, config signing.SignerConfig) error {
	fulcioConfig := config.Fulcio

	token, err := resolveToken(ctx, *fulcioConfig)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "fulcio", "pre-sign", "failed to resolve token")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "fulcio", "pre-sign", "failed to generate ephemeral key")
	}

	cert, err := getCertificateFromFulcio(ctx, fulcioConfig.FulcioURL, token, &privateKey.PublicKey, fulcioConfig.Insecure, privateKey)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "fulcio", "pre-sign", "failed to get certificate from Fulcio")
	}

	keyID, err := generateKeyIDFromCert(cert)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "fulcio", "pre-sign", "failed to generate key ID")
	}

	s.privateKey = privateKey
	s.certificate = cert
	s.keyID = keyID

	return nil
}

// Sign signs the payload with the ephemeral private key.
func (s *Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	hash := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, s.privateKey, hash[:])
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "fulcio", "sign", "ECDSA signing failed")
	}
	return signature, nil
}

// PostSign performs cleanup after signing (no-op for fulcio signer).
func (s *Signer) PostSign(ctx context.Context) error { return nil }

// KeyID returns the key identifier (from certificate).
func (s *Signer) KeyID() (string, error) { return s.keyID, nil }

// PublicKey returns the public key.
func (s *Signer) PublicKey() (crypto.PublicKey, error) { return &s.privateKey.PublicKey, nil }

// GetCertificate returns the Fulcio certificate object.
func (s *Signer) GetCertificate() *x509.Certificate { return s.certificate }

// Certificate returns the certificate in PEM format (implements CertificateSigner).
func (s *Signer) Certificate() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.certificate.Raw,
	}), nil
}

// CertificateToPEM converts the certificate to PEM format.
func (s *Signer) CertificateToPEM() ([]byte, error) { return s.Certificate() }

// New creates a new Fulcio-based signer.
func New(ctx context.Context, config signing.SignerConfig) (signing.Signer, error) {
	return &Signer{}, nil
}

func init() {
	if err := signing.Register(signerID, New); err != nil {
		panic(fmt.Sprintf("failed to register fulcio signer: %v", err))
	}
}
