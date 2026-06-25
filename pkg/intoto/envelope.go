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

package intoto

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/thomsonreuters/stamp/pkg/crypto/keys"
	"github.com/thomsonreuters/stamp/pkg/signing"
)

const (
	// PayloadType is the DSSE payload type for in-toto attestations.
	PayloadType = "application/vnd.in-toto+json"

	// DSSEVersion is the DSSE protocol version.
	DSSEVersion = "DSSEv1"
)

// Envelope represents a DSSE (Dead Simple Signing Envelope) envelope.
type Envelope struct {
	Payload     string      `json:"payload"`
	PayloadType string      `json:"payloadType"`
	Signatures  []Signature `json:"signatures"`
}

// Signature represents a DSSE signature.
type Signature struct {
	KeyID       string `json:"keyid"`
	Signature   string `json:"sig"`
	Certificate string `json:"cert,omitempty"` // PEM-encoded certificate for certificate-based signing
}

// NewEnvelope creates a new DSSE envelope from a statement.
func NewEnvelope(statement *Statement) (*Envelope, error) {
	if statement == nil {
		return nil, ErrNilStatement
	}

	if err := statement.Validate(); err != nil {
		return nil, fmt.Errorf("invalid statement: %w", err)
	}

	payloadBytes, err := statement.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize statement: %w", err)
	}

	return &Envelope{
		Payload:     base64.StdEncoding.EncodeToString(payloadBytes),
		PayloadType: PayloadType,
		Signatures:  []Signature{},
	}, nil
}

// Sign adds a signature to the envelope using the provided signer.
func (e *Envelope) Sign(ctx context.Context, signer signing.Signer) error {
	if signer == nil {
		return ErrNilSigner
	}

	pae := e.preauthEncode()

	signature, err := signer.Sign(ctx, pae)
	if err != nil {
		return fmt.Errorf("failed to sign payload: %w", err)
	}

	keyID, err := signer.KeyID()
	if err != nil {
		return fmt.Errorf("failed to get key ID: %w", err)
	}

	sig := Signature{
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}

	if certSigner, ok := signer.(signing.CertificateSigner); ok {
		certPEM, err := certSigner.Certificate()
		if err != nil {
			return fmt.Errorf("failed to get certificate: %w", err)
		}
		if len(certPEM) > 0 {
			sig.Certificate = base64.StdEncoding.EncodeToString(certPEM)
		}
	}

	e.Signatures = append(e.Signatures, sig)
	return nil
}

// ToJSON serializes the envelope to JSON.
func (e *Envelope) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// ToJSONIndent serializes the envelope to pretty-printed JSON.
func (e *Envelope) ToJSONIndent() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}

// SHA256 returns the SHA256 hash of the envelope's JSON representation.
// This is used for searching in transparency logs like Rekor.
func (e *Envelope) SHA256() (string, error) {
	data, err := e.ToJSON()
	if err != nil {
		return "", fmt.Errorf("failed to serialize envelope: %w", err)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// GetStatement extracts and parses the statement from the envelope.
func (e *Envelope) GetStatement() (*Statement, error) {
	payloadBytes, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var statement Statement
	if err := json.Unmarshal(payloadBytes, &statement); err != nil {
		return nil, fmt.Errorf("failed to unmarshal statement: %w", err)
	}

	return &statement, nil
}

// Verify verifies the signature using the provided verifier.
func (e *Envelope) Verify(verifier Verifier) error {
	if verifier == nil {
		return ErrNilVerifier
	}

	if len(e.Signatures) == 0 {
		return ErrNoSignatures
	}

	pae := e.preauthEncode()

	for i, sig := range e.Signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Signature)
		if err != nil {
			return fmt.Errorf("failed to decode signature %d: %w", i, err)
		}

		if err := verifier.Verify(pae, sigBytes, sig.KeyID); err != nil {
			return fmt.Errorf("signature %d verification failed: %w", i, err)
		}
	}

	return nil
}

// preauthEncode implements the DSSE pre-authentication encoding
// PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body.
func (e *Envelope) preauthEncode() []byte {
	payloadBytes, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		payloadBytes = []byte(e.Payload)
	}

	return fmt.Appendf(nil, "%s %d %s %d %s",
		DSSEVersion,
		len(e.PayloadType),
		e.PayloadType,
		len(payloadBytes),
		string(payloadBytes))
}

// Verifier interface for verifying DSSE signatures.
type Verifier interface {
	Verify(payload, signature []byte, keyID string) error
}

// HasSignatures returns true if the envelope has any signatures.
func (e *Envelope) HasSignatures() bool {
	return len(e.Signatures) > 0
}

// SignatureCount returns the number of signatures in the envelope.
func (e *Envelope) SignatureCount() int {
	return len(e.Signatures)
}

// HasCertificate returns true if any signature contains a certificate.
func (e *Envelope) HasCertificate() bool {
	for _, sig := range e.Signatures {
		if sig.Certificate != "" {
			return true
		}
	}
	return false
}

// ExtractCertificate extracts the first valid X.509 certificate found in the envelope's signatures.
// It iterates through all signatures, attempting to parse each certificate field.
// Certificates can be either DER-encoded or PEM-encoded (both base64 wrapped).
// If a signature's certificate field cannot be decoded or parsed, it continues to the next signature.
// Returns the first successfully parsed certificate, or an error if no valid certificate is found.
func (e *Envelope) ExtractCertificate() (*x509.Certificate, error) {
	for _, signature := range e.Signatures {
		if signature.Certificate == "" {
			continue
		}

		certBytes, err := base64.StdEncoding.DecodeString(signature.Certificate)
		if err != nil {
			continue
		}

		certificate, err := keys.ParseCertificateFromBytes(certBytes)
		if err != nil {
			continue
		}

		return certificate, nil
	}

	return nil, ErrNoCertificate
}

// ExtractCertificates extracts all valid X.509 certificates from all signatures in the envelope.
// Certificates can be either DER-encoded or PEM-encoded (both base64 wrapped).
// For certificate chains, all certificates in the chain are included.
// Returns an error if no valid certificates are found.
func (e *Envelope) ExtractCertificates() ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate

	for _, signature := range e.Signatures {
		if signature.Certificate == "" {
			continue
		}

		certificateBytes, err := base64.StdEncoding.DecodeString(signature.Certificate)
		if err != nil {
			continue
		}

		parsedCerts, err := keys.ParseCertificateChainFromBytes(certificateBytes)
		if err != nil {
			continue
		}

		certificates = append(certificates, parsedCerts...)
	}

	if len(certificates) == 0 {
		return nil, ErrNoCertificate
	}

	return certificates, nil
}
