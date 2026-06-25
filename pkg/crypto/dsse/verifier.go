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

package dsse

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/thomsonreuters/stamp/pkg/crypto/keys"
	"github.com/thomsonreuters/stamp/pkg/intoto"
)

// Sentinel errors for DSSE verification.
var (
	ErrNoSignatures                = errors.New("no signatures found in envelope")
	ErrSignatureVerificationFailed = errors.New("signature verification failed")
	ErrNoPublicKey                 = errors.New("no public key available")
	ErrUnsupportedKeyType          = errors.New("unsupported public key type")
	ErrSignatureInvalid            = errors.New("signature verification failed")
	ErrSignatureDecode             = errors.New("failed to decode signature")
	ErrCertificateDecode           = errors.New("failed to decode certificate")
	ErrPayloadDecode               = errors.New("failed to decode payload")
)

// VerifyDSSESignature verifies DSSE signatures in the envelope.
func VerifyDSSESignature(_ context.Context, envelope *intoto.Envelope, publicKeyPath string) (bool, error) {
	if len(envelope.Signatures) == 0 {
		return false, ErrNoSignatures
	}

	pae, err := createDSSEPAE(envelope)
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256(pae)

	for _, sig := range envelope.Signatures {
		if err := verifySignatureEntry(sig, hash[:], publicKeyPath); err != nil {
			return false, err
		}
	}

	return true, nil
}

// createDSSEPAE creates the DSSE Pre-Authentication Encoding.
// PAE(payloadType, payload) = "DSSEv1" + SP + LEN(payloadType) + SP + payloadType + SP + LEN(payload) + SP + payload.
func createDSSEPAE(envelope *intoto.Envelope) ([]byte, error) {
	payloadBytes, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, ErrPayloadDecode
	}

	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s",
		len(envelope.PayloadType),
		envelope.PayloadType,
		len(payloadBytes),
		payloadBytes), nil
}

// verifySignatureEntry verifies a single signature entry.
func verifySignatureEntry(sig intoto.Signature, hash []byte, publicKeyPath string) error {
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return ErrSignatureDecode
	}

	publicKey, err := extractPublicKey(sig, publicKeyPath)
	if err != nil {
		return err
	}

	return verifySignature(publicKey, hash, sigBytes)
}

// extractPublicKey extracts the public key from either a certificate or key file.
func extractPublicKey(sig intoto.Signature, publicKeyPath string) (crypto.PublicKey, error) {
	if sig.Certificate != "" {
		certBytes, err := base64.StdEncoding.DecodeString(sig.Certificate)
		if err != nil {
			return nil, ErrCertificateDecode
		}
		cert, err := keys.ParseCertificateFromBytes(certBytes)
		if err != nil {
			return nil, ErrCertificateDecode
		}
		return cert.PublicKey, nil
	}

	if publicKeyPath != "" {
		key, err := keys.LoadPublicKeyFromFile(publicKeyPath)
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	return nil, ErrNoPublicKey
}

// verifySignature verifies the signature using the appropriate algorithm.
func verifySignature(publicKey crypto.PublicKey, hash, signature []byte) error {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		return verifyECDSASignature(key, hash, signature)
	case *rsa.PublicKey:
		return verifyRSASignature(key, hash, signature)
	case ed25519.PublicKey:
		return verifyEd25519Signature(key, hash, signature)
	default:
		return ErrUnsupportedKeyType
	}
}

// verifyECDSASignature verifies an ECDSA signature.
func verifyECDSASignature(publicKey *ecdsa.PublicKey, hash, signature []byte) error {
	if !ecdsa.VerifyASN1(publicKey, hash, signature) {
		return ErrSignatureInvalid
	}
	return nil
}

// verifyRSASignature verifies an RSA signature (tries PSS first, then PKCS#1 v1.5).
func verifyRSASignature(publicKey *rsa.PublicKey, hash, signature []byte) error {
	// Try RSA-PSS first (more common in modern signing)
	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, hash, signature, nil); err == nil {
		return nil
	}

	// Fallback to PKCS#1 v1.5
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash, signature); err != nil {
		return ErrSignatureInvalid
	}

	return nil
}

// verifyEd25519Signature verifies an Ed25519 signature.
func verifyEd25519Signature(publicKey ed25519.PublicKey, hash, signature []byte) error {
	// Ed25519 signs the message directly, not the hash
	// However, in DSSE context we're verifying against the PAE hash
	// This matches sigstore/cosign behavior
	if !ed25519.Verify(publicKey, hash, signature) {
		return ErrSignatureInvalid
	}
	return nil
}
