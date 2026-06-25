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

// Package keys provides utilities for loading, parsing, and managing cryptographic keys.
package keys

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"go.step.sm/crypto/pemutil"
)

// PEM block type constants.
const (
	PEMTypePKCS8          = "PRIVATE KEY"
	PEMTypePKCS8Encrypted = "ENCRYPTED PRIVATE KEY"
	PEMTypePKCS1RSA       = "RSA PRIVATE KEY"
	PEMTypeSEC1EC         = "EC PRIVATE KEY"
	PEMTypePublicKey      = "PUBLIC KEY"
	PEMTypeRSAPublicKey   = "RSA PUBLIC KEY"
	PEMTypeCertificate    = "CERTIFICATE"
)

var (
	ErrUnsupportedKeyType  = errors.New("unsupported key type")
	ErrMissingPassword     = errors.New("missing password")
	ErrDecryptionFailed    = errors.New("decryption failed")
	ErrLegacyEncryption    = errors.New("legacy PEM encryption (RFC 1423) is not supported due to security vulnerabilities")
	ErrCertificateParse    = errors.New("failed to parse certificate")
	ErrCertificateNotFound = errors.New("no certificate found in data")
)

// LoadedKey contains the result of loading a private key.
type LoadedKey struct {
	PrivateKey  crypto.PrivateKey
	IsEncrypted bool
}

// LoadPrivateKeyFromFile loads a private key from a file path.
func LoadPrivateKeyFromFile(path, password string) (*LoadedKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadPrivateKeyFromPEM(data, password, path)
}

// LoadPrivateKeyFromPEM loads a private key from PEM-encoded bytes.
func LoadPrivateKeyFromPEM(data []byte, password, source string) (*LoadedKey, error) {
	block, err := decodePEM(data, source)
	if err != nil {
		return nil, err
	}

	keyBytes, isEncrypted, err := decryptIfNeeded(block, password)
	if err != nil {
		return nil, err
	}

	var privateKey crypto.PrivateKey

	switch block.Type {
	case PEMTypePKCS8, PEMTypePKCS8Encrypted:
		privateKey, err = x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}

	case PEMTypePKCS1RSA:
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}

	case PEMTypeSEC1EC:
		privateKey, err = x509.ParseECPrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}

	default:
		return nil, ErrUnsupportedKeyType
	}

	return &LoadedKey{
		PrivateKey:  privateKey,
		IsEncrypted: isEncrypted,
	}, nil
}

// LoadPublicKeyFromFile loads a public key from a file path.
func LoadPublicKeyFromFile(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadPublicKeyFromPEM(data, path)
}

// LoadPublicKeyFromPEM loads a public key from PEM-encoded bytes.
func LoadPublicKeyFromPEM(data []byte, source string) (crypto.PublicKey, error) {
	block, err := decodePEM(data, source)
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case PEMTypePublicKey:
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return publicKey, nil

	case PEMTypeRSAPublicKey:
		publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return publicKey, nil

	case PEMTypeCertificate:
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil

	default:
		return nil, ErrUnsupportedKeyType
	}
}

// ParseCertificateFromBytes parses a certificate from raw bytes.
func ParseCertificateFromBytes(data []byte) (*x509.Certificate, error) {
	if cert, err := x509.ParseCertificate(data); err == nil {
		return cert, nil
	}

	if certs, err := x509.ParseCertificates(data); err == nil && len(certs) > 0 {
		return certs[0], nil
	}

	if cert := parsePEMCertificate(data); cert != nil {
		return cert, nil
	}

	return nil, ErrCertificateParse
}

// ParseCertificateChainFromBytes parses all certificates from raw bytes.
func ParseCertificateChainFromBytes(data []byte) ([]*x509.Certificate, error) {
	if certs, err := x509.ParseCertificates(data); err == nil && len(certs) > 0 {
		return certs, nil
	}

	if certs := parsePEMCertificateChain(data); len(certs) > 0 {
		return certs, nil
	}

	return nil, ErrCertificateParse
}

// parsePEMCertificate parses a PEM-encoded certificate.
// For certificate chains, returns the first (leaf) certificate.
func parsePEMCertificate(data []byte) *x509.Certificate {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}

	if block.Type == PEMTypeCertificate {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			return cert
		}
	}

	return nil
}

// parsePEMCertificateChain parses all PEM-encoded certificates from data.
func parsePEMCertificateChain(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	remaining := data

	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type == PEMTypeCertificate {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, cert)
			}
		}

		remaining = rest
	}

	return certs
}

func decodePEM(data []byte, source string) (*pem.Block, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", source)
	}
	return block, nil
}

func decryptIfNeeded(block *pem.Block, password string) ([]byte, bool, error) {
	if block.Type == PEMTypePKCS8Encrypted {
		if password == "" {
			return nil, true, ErrMissingPassword
		}
		decrypted, err := pemutil.DecryptPKCS8PrivateKey(block.Bytes, []byte(password))
		if err != nil {
			return nil, true, ErrDecryptionFailed
		}
		return decrypted, true, nil
	}

	if len(block.Headers) > 0 {
		if _, ok := block.Headers["Proc-Type"]; ok {
			return nil, false, ErrLegacyEncryption
		}
	}

	return block.Bytes, false, nil
}

func HasCertificateExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}
