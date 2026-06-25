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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"go.step.sm/crypto/pemutil"
)

// Key algorithm constants.
const (
	AlgorithmRSA   = "rsa"
	AlgorithmECDSA = "ecdsa"

	DefaultRSAKeySize = 2048
)

// GenerateOptions configures key pair generation.
type GenerateOptions struct {
	Algorithm  string // rsa, ecdsa
	RSAKeySize int    // default: 2048
	Overwrite  bool   // overwrite existing files
	Password   string // encrypt private key (empty = no encryption)
}

// GeneratedKeyPair contains paths to the generated key files.
type GeneratedKeyPair struct {
	PrivateKeyPath string
	PublicKeyPath  string
}

// Generate creates a new private key of the specified algorithm.
func Generate(algorithm string) (crypto.PrivateKey, error) {
	switch strings.ToLower(algorithm) {
	case AlgorithmRSA:
		return GenerateRSA(DefaultRSAKeySize)
	case AlgorithmECDSA:
		return GenerateECDSA()
	default:
		return nil, pkgerrors.NewWithContext("keys", "generate", fmt.Sprintf("unsupported algorithm: %s (supported: rsa, ecdsa)", algorithm))
	}
}

// GenerateRSA creates a new RSA private key with the specified bit size.
func GenerateRSA(bits int) (*rsa.PrivateKey, error) {
	if bits < DefaultRSAKeySize {
		return nil, pkgerrors.NewWithContext("keys", "generate", "RSA key size must be at least 2048 bits")
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "keys", "generate", "failed to generate RSA key")
	}
	return key, nil
}

// GenerateECDSA creates a new ECDSA private key on P-256 curve.
func GenerateECDSA() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "keys", "generate", "failed to generate ECDSA key")
	}
	return key, nil
}

// GenerateToFile generates a key pair and saves to files.
// Returns paths to the generated private and public key files.
func GenerateToFile(basePath string, opts GenerateOptions) (*GeneratedKeyPair, error) {
	if opts.Algorithm == "" {
		opts.Algorithm = AlgorithmECDSA
	}

	privateKey, err := Generate(opts.Algorithm)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(basePath), 0755); err != nil {
		return nil, pkgerrors.WrapWithContext(err, "keys", "mkdir", "failed to create directory")
	}

	base := strings.TrimSuffix(basePath, filepath.Ext(basePath))
	privateKeyPath := base + ".key"
	publicKeyPath := base + ".pub"

	if !opts.Overwrite {
		if _, err := os.Stat(privateKeyPath); err == nil {
			return nil, pkgerrors.NewWithContext("keys", "check", fmt.Sprintf("file already exists: %s", privateKeyPath))
		}
		if _, err := os.Stat(publicKeyPath); err == nil {
			return nil, pkgerrors.NewWithContext("keys", "check", fmt.Sprintf("file already exists: %s", publicKeyPath))
		}
	}

	if err := writePrivateKeyFile(privateKeyPath, privateKey, opts.Password, opts.Overwrite); err != nil {
		return nil, err
	}

	if err := writePublicKeyFile(publicKeyPath, privateKey, opts.Overwrite); err != nil {
		_ = os.Remove(privateKeyPath)
		return nil, err
	}

	return &GeneratedKeyPair{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
	}, nil
}

func writePrivateKeyFile(path string, key crypto.PrivateKey, password string, overwrite bool) error {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "keys", "marshal", "failed to marshal private key")
	}

	var pemBlock *pem.Block
	if password != "" {
		pemBlock, err = pemutil.EncryptPKCS8PrivateKey(rand.Reader, keyBytes, []byte(password), x509.PEMCipherAES256)
		if err != nil {
			return pkgerrors.WrapWithContext(err, "keys", "encrypt", "failed to encrypt private key")
		}
	} else {
		pemBlock = &pem.Block{Type: PEMTypePKCS8, Bytes: keyBytes}
	}

	return writePEMFile(path, pemBlock, 0600, overwrite)
}

func writePublicKeyFile(path string, privateKey crypto.PrivateKey, overwrite bool) error {
	publicKey, err := ExtractPublicKey(privateKey)
	if err != nil {
		return err
	}

	keyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "keys", "marshal", "failed to marshal public key")
	}

	pemBlock := &pem.Block{Type: PEMTypePublicKey, Bytes: keyBytes}
	return writePEMFile(path, pemBlock, 0644, overwrite)
}

func writePEMFile(path string, block *pem.Block, perm os.FileMode, overwrite bool) error {
	flags := os.O_WRONLY | os.O_CREATE
	if overwrite {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}

	file, err := os.OpenFile(path, flags, perm)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "keys", "write", fmt.Sprintf("failed to create file: %s", path))
	}
	defer func() { _ = file.Close() }()

	if err := pem.Encode(file, block); err != nil {
		return pkgerrors.WrapWithContext(err, "keys", "write", "failed to write PEM data")
	}
	return nil
}
