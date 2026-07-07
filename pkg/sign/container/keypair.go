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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

// keypairAdapter adapts a stdlib crypto.Signer to sigstore-go's sign.Keypair:
// fills in the algorithm metadata and returns the digest alongside the
// signature that sign.Bundle expects.
type keypairAdapter struct {
	signer       crypto.Signer
	hint         []byte
	hashAlgo     crypto.Hash
	hashProto    protocommon.HashAlgorithm
	signingProto protocommon.PublicKeyDetails
	keyAlgo      string
	pubKeyPemStr string
}

func newKeypairAdapter(signer crypto.Signer, hint []byte) (*keypairAdapter, error) {
	pub := signer.Public()
	hashAlgo, hashProto, signingProto, keyAlgo, err := detectAlgorithms(pub)
	if err != nil {
		return nil, err
	}
	pemStr, err := publicKeyToPEM(pub)
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	return &keypairAdapter{
		signer:       signer,
		hint:         hint,
		hashAlgo:     hashAlgo,
		hashProto:    hashProto,
		signingProto: signingProto,
		keyAlgo:      keyAlgo,
		pubKeyPemStr: pemStr,
	}, nil
}

func (k *keypairAdapter) GetHashAlgorithm() protocommon.HashAlgorithm       { return k.hashProto }
func (k *keypairAdapter) GetSigningAlgorithm() protocommon.PublicKeyDetails { return k.signingProto }
func (k *keypairAdapter) GetHint() []byte                                   { return k.hint }
func (k *keypairAdapter) GetKeyAlgorithm() string                           { return k.keyAlgo }
func (k *keypairAdapter) GetPublicKey() crypto.PublicKey                    { return k.signer.Public() }
func (k *keypairAdapter) GetPublicKeyPem() (string, error)                  { return k.pubKeyPemStr, nil }

func (k *keypairAdapter) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	hasher := k.hashAlgo.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)
	sig, err := k.signer.Sign(rand.Reader, digest, k.hashAlgo)
	if err != nil {
		return nil, nil, fmt.Errorf("sign: %w", err)
	}
	return sig, digest, nil
}

// detectAlgorithms returns the (hash, signing-algo, key-algo) triple
// advertised in the bundle. Verifiers use these to hash the payload the
// same way the signer did — a mismatch (e.g. claiming SHA-384 while
// signing SHA-256) produces unverifiable bundles.
func detectAlgorithms(pub crypto.PublicKey) (crypto.Hash, protocommon.HashAlgorithm, protocommon.PublicKeyDetails, string, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return crypto.SHA256, protocommon.HashAlgorithm_SHA2_256,
				protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256, "ECDSA", nil
		case elliptic.P384():
			return crypto.SHA384, protocommon.HashAlgorithm_SHA2_384,
				protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384, "ECDSA", nil
		case elliptic.P521():
			return crypto.SHA512, protocommon.HashAlgorithm_SHA2_512,
				protocommon.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512, "ECDSA", nil
		default:
			return 0, 0, 0, "", fmt.Errorf("unsupported ECDSA curve %q", k.Params().Name)
		}
	case *rsa.PublicKey:
		bits := k.Size() * 8
		switch bits {
		case 2048:
			return crypto.SHA256, protocommon.HashAlgorithm_SHA2_256,
				protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256, "RSA", nil
		case 3072:
			return crypto.SHA256, protocommon.HashAlgorithm_SHA2_256,
				protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256, "RSA", nil
		case 4096:
			return crypto.SHA256, protocommon.HashAlgorithm_SHA2_256,
				protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256, "RSA", nil
		default:
			return 0, 0, 0, "", fmt.Errorf("unsupported RSA key size: %d bits", bits)
		}
	default:
		return 0, 0, 0, "", fmt.Errorf("unsupported public key type %T", pub)
	}
}

func publicKeyToPEM(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}
