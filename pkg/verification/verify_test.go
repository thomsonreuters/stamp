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

package verification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
)

// TestVerify_NoTrustedMaterial asserts Verify returns an error when it is
// called without any trust root.
func TestVerify_NoTrustedMaterial(t *testing.T) {
	result, err := Verify(nil, nil, Config{})
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no trusted material")
}

// TestVerify_NilBundle asserts Verify returns an error when given trust
// material but no bundle to check it against.
func TestVerify_NilBundle(t *testing.T) {
	result, err := Verify(&root.BaseTrustedMaterial{}, nil, Config{})
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "bundle is nil")
}

// TestVerify_Success exercises the raw-key happy path end to end: an
// ephemeral keypair signs a DSSE envelope into a bundle with no certificate
// and no transparency log entry, and a trust material mocked to recognize
// that same keypair's public key (regardless of hint) verifies it.
func TestVerify_Success(t *testing.T) {
	kp, err := sign.NewEphemeralKeypair(nil)
	require.NoError(t, err)

	content := &sign.DSSEData{
		Data:        []byte(`{"_type":"https://in-toto.io/Statement/v1"}`),
		PayloadType: "application/vnd.in-toto+json",
	}
	pbBundle, err := sign.Bundle(content, kp, sign.BundleOptions{})
	require.NoError(t, err)

	b, err := bundle.NewBundle(pbBundle)
	require.NoError(t, err)

	verifier, err := signature.LoadDefaultVerifier(kp.GetPublicKey())
	require.NoError(t, err)
	tm := root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
		return root.NewExpiringKey(verifier, time.Time{}, time.Time{}), nil
	})

	result, err := Verify(tm, b, Config{})
	require.NoError(t, err)
	require.NotNil(t, result)
}

// TestCheckMaxCertValidity_RejectsLongLivedCert asserts checkMaxCertValidity
// rejects a self-signed certificate whose validity window exceeds stamp's
// 24h ceiling, using a synthetic cert built in-process rather than a real
// Fulcio-issued one.
func TestCheckMaxCertValidity_RejectsLongLivedCert(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	notBefore := time.Now()
	notAfter := notBefore.Add(48 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "stamp-test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	b := &bundle.Bundle{
		Bundle: &protobundle.Bundle{
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_Certificate{
					Certificate: &protocommon.X509Certificate{RawBytes: der},
				},
			},
		},
	}

	err = checkMaxCertValidity(b)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate validity too long")
}
