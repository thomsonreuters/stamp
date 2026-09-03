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

package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeSelfSignedCertPEM(t *testing.T, cn string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func makePubKeyPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func writePEM(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestExplicitResolver_HappyPath(t *testing.T) {
	fulcioChain := append(makeSelfSignedCertPEM(t, "fulcio-intermediate"),
		makeSelfSignedCertPEM(t, "fulcio-root")...)
	tsaChain := append(append(
		makeSelfSignedCertPEM(t, "tsa-leaf"),
		makeSelfSignedCertPEM(t, "tsa-intermediate")...),
		makeSelfSignedCertPEM(t, "tsa-root")...)
	rekorPub := makePubKeyPEM(t)

	r := &explicitResolver{opts: Options{
		FulcioURL:           "https://fulcio.example.com",
		FulcioCertChainPath: writePEM(t, "fulcio.pem", fulcioChain),
		RekorURL:            "https://rekor.example.com",
		RekorPublicKeyPath:  writePEM(t, "rekor.pub", rekorPub),
		TSAURL:              "https://tsa.example.com",
		TSACertChainPath:    writePEM(t, "tsa.pem", tsaChain),
	}}

	tr, err := r.Resolve(context.Background())
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.Len(t, tr.FulcioCertificateAuthorities(), 1)
	assert.Len(t, tr.TimestampingAuthorities(), 1)
	assert.Len(t, tr.RekorLogs(), 1)
	assert.Empty(t, tr.CTLogs())
}

func TestExplicitResolver_FulcioOnly(t *testing.T) {
	chain := makeSelfSignedCertPEM(t, "fulcio-root")
	r := &explicitResolver{opts: Options{
		FulcioURL:           "https://fulcio.example.com",
		FulcioCertChainPath: writePEM(t, "fulcio.pem", chain),
	}}
	tr, err := r.Resolve(context.Background())
	require.NoError(t, err)
	assert.Len(t, tr.FulcioCertificateAuthorities(), 1)
	assert.Empty(t, tr.RekorLogs())
	assert.Empty(t, tr.TimestampingAuthorities())
}

func TestExplicitResolver_MissingFile(t *testing.T) {
	r := &explicitResolver{opts: Options{
		FulcioURL:           "https://fulcio.example.com",
		FulcioCertChainPath: "/nonexistent/fulcio.pem",
	}}
	_, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read")
}

func TestExplicitResolver_MalformedPEM(t *testing.T) {
	path := writePEM(t, "junk.pem", []byte("not a PEM block"))
	r := &explicitResolver{opts: Options{
		FulcioURL:           "https://fulcio.example.com",
		FulcioCertChainPath: path,
	}}
	_, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no CERTIFICATE blocks")
}

func TestExplicitResolver_TSAChainTooShort(t *testing.T) {
	oneCert := makeSelfSignedCertPEM(t, "solo")
	r := &explicitResolver{opts: Options{
		TSAURL:           "https://tsa.example.com",
		TSACertChainPath: writePEM(t, "tsa.pem", oneCert),
	}}
	_, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "leaf+root")
}

func TestExplicitResolver_RekorLogIDIsSHA256OfSPKI(t *testing.T) {
	pub := makePubKeyPEM(t)
	r := &explicitResolver{opts: Options{
		RekorURL:           "https://rekor.example.com",
		RekorPublicKeyPath: writePEM(t, "rekor.pub", pub),
	}}
	tr, err := r.Resolve(context.Background())
	require.NoError(t, err)
	logs := tr.RekorLogs()
	require.Len(t, logs, 1)
	for _, log := range logs {
		assert.Len(t, log.ID, 32, "log ID should be SHA-256 digest = 32 bytes")
	}
}
