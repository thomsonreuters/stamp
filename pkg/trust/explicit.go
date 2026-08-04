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
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/root"
)

type explicitResolver struct {
	opts Options
}

func (r *explicitResolver) Resolve(_ context.Context) (*root.TrustedRoot, error) {
	var cas []root.CertificateAuthority
	var tsas []root.TimestampingAuthority
	tlogs := map[string]*root.TransparencyLog{}

	if r.opts.FulcioURL != "" {
		ca, err := loadFulcioCA(r.opts.FulcioCertChainPath, r.opts.FulcioURL)
		if err != nil {
			return nil, fmt.Errorf("trust: fulcio: %w", err)
		}
		cas = append(cas, ca)
	}

	if r.opts.RekorURL != "" {
		tlog, err := loadRekorTLog(r.opts.RekorPublicKeyPath, r.opts.RekorURL)
		if err != nil {
			return nil, fmt.Errorf("trust: rekor: %w", err)
		}
		tlogs[hex.EncodeToString(tlog.ID)] = tlog
	}

	if r.opts.TSAURL != "" {
		tsa, err := loadTSA(r.opts.TSACertChainPath, r.opts.TSAURL)
		if err != nil {
			return nil, fmt.Errorf("trust: tsa: %w", err)
		}
		tsas = append(tsas, tsa)
	}

	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01, cas, nil, tsas, tlogs)
	if err != nil {
		return nil, fmt.Errorf("trust: assemble trusted root: %w", err)
	}
	return tr, nil
}

// PEM chain: last cert = Root, preceding = Intermediates.
func loadFulcioCA(path, url string) (root.CertificateAuthority, error) {
	certs, err := parseCertChain(path)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %q", path)
	}
	return &root.FulcioCertificateAuthority{
		Root:          certs[len(certs)-1],
		Intermediates: certs[:len(certs)-1],
		URI:           url,
	}, nil
}

// Log ID = SHA-256(DER SPKI), per sigstore convention.
func loadRekorTLog(path, url string) (*root.TransparencyLog, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %q", path)
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key from %q: %w", path, err)
	}
	sum := sha256.Sum256(block.Bytes)
	return &root.TransparencyLog{
		BaseURL:           url,
		ID:                sum[:],
		HashFunc:          crypto.SHA256,
		PublicKey:         pubKey,
		SignatureHashFunc: crypto.SHA256,
	}, nil
}

// PEM chain: first cert = Leaf, last = Root, middle = Intermediates.
func loadTSA(path, url string) (root.TimestampingAuthority, error) {
	certs, err := parseCertChain(path)
	if err != nil {
		return nil, err
	}
	if len(certs) < 2 {
		return nil, fmt.Errorf("tsa chain in %q needs at least leaf+root, got %d certificate(s)", path, len(certs))
	}
	tsa := &root.SigstoreTimestampingAuthority{
		Leaf: certs[0],
		Root: certs[len(certs)-1],
		URI:  url,
	}
	if len(certs) > 2 {
		tsa.Intermediates = certs[1 : len(certs)-1]
	}
	return tsa, nil
}

func parseCertChain(path string) ([]*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate from %q: %w", path, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks in %q", path)
	}
	return certs, nil
}
