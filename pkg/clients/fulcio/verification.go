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
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"
	"time"

	"github.com/thomsonreuters/stamp/pkg/crypto/keys"
)

var (
	// OIDIssuerV2 is the OID for the OIDC issuer (v2 format with UTF8String).
	OIDIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}

	// OIDIssuerLegacy is the legacy OID for the OIDC issuer.
	OIDIssuerLegacy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
)

func (c *Client) VerifyCertificate(ctx context.Context, cert *x509.Certificate, maxCertValidityDuration time.Duration) error {
	if err := c.ValidateCertificateChain(ctx, cert); err != nil {
		return err
	}

	if err := c.ValidateTemporalValidity(cert, maxCertValidityDuration); err != nil {
		return err
	}

	if err := c.ValidateCodeSigningUsage(cert); err != nil {
		return err
	}

	if err := c.ValidateFulcioSpecificProperties(cert); err != nil {
		return err
	}

	return nil
}

func (c *Client) ValidateCertificateChain(ctx context.Context, cert *x509.Certificate) error {
	trustPool, err := c.GetTrustRoots(ctx)
	if err != nil {
		return err
	}
	opts := x509.VerifyOptions{
		Roots:       trustPool,
		CurrentTime: cert.NotBefore.Add(time.Second),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	_, err = cert.Verify(opts)
	return err
}

func (c *Client) ValidateTemporalValidity(cert *x509.Certificate, maxCertValidityDuration time.Duration) error {
	if cert.NotAfter.Before(cert.NotBefore) {
		return ErrInvalidValidityPeriod
	}

	validityDuration := cert.NotAfter.Sub(cert.NotBefore)
	if validityDuration > maxCertValidityDuration {
		return fmt.Errorf("%w: %v (max expected: %v)", ErrValidityPeriodTooLong, validityDuration, maxCertValidityDuration)
	}

	return nil
}

func (c *Client) ValidateCodeSigningUsage(cert *x509.Certificate) error {
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return ErrMissingDigitalSignature
	}

	problematicUsages := []x509.KeyUsage{
		x509.KeyUsageKeyEncipherment,
		x509.KeyUsageDataEncipherment,
		x509.KeyUsageKeyAgreement,
		x509.KeyUsageCertSign,
		x509.KeyUsageCRLSign,
	}
	for _, usage := range problematicUsages {
		if cert.KeyUsage&usage != 0 {
			return ErrInappropriateKeyUsage
		}
	}

	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
		return ErrMissingCodeSigningUsage
	}

	inappropriateExtUsages := []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageEmailProtection,
		x509.ExtKeyUsageOCSPSigning,
	}
	for _, inappropriate := range inappropriateExtUsages {
		if slices.Contains(cert.ExtKeyUsage, inappropriate) {
			return fmt.Errorf("%w: %v", ErrInappropriateExtKeyUsage, inappropriate)
		}
	}

	return nil
}

func (c *Client) ValidateFulcioSpecificProperties(cert *x509.Certificate) error {
	if len(cert.EmailAddresses) == 0 && len(cert.URIs) == 0 {
		return ErrMissingSANIdentity
	}

	return c.ValidateFulcioExtensions(cert)
}

func (c *Client) ValidateFulcioExtensions(cert *x509.Certificate) error {
	if !keys.HasCertificateExtension(cert, OIDIssuerV2) && !keys.HasCertificateExtension(cert, OIDIssuerLegacy) {
		return ErrMissingOIDCIssuer
	}

	return nil
}
