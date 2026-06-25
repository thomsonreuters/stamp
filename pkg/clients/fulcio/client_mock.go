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
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
)

// MockClient is a mock implementation of ClientIface for testing.
// Use SetupMockClient to replace the global New function with this mock,
// allowing tests to control Fulcio client behavior without network calls.
type MockClient struct {
	mock.Mock
}

// GetCertificate mocks requesting a certificate from Fulcio.
func (m *MockClient) GetCertificate(ctx context.Context, req CertificateRequest) (*x509.Certificate, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(*x509.Certificate)
	return result, args.Error(1)
}

// FetchTrustBundle mocks fetching the trust bundle from Fulcio.
func (m *MockClient) FetchTrustBundle(ctx context.Context) (*TrustBundle, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(*TrustBundle)
	return result, args.Error(1)
}

// GetTrustRoots mocks fetching the trust roots as a CertPool from Fulcio.
func (m *MockClient) GetTrustRoots(ctx context.Context) (*x509.CertPool, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(*x509.CertPool)
	return result, args.Error(1)
}

// ValidateCertificateChain mocks validating the certificate chain.
func (m *MockClient) ValidateCertificateChain(ctx context.Context, cert *x509.Certificate) error {
	args := m.Called(ctx, cert)
	return args.Error(0)
}

// ValidateTemporalValidity mocks validating the temporal validity of the certificate.
func (m *MockClient) ValidateTemporalValidity(cert *x509.Certificate, maxCertValidityDuration time.Duration) error {
	args := m.Called(cert, maxCertValidityDuration)
	return args.Error(0)
}

// ValidateCodeSigningUsage mocks validating the code signing usage of the certificate.
func (m *MockClient) ValidateCodeSigningUsage(cert *x509.Certificate) error {
	args := m.Called(cert)
	return args.Error(0)
}

// ValidateFulcioSpecificProperties mocks validating the Fulcio specific properties of the certificate.
func (m *MockClient) ValidateFulcioSpecificProperties(cert *x509.Certificate) error {
	args := m.Called(cert)
	return args.Error(0)
}

// ValidateFulcioExtensions mocks validating the Fulcio extensions of the certificate.
func (m *MockClient) ValidateFulcioExtensions(cert *x509.Certificate) error {
	args := m.Called(cert)
	return args.Error(0)
}

// VerifyCertificate mocks validating a Fulcio certificate.
func (m *MockClient) VerifyCertificate(ctx context.Context, cert *x509.Certificate, maxCertValidityDuration time.Duration) error {
	args := m.Called(ctx, cert, maxCertValidityDuration)
	return args.Error(0)
}

// SetupMockClient replaces the global New function with a mock for testing.
func SetupMockClient(t *testing.T) *MockClient {
	t.Helper()

	mockClient := &MockClient{}

	original := New
	New = func(ctx context.Context, opts Options) (ClientIface, error) {
		return mockClient, nil
	}

	t.Cleanup(func() {
		New = original
	})

	return mockClient
}
