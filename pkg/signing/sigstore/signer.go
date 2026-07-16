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

// Package sigstore produces sigstore Bundle v0.3 signatures over arbitrary
// payloads. Callers supply the payload and payloadType (typically an
// in-toto Statement with application/vnd.in-toto+json); the package handles
// keypair adaptation, Fulcio certificate issuance, Rekor entry submission,
// and bundle serialization.
package sigstore

import (
	"context"
	"fmt"
	"strings"

	sigstorebundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"google.golang.org/protobuf/encoding/protojson"
)

// Signer is safe to reuse across many SignBundle calls; per-call config
// (key material, Fulcio token, Rekor URL) lives in Options.
type Signer struct {
	logger logger.Logger
}

func NewSigner(log logger.Logger) *Signer {
	return &Signer{logger: log}
}

// SignBundle signs payload with the material specified by opts and returns
// a sigstore Bundle v0.3. payloadType is the DSSE payload type, e.g.
// intoto.PayloadType ("application/vnd.in-toto+json").
func (s *Signer) SignBundle(ctx context.Context, payload []byte, payloadType string, opts Options) (*Result, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	keypair, certProvider, certOpts, err := opts.BuildSigningMaterial()
	if err != nil {
		return nil, err
	}

	bundleOpts := sign.BundleOptions{
		Context:                    ctx,
		CertificateProvider:        certProvider,
		CertificateProviderOptions: certOpts,
	}
	if opts.Rekor != nil {
		bundleOpts.TransparencyLogs = []sign.Transparency{
			sign.NewRekor(&sign.RekorOptions{
				BaseURL: opts.Rekor.URL,
			}),
		}
	}

	s.logger.InfoContext(ctx, "signing bundle",
		"keyless", opts.Fulcio != nil,
		"rekor", opts.Rekor != nil,
		"payload_type", payloadType,
	)

	b, err := sign.Bundle(&sign.DSSEData{Data: payload, PayloadType: payloadType}, keypair, bundleOpts)
	if err != nil {
		return nil, wrapSignBundleError(err, opts.Rekor != nil)
	}
	// Round-trip parse to catch malformed bundles before we hand them out.
	if _, verr := sigstorebundle.NewBundle(b); verr != nil {
		return nil, fmt.Errorf("sigstore sign: bundle validation: %w", verr)
	}

	data, err := protojson.MarshalOptions{Indent: "  "}.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("sigstore sign: marshal bundle: %w", err)
	}

	return &Result{
		Bundle:     b,
		BundleJSON: data,
	}, nil
}

// wrapSignBundleError translates sigstore-go's cryptic TextConsumer
// failure — raised when Rekor returns non-JSON (e.g. a policy denial) —
// into an actionable message.
func wrapSignBundleError(err error, rekorEnabled bool) error {
	if rekorEnabled && strings.Contains(err.Error(), "TextConsumer") {
		return fmt.Errorf(
			"sigstore sign: Rekor rejected the upload with a non-JSON response; "+
				"the server may enforce a policy this signer does not satisfy "+
				"(e.g. keyless-only). Try --signer fulcio, or --rekor=false to "+
				"skip Rekor. Underlying error: %w", err)
	}
	return fmt.Errorf("sigstore sign: sign.Bundle: %w", err)
}
