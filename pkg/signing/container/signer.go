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

// Package container signs container images and returns a sigstore Bundle v0.3.
package container

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/signing/sigstore"
)

// CosignPredicateType is cosign's predicate URI for simple container
// signatures (no semantic payload).
const CosignPredicateType = "https://sigstore.dev/cosign/sign/v1"

// Signer is safe to reuse across many Sign calls; registry credentials
// are supplied per-call via Options.Registry.
type Signer struct {
	sigstore *sigstore.Signer
	logger   logger.Logger
}

func NewSigner(log logger.Logger) *Signer {
	return &Signer{
		sigstore: sigstore.NewSigner(log),
		logger:   log,
	}
}

func (s *Signer) Sign(ctx context.Context, imageRef string, opts Options) (*Result, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("container sign: parse reference %q: %w", imageRef, err)
	}

	s.logger.InfoContext(ctx, "fetching image descriptor", "image", imageRef)
	// Fall back to the Docker keychain (which covers anonymous access for
	// public registries) when no explicit creds were provided. Treat an
	// empty struct the same as nil: Options.validate already accepts it,
	// so signing empty must not send `Authorization: Basic Og==`.
	remoteOpts := []remote.Option{remote.WithContext(ctx)}
	if hasExplicitRegistryCreds(opts.Registry) {
		remoteOpts = append(remoteOpts, remote.WithAuth(authn.FromConfig(authn.AuthConfig{
			Username: opts.Registry.Username,
			Password: opts.Registry.Password,
		})))
	} else {
		remoteOpts = append(remoteOpts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}
	desc, err := remote.Get(ref, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("container sign: fetch %s: %w", imageRef, err)
	}
	digest := desc.Digest

	payload, err := buildStatementPayload(ref, digest.Algorithm, digest.Hex)
	if err != nil {
		return nil, err
	}

	s.logger.InfoContext(ctx, "signing container",
		"image", imageRef,
		"digest", digest.String(),
		"keyless", opts.Fulcio != nil,
		"rekor", opts.Rekor != nil,
	)

	sigRes, err := s.sigstore.SignBundle(ctx, payload, intoto.PayloadType, opts.Options)
	if err != nil {
		return nil, fmt.Errorf("container sign: %w", err)
	}

	return &Result{
		Result: *sigRes,
		Digest: digest.String(),
	}, nil
}

// hasExplicitRegistryCreds reports whether the caller provided a
// populated Registry (both fields non-empty). Options.validate accepts a
// nil pointer OR an empty struct as "no creds provided", so both must
// route to the keychain fallback; only a truly populated struct sends
// Basic Auth.
func hasExplicitRegistryCreds(r *RegistryOptions) bool {
	return r != nil && r.Username != "" && r.Password != ""
}

// buildStatementPayload emits a cosign-shaped in-toto Statement: empty
// predicate, single subject = image name + manifest digest.
func buildStatementPayload(ref name.Reference, digestAlgo, digestHex string) ([]byte, error) {
	stmt := &intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: CosignPredicateType,
		Subject: []intoto.Subject{{
			Name:   ref.Context().Name(),
			Digest: map[string]string{digestAlgo: digestHex},
		}},
		Predicate: json.RawMessage(`{}`),
	}
	payload, err := stmt.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("container sign: marshal statement: %w", err)
	}
	return payload, nil
}
