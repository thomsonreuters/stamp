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
	"errors"
	"fmt"

	"github.com/thomsonreuters/stamp/pkg/signing/sigstore"
)

// Options for Signer.Sign. A nil Registry falls back to the Docker
// keychain (which handles anonymous pulls of public images).
type Options struct {
	sigstore.Options
	Registry *RegistryOptions
}

type RegistryOptions struct {
	Username string
	Password string
}

type Result struct {
	sigstore.Result
	// Digest is the resolved image manifest digest (e.g. "sha256:abc...").
	Digest string
}

func (o *Options) validate() error {
	if err := o.Options.Validate(); err != nil {
		return fmt.Errorf("container sign: %w", err)
	}
	// Registry is optional (anonymous / keychain fallback); reject only
	// the half-set case, which would produce a malformed Basic Auth header.
	if o.Registry != nil && (o.Registry.Username == "") != (o.Registry.Password == "") {
		return errors.New("container sign: Registry.Username and Registry.Password must be set together")
	}
	return nil
}
