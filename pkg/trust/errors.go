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

import "errors"

var (
	ErrFulcioCertChainRequired = errors.New("trust: --fulcio-cert-chain required when --fulcio-url is set in explicit mode")
	ErrRekorKeyRequired        = errors.New("trust: --rekor-public-key required when --rekor-url is set in explicit mode")
	ErrTSACertRequired         = errors.New("trust: --tsa-cert-chain required when --tsa-url is set in explicit mode")

	ErrSigningConfigNeedsTUF    = errors.New("trust: --use-signing-config requires --tuf-url (or the embedded public sigstore TUF default)")
	ErrSigningConfigURLConflict = errors.New(
		"trust: explicit --fulcio-url/--rekor-url/--tsa-url cannot be combined with --use-signing-config or --signing-config; drop the explicit URL flags or set --use-signing-config=false",
	)
)
