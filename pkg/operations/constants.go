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

package operations

// File size limits for validation.
const (
	// MaxAttestationFileSize is the maximum allowed size for attestation files (50MB).
	MaxAttestationFileSize = 50 * 1024 * 1024

	// MaxPublicKeyFileSize is the maximum allowed size for public key files (64KB).
	MaxPublicKeyFileSize = 64 * 1024
)
