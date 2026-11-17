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

package v1

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// RecordLookupKey derives a stable index key for the platform onboarding
// record identified by immutable repository ID and full branch ref. The key
// is only an index hint; the matching signed onboarding attestation remains
// the source of truth.
func RecordLookupKey(repositoryID int64, branchRef string) (string, error) {
	if repositoryID <= 0 {
		return "", errors.New("source-onboarding: repository ID must be positive")
	}
	if !branchPattern.MatchString(branchRef) || strings.TrimSpace(branchRef) != branchRef {
		return "", errors.New("source-onboarding: branch must be a full refs/heads/... ref")
	}

	branchHash := sha256.Sum256([]byte(branchRef))
	return fmt.Sprintf("source-onboarding-%d-%s", repositoryID, hex.EncodeToString(branchHash[:])), nil
}
