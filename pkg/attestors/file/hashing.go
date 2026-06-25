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

package file

import (
	"context"
	"sort"
	"strings"

	filepredicate "github.com/thomsonreuters/stamp/pkg/predicates/file/v1"
)

// generateManifestDigest creates a digest representing all collected artifacts.
func (a *Attestor) generateManifestDigest() map[string]string {
	sortedArtifacts := make([]filepredicate.ArtifactInfo, len(a.artifacts))
	copy(sortedArtifacts, a.artifacts)
	sort.Slice(sortedArtifacts, func(i, j int) bool {
		return sortedArtifacts[i].Path < sortedArtifacts[j].Path
	})

	var manifestBuilder strings.Builder
	for _, artifact := range sortedArtifacts {
		manifestBuilder.WriteString(artifact.Path)
		manifestBuilder.WriteByte(0)

		for _, alg := range a.config.HashAlgorithms {
			if digest, ok := artifact.Digests[alg]; ok {
				manifestBuilder.WriteString(digest)
				manifestBuilder.WriteByte(0)
			}
		}
	}

	hashResult, err := a.hasher.HashBytes(context.Background(), []byte(manifestBuilder.String()), "manifest")
	if err != nil {
		a.logger.Warn("failed to generate manifest digest", "error", err.Error())
		return make(map[string]string)
	}

	if hashResult.Error != nil {
		a.logger.Warn("manifest hash result contains error", "error", hashResult.Error.Error())
		return make(map[string]string)
	}

	return hashResult.Digests
}
