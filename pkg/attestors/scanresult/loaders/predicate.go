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

package loaders

import (
	"bytes"
	"encoding/json"
	"fmt"

	scanpredicate "github.com/thomsonreuters/stamp/pkg/predicates/scanresult/v1"
)

// predicateLoader ingests an already-built scan-result predicate. It is the
// backward-compatible default: the caller is responsible for the mapping and this
// loader only validates the JSON shape.
type predicateLoader struct{}

// Load decodes a ready predicate, failing closed on unknown fields so a producer's
// mapping mistakes surface instead of being silently dropped and signed away.
func (predicateLoader) Load(content []byte, _ Options) (scanpredicate.Predicate, error) {
	var p scanpredicate.Predicate
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return scanpredicate.Predicate{}, fmt.Errorf("failed to parse scan-result predicate JSON: %w", err)
	}
	return p, nil
}
