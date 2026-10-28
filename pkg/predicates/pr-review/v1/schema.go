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

import "github.com/invopop/jsonschema"

// Schema returns the JSON schema for the pr-review/v1 predicate.
func Schema() *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		AllowAdditionalProperties:  false,
		RequiredFromJSONSchemaTags: true,
	}
	schema := reflector.Reflect(&Predicate{})
	schema.Title = "Pull Request Review Attestation"
	schema.Description = "Evidence that a merged GitHub pull request was reviewed under the rulesets that applied to its base branch"
	return schema
}
