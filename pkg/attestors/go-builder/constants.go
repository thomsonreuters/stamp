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

package gobuilder

const (
	id          = "go-builder"
	name        = "Go Builder Attestor"
	description = "Generates SLSA provenance attestation for Go binary builds (auto-detects GitHub Actions and EC2; all other environments use generic mode)"

	// BuildTypeGolang is the build type URI for Go binary builds.
	BuildTypeGolang = "https://github.com/thomsonreuters/stamp/build/golang/v1"
)
