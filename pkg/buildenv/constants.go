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

package buildenv

const (
	// BuilderIDEC2 is the builder URI for EC2 environments.
	BuilderIDEC2 = "https://github.com/thomsonreuters/stamp/builders/ec2/v1"

	// BuilderIDGitHub is the builder URI for GitHub Actions environments.
	BuilderIDGitHub = "https://github.com/thomsonreuters/stamp/builders/github/v1"

	// BuilderIDGeneric is the builder URI for generic/unknown environments.
	BuilderIDGeneric = "https://github.com/thomsonreuters/stamp/builders/generic/v1"
)
