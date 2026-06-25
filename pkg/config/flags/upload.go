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

package flags

import (
	plugincobra "github.com/thomsonreuters/stamp/plugins/cobra"
)

// UploadFlags contains upload command options for uploading attestations to Rekor.
var UploadFlags = plugincobra.FlagGroup{
	"public-key": {
		Name:       "public-key",
		ShortName:  "k",
		ConfigPath: UploadPublicKey,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Path to public key file (required for file-based signatures, not needed for certificate-based)",
	},
}
