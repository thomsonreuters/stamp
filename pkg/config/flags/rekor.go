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
	"fmt"
	"strings"

	"github.com/thomsonreuters/stamp/pkg/types"
	plugincobra "github.com/thomsonreuters/stamp/plugins/cobra"
)

// RekorEnableFlags contains flags to enable/disable Rekor transparency logging.
var RekorEnableFlags = plugincobra.FlagGroup{
	"rekor": {
		Name:       "rekor",
		ConfigPath: TransparencyEnable,
		Type:       plugincobra.BoolFlag,
		Default:    true,
		Help:       "Upload attestations to Rekor transparency log (default: true; pass --rekor=false to disable)",
	},
}

// RekorServerFlags contains Rekor server configuration.
var RekorServerFlags = plugincobra.FlagGroup{
	"rekor-url": {
		Name:       "rekor-url",
		ConfigPath: RekorURL,
		Type:       plugincobra.StringFlag,
		Default:    "https://rekor.sigstore.dev",
		Help:       "Rekor server URL",
		Constraints: &plugincobra.FlagConstraints{
			RequiresTLS: true,
		},
	},
}

// RekorUploadFlags contains Rekor upload target configuration.
var RekorUploadFlags = plugincobra.FlagGroup{
	"rekor-upload": {
		Name:       "rekor-upload",
		ConfigPath: RekorUploadTarget,
		Type:       plugincobra.StringFlag,
		Default:    types.OutputModeIndividual.String(),
		Help:       fmt.Sprintf("Rekor upload target (%s)", strings.Join(types.ValidOutputModes, ", ")),
		Constraints: &plugincobra.FlagConstraints{
			ValidValues: types.ValidOutputModes,
		},
	},
}
