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

// VerifyFlags contains verify command options for attestation signature verification.
var VerifyFlags = plugincobra.FlagGroup{
	"public-key": {
		Name:       "public-key",
		ShortName:  "k",
		ConfigPath: VerifyPublicKey,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Path to public key file for signature verification (alternative to Fulcio certificate verification)",
	},
	"output-verification": {
		Name:       "output-verification",
		ShortName:  "o",
		ConfigPath: VerifyOutputFile,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Save detailed verification result to JSON file",
	},
	"rekor-temporal-policy": {
		Name:       "rekor-temporal-policy",
		ConfigPath: RekorTemporalPolicy,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       fmt.Sprintf("Temporal validation policy (%s; default: warn)", strings.Join(types.ValidTemporalPolicies, ", ")),
		Constraints: &plugincobra.FlagConstraints{
			ValidValues: types.ValidTemporalPolicies,
		},
	},
}
