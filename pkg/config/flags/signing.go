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

// SigningFlags contains cryptographic signing operations (signer selection and OIDC tokens).
var SigningFlags = plugincobra.FlagGroup{
	"signer": {
		Name:       "signer",
		ShortName:  "s",
		ConfigPath: Signer,
		Type:       plugincobra.StringFlag,
		Default:    "fulcio",
		Help:       fmt.Sprintf("Signing backend (%s)", strings.Join(types.ValidSigners, ", ")),
		Constraints: &plugincobra.FlagConstraints{
			ValidValues: types.ValidSigners,
		},
	},
	"oidc-token": {
		Name:       "oidc-token",
		ShortName:  "t",
		ConfigPath: OIDCToken,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "OIDC token string (mutually exclusive with other token options)",
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"oidc-token-file", "spire", "github"},
		},
	},
	"oidc-token-file": {
		Name:       "oidc-token-file",
		ShortName:  "f",
		ConfigPath: OIDCTokenFile,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Path to file containing OIDC token (mutually exclusive with other token options)",
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"oidc-token", "spire", "github"},
		},
	},
	"spire": {
		Name:       "spire",
		ConfigPath: UseSpire,
		Type:       plugincobra.BoolFlag,
		Default:    false,
		Help:       "Use SPIRE workload API for OIDC token (mutually exclusive with other token options)",
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"oidc-token", "oidc-token-file", "github"},
		},
	},
	"socket": {
		Name:                "socket",
		ConfigPath:          SPIRESocket,
		Type:                plugincobra.StringFlag,
		Default:             "",
		EnvironmentVariable: "SPIFFE_ENDPOINT_SOCKET",
		Help:                "Path to SPIRE Agent socket (implies SPIRE workload API, mutually exclusive with other token options)",
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"oidc-token", "oidc-token-file", "github"},
		},
	},
	"github": {
		Name:       "github",
		ConfigPath: UseGitHub,
		Type:       plugincobra.BoolFlag,
		Default:    false,
		Help:       "Use GitHub Actions OIDC token",
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"oidc-token", "oidc-token-file", "spire"},
		},
	},
}
