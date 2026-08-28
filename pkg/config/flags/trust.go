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

import plugincobra "github.com/thomsonreuters/stamp/plugins/cobra"

const DefaultTUFURL = "https://tuf-repo-cdn.sigstore.dev"

var TrustFlags = plugincobra.FlagGroup{
	"trusted-root": {
		Name:       "trusted-root",
		ConfigPath: TrustedRootPath,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Path to a sigstore trusted_root.json (mutually exclusive with --tuf-url). For fully offline operation, also pass --use-signing-config=false (or provide --signing-config=<path> to read signing config locally)",
	},
	"tuf-url": {
		Name:       "tuf-url",
		ConfigPath: TUFURL,
		Type:       plugincobra.StringFlag,
		Default:    DefaultTUFURL,
		Help:       "TUF repository base URL (defaults to public sigstore)",
		Constraints: &plugincobra.FlagConstraints{
			RequiresTLS: true,
		},
	},
	"tuf-root": {
		Name:       "tuf-root",
		ConfigPath: TUFRootPath,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Path OR https URL to a TUF root configuration file for bootstrapping trust (URL requires --tuf-root-checksum)",
	},
	"tuf-root-checksum": {
		Name:       "tuf-root-checksum",
		ConfigPath: TUFRootChecksum,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "SHA-256 hex digest of the TUF root fetched via --tuf-root=<URL>",
	},
	"fulcio-cert-chain": {
		Name:       "fulcio-cert-chain",
		ConfigPath: FulcioCertChain,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Path to Fulcio CA cert-chain PEM (required when configuring trust manually)",
	},
	"rekor-public-key": {
		Name:       "rekor-public-key",
		ConfigPath: RekorPublicKey,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Path to Rekor log public key PEM (required when configuring trust manually)",
	},
	"tsa-cert-chain": {
		Name:       "tsa-cert-chain",
		ConfigPath: TSACertChain,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Path to TSA cert-chain PEM (required when configuring trust manually)",
	},
	"signing-config": {
		Name:       "signing-config",
		ConfigPath: SigningConfigPath,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Path to a sigstore signing config file (mutually exclusive with --use-signing-config)",
	},
	"use-signing-config": {
		Name:       "use-signing-config",
		ConfigPath: UseSigningConfig,
		Type:       plugincobra.BoolFlag,
		Default:    true,
		Help:       "Fetch signing_config.v0.2.json from --tuf-url and use its service URLs (default true). Pass --use-signing-config=false to use explicit --fulcio-url/--rekor-url/--tsa-url flags instead.",
	},
}
