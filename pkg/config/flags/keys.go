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

// PasswordFlags contains private key password handling options.
var PasswordFlags = plugincobra.FlagGroup{
	"password": {
		Name:       "password",
		ConfigPath: CryptographyKeyPassword,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Password for encrypted private key (not recommended, use env var or prompt)",
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"password-file", "prompt"},
		},
	},
	"password-file": {
		Name:       "password-file",
		ConfigPath: CryptographyKeyPasswordFile,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Path to file containing password for encrypted private key",
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"password", "prompt"},
		},
	},
	"prompt": {
		Name:       "prompt",
		ConfigPath: CryptographyKeyPasswordPrompt,
		Type:       plugincobra.BoolFlag,
		Default:    false,
		Help:       "Prompt for private key password if encrypted",
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"password", "password-file"},
		},
	},
}

// PrivateKeyFlags contains private key handling options.
var PrivateKeyFlags = plugincobra.FlagGroup{
	"private-key": {
		Name:       "private-key",
		ShortName:  "k",
		ConfigPath: PrivateKey,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Private key file path (required for signing operations with 'key' signer)",
	},
}

// PublicKeyFlags contains public key handling options.
var PublicKeyFlags = plugincobra.FlagGroup{
	"public-key": {
		Name:       "public-key",
		ConfigPath: PublicKey,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Public key file path (required for transparency operations)",
	},
}
