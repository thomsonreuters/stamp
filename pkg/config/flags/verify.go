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

// VerifyFlags contains verify command options for attestation signature verification.
var VerifyFlags = plugincobra.FlagGroup{
	"output-verification": {
		Name:       "output-verification",
		ShortName:  "o",
		ConfigPath: VerifyOutputFile,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Save detailed verification result to JSON file",
	},
	"expected-san": {
		Name:       "expected-san",
		ConfigPath: VerifyExpectedSAN,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Enforce this exact SubjectAlternativeName on the signing certificate (optional)",
	},
	"expected-san-regex": {
		Name:       "expected-san-regex",
		ConfigPath: VerifyExpectedSANRegex,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Enforce this regexp on the signing certificate SAN (optional)",
	},
	"expected-issuer": {
		Name:       "expected-issuer",
		ConfigPath: VerifyExpectedIssuer,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Enforce this exact OIDC issuer on the signing certificate (optional)",
	},
	"expected-issuer-regex": {
		Name:       "expected-issuer-regex",
		ConfigPath: VerifyExpectedIssuerRegex,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Enforce this regexp on the signing certificate OIDC issuer (optional)",
	},
	"public-key": {
		Name:       "public-key",
		ShortName:  "k",
		ConfigPath: VerifyPublicKey,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Public key PEM path for verifying key-signed bundles",
	},
}
