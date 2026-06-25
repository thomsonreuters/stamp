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

// FetchFlags contains fetch command options for retrieving attestations from Rekor.
var FetchFlags = plugincobra.FlagGroup{
	"file": {
		Name:       "file",
		ConfigPath: FetchFile,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Path to attestation file (mutually exclusive with --uuid and --log-index)",
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"uuid", "log-index"},
		},
	},
	"uuid": {
		Name:       "uuid",
		ConfigPath: FetchUUID,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Rekor entry UUID (mutually exclusive with --file and --log-index)",
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"file", "log-index"},
		},
	},
	"log-index": {
		Name:       "log-index",
		ConfigPath: FetchLogIndex,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Rekor log index (mutually exclusive with --file and --uuid)",
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"file", "uuid"},
		},
	},
	"raw": {
		Name:       "raw",
		ConfigPath: FetchRaw,
		Type:       plugincobra.BoolFlag,
		Default:    false,
		Help:       "Output raw Rekor API response instead of processed format",
	},
	"output": {
		Name:       "output",
		ShortName:  "o",
		ConfigPath: FetchOutputFile,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Save fetched entry to JSON file",
	},
}
