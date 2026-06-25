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

// RunFlags contains run command options for unified execution of attestors and workflows.
var RunFlags = plugincobra.FlagGroup{
	"attestor": {
		Name:       "attestor",
		ShortName:  "a",
		ConfigPath: RunAttestor,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Attestor to execute (mutually exclusive with workflow selection)",
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"all", "tags", "include", "exclude"},
		},
	},
	"all": {
		Name:       "all",
		ConfigPath: RunAll,
		Type:       plugincobra.BoolFlag,
		Default:    false,
		Help:       "Run all workflows defined in configuration",
	},
	"tags": {
		Name:       "tags",
		ConfigPath: RunTags,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Filter workflows by tags (comma-separated, e.g., 'security,compliance')",
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"attestor"},
		},
	},
	"include": {
		Name:       "include",
		ConfigPath: RunInclude,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Include workflows matching glob pattern (e.g., '*-audit')",
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"attestor"},
		},
	},
	"exclude": {
		Name:       "exclude",
		ConfigPath: RunExclude,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Exclude workflows matching glob pattern (e.g., 'experimental-*')",
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"attestor"},
		},
	},
	"continue-on-error": {
		Name:       "continue-on-error",
		ConfigPath: RunContinueOnError,
		Type:       plugincobra.BoolFlag,
		Default:    false,
		Help:       "Continue to next workflow when a workflow fails (does not override per-workflow failure_policy)",
	},
	"set": {
		Name:       "set",
		ConfigPath: RunSet,
		Type:       plugincobra.StringArrayFlag,
		Default:    []string{},
		Help:       "Set attestorconfiguration values (key=value)",
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"all", "tags", "include", "exclude"},
			Requires:          []string{"attestor"},
		},
	},
	"persist": {
		Name:       "persist",
		ConfigPath: RunPersist,
		Type:       plugincobra.BoolFlag,
		Default:    false,
		Help:       "Write attestations to file in addition to stdout (requires --attestor)",
		Constraints: &plugincobra.FlagConstraints{
			Requires: []string{"attestor"},
		},
	},
	"force": {
		Name:       "force",
		ConfigPath: RunForce,
		Type:       plugincobra.BoolFlag,
		Default:    false,
		Help:       "Overwrite existing files when using --persist",
		Constraints: &plugincobra.FlagConstraints{
			Requires: []string{"persist"},
		},
	},
	"template": {
		Name:       "template",
		ConfigPath: RunTemplate,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "File path template for --persist flag (e.g., './attestations/${attestor}/${id}.json')",
		Constraints: &plugincobra.FlagConstraints{
			Requires: []string{"persist"},
		},
	},
}
