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

// GlobalFlags contains flags available to all commands.
var GlobalFlags = plugincobra.FlagGroup{
	"config": {
		Name:       "config",
		ShortName:  "c",
		ConfigPath: plugincobra.NoConfig, // Bootstrap-only: cannot be set via config file
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Configuration file path",
		Persistent: true,
	},
	"log-level": {
		Name:       "log-level",
		ConfigPath: LogLevel,
		Type:       plugincobra.StringFlag,
		Default:    "warn",
		Help:       fmt.Sprintf("Log level (%s)", strings.Join(types.ValidLogLevels, ", ")),
		Persistent: true,
		Constraints: &plugincobra.FlagConstraints{
			ValidValues: types.ValidLogLevels,
		},
	},
	"log-format": {
		Name:       "log-format",
		ConfigPath: LogFormat,
		Type:       plugincobra.StringFlag,
		Default:    "console",
		Help:       fmt.Sprintf("Log format (%s)", strings.Join(types.ValidLogFormats, ", ")),
		Persistent: true,
		Constraints: &plugincobra.FlagConstraints{
			ValidValues: types.ValidLogFormats,
		},
	},
	"log-file": {
		Name:       "log-file",
		ConfigPath: LogFile,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Log file path (enables file output)",
		Persistent: true,
	},
	"quiet": {
		Name:       "quiet",
		ShortName:  "q",
		ConfigPath: Quiet,
		Type:       plugincobra.BoolFlag,
		Default:    false,
		Help:       "Suppress logs and user messages, show only data output (mutually exclusive with --log-only, --debug)",
		Persistent: true,
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"log-only", "debug"},
		},
	},
	"log-only": {
		Name:       "log-only",
		ConfigPath: LogOnly,
		Type:       plugincobra.BoolFlag,
		Default:    false,
		Help:       "Suppress data output, show only logs and messages (mutually exclusive with --quiet)",
		Persistent: true,
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"quiet"},
		},
	},
	"debug": {
		Name:       "debug",
		ConfigPath: Debug,
		Type:       plugincobra.BoolFlag,
		Default:    false,
		Help:       "Enable debug mode (mutually exclusive with --quiet)",
		Persistent: true,
		Constraints: &plugincobra.FlagConstraints{
			MutuallyExclusive: []string{"quiet"},
		},
	},
	"no-color": {
		Name:       "no-color",
		ConfigPath: NoColor,
		Type:       plugincobra.BoolFlag,
		Default:    false,
		Help:       "Disable colored output",
		Persistent: true,
	},
}
