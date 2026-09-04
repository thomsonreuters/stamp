// Copyright 2025 Thomson Reuters
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

// ContainerSignFlags contains flags specific to `stamp container sign`.
var ContainerSignFlags = plugincobra.FlagGroup{
	"bundle-output": {
		Name:       "bundle-output",
		ShortName:  "o",
		ConfigPath: ContainerSignOutput,
		Type:       plugincobra.StringFlag,
		Default:    "",
		Help:       "Path to write the signed .sigstore.json bundle (default: stdout)",
	},
	"overwrite": {
		Name:       "overwrite",
		ConfigPath: ContainerSignOverwrite,
		Type:       plugincobra.BoolFlag,
		Default:    false,
		Help:       "Overwrite existing bundle file at --bundle-output",
	},
}
