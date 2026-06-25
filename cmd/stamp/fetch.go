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

package stamp

import (
	"github.com/spf13/cobra"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	"github.com/thomsonreuters/stamp/pkg/operations"
	plugincobra "github.com/thomsonreuters/stamp/plugins/cobra"
)

var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch attestation entries from Rekor transparency log",
	Long: `Fetch detailed information about Rekor entries using different input methods.

Fetch methods (mutually exclusive):
  • File: Calculate hash from attestation file to find corresponding entry
  • UUID: Directly retrieve entry using Rekor entry UUID
  • Log index: Retrieve entry by sequential log position`,
	Example: `  # Fetch entry by attestation file
  stamp fetch --file attestation.json

  # Fetch by UUID
  stamp fetch --uuid 5b40a1363fa79794676e15895eac2f3ff881d4337ee6fe1b6817a05709d12a1c

  # Fetch by log index
  stamp fetch --log-index 12345

  # Get raw API response for debugging
  stamp fetch --uuid abc123def456... --raw

  # Save to file (also outputs to stdout)
  stamp fetch --file attestation.json --output rekor-entry.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		op := operations.NewFetchOp(rootConfig, rootLogger, rootOutput)

		if err := op.Validate(args); err != nil {
			return err
		}

		return op.Execute(cmd.Context(), args)
	},
}

func init() {
	_ = plugincobra.ApplyFlagGroup(fetchCmd, flags.FetchFlags)
	_ = plugincobra.ApplyFlagGroup(fetchCmd, flags.RekorServerFlags)

	rootCmd.AddCommand(fetchCmd)
}
