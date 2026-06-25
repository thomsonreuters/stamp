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

var listCmd = &cobra.Command{
	Use:   "list [attestor-id]",
	Short: "List available attestors",
	Long: `List all registered attestors with optional detail levels.

The list command displays available attestors that can be used to generate
attestations. You can show configuration for all attestors, or view detailed
configuration for a specific attestor.`,
	Example: `  # List all attestors (compact view)
  stamp list

  # List all attestors with configuration details
  stamp list --show-config

  # Show detailed configuration for specific attestor
  stamp list git`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		op := operations.NewListOp(rootConfig, rootLogger, rootOutput)

		return op.Execute(cmd.Context(), args)
	},
}

func init() {
	_ = plugincobra.ApplyFlagGroup(listCmd, flags.ListFlags)

	rootCmd.AddCommand(listCmd)
}
