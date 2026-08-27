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

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Execute attestors, workflows, or filtered sets of workflows",
	Long: `Run attestors or workflows to generate attestations.

This command can operate in different modes:
  • Single attestor: --attestor <attestor-id>
  • All workflows from config: --all
  • Filtered workflows: --tags, --include, --exclude

Workflow selection options can be combined (e.g., --all --exclude 'test-*').`,
	Example: `  # Run a single attestor
  stamp run --attestor git

  # Run all workflows from config
  stamp run --all

  # Run workflows by tag
  stamp run --tags ci,security

  # Run workflows matching pattern
  stamp run --all --include '*-prod'

  # Run all except experimental
  stamp run --all --exclude 'experimental-*'

  # Continue on errors instead of fail-fast
  stamp run --all --continue-on-error

  # Set attestor configuration
  stamp run --attestor git --set branch=main --set remote=origin

  # Persist results to file
  stamp run --attestor git --persist --template './attestations/${attestor}.json'`,
	RunE: func(cmd *cobra.Command, args []string) error {
		op := operations.NewRunOp(rootConfig, rootLogger, rootOutput)

		if err := op.Validate(args); err != nil {
			return err
		}

		logOnly := rootConfig.GetBool(flags.LogOnly)
		rootOutput.SetDataEnabled(!logOnly)

		return op.Execute(cmd.Context(), args)
	},
}

func init() {
	_ = plugincobra.ApplyFlagGroup(runCmd, flags.ExecutionFlags)
	_ = plugincobra.ApplyFlagGroup(runCmd, flags.SigningFlags)
	_ = plugincobra.ApplyFlagGroup(runCmd, flags.FulcioServerFlags)
	_ = plugincobra.ApplyFlagGroup(runCmd, flags.PrivateKeyFlags)
	_ = plugincobra.ApplyFlagGroup(runCmd, flags.PublicKeyFlags)
	_ = plugincobra.ApplyFlagGroup(runCmd, flags.PasswordFlags)
	_ = plugincobra.ApplyFlagGroup(runCmd, flags.RekorEnableFlags)
	_ = plugincobra.ApplyFlagGroup(runCmd, flags.RekorServerFlags)
	_ = plugincobra.ApplyFlagGroup(runCmd, flags.RekorVersionFlags)
	_ = plugincobra.ApplyFlagGroup(runCmd, flags.RekorUploadFlags)
	_ = plugincobra.ApplyFlagGroup(runCmd, flags.TSAServerFlags)
	_ = plugincobra.ApplyFlagGroup(runCmd, flags.TrustFlags)
	_ = plugincobra.ApplyFlagGroup(runCmd, flags.OutputFlags)
	_ = plugincobra.ApplyFlagGroup(runCmd, flags.RunFlags)

	rootCmd.AddCommand(runCmd)
}
