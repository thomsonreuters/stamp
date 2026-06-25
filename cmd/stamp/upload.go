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
	"github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/operations"
	plugincobra "github.com/thomsonreuters/stamp/plugins/cobra"
)

var uploadCmd = &cobra.Command{
	Use:   "upload <attestation-file>",
	Short: "Upload signed attestation to Rekor transparency log",
	Long: `Upload a previously generated and signed attestation to a Rekor transparency log.

The upload command takes an existing attestation file and uploads it to Rekor for
transparency and immutable logging. The attestation must already be signed.

Verification requirements:
  • Certificate-based signatures: Uses certificates embedded in the attestation (preferred)
  • File-based signatures: Requires --public-key or config file public key setting`,
	Example: `  # Upload attestation to default Rekor instance
  stamp upload attestation.json

  # Upload with custom Rekor server
  stamp upload attestation.json --rekor-url https://rekor.example.com

  # Upload attestation signed with file-based key (explicit public key)
  stamp upload attestation.json --public-key ./public-key.pem`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		op := operations.NewUploadOp(rootConfig, rootLogger, rootOutput)

		if len(args) != 1 {
			return errors.NewUsageError("exactly one attestation file required",
				"Example: stamp upload attestation.json")
		}
		if err := op.Validate(args[0]); err != nil {
			return err
		}

		return op.Execute(cmd.Context(), args[0])
	},
}

func init() {
	_ = plugincobra.ApplyFlagGroup(uploadCmd, flags.RekorServerFlags)
	_ = plugincobra.ApplyFlagGroup(uploadCmd, flags.UploadFlags)

	rootCmd.AddCommand(uploadCmd)
}
