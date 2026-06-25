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

var verifyCmd = &cobra.Command{
	Use:   "verify <attestation-file>",
	Short: "Verify attestation signatures and transparency log inclusion",
	Long: `Verify the cryptographic signature and optionally the transparency log inclusion
of an attestation. Supports both file-based public key verification and certificate-based
verification using Fulcio trust bundles.

Verification modes:
  • Signature verification: Validates cryptographic signatures using public keys or certificates
  • Rekor inclusion: Verifies the attestation was logged in a transparency log
  • Temporal validation: Ensures Rekor entries were created within certificate validity periods`,
	Example: `  # Basic signature verification (auto-detects certificate or key-based)
  stamp verify attestation.json

  # Verify with explicit public key (for key-based signatures)
  stamp verify attestation.json --public-key ./public-key.pem

  # Verify Rekor transparency log inclusion
  stamp verify attestation.json --rekor

  # Verify with custom Rekor server
  stamp verify attestation.json --rekor --rekor-url https://rekor.example.com

  # Strict temporal policy (fail if Rekor entry added after cert expired)
  stamp verify attestation.json --rekor --rekor-temporal-policy strict

  # Save verification result to file
  stamp verify attestation.json --rekor --output-verification result.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		op := operations.NewVerifyOp(rootConfig, rootLogger, rootOutput)

		if len(args) != 1 {
			return errors.NewUsageError("exactly one attestation file required",
				"Example: stamp verify attestation.json")
		}
		if err := op.Validate(args[0]); err != nil {
			return err
		}

		return op.Execute(cmd.Context(), args[0])
	},
}

func init() {
	_ = plugincobra.ApplyFlagGroup(verifyCmd, flags.FulcioServerFlags)
	_ = plugincobra.ApplyFlagGroup(verifyCmd, flags.RekorEnableFlags)
	_ = plugincobra.ApplyFlagGroup(verifyCmd, flags.RekorServerFlags)
	_ = plugincobra.ApplyFlagGroup(verifyCmd, flags.VerifyFlags)

	rootCmd.AddCommand(verifyCmd)
}
