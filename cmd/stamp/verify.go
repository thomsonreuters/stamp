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
	Long: `Verify a Sigstore attestation bundle (.sigstore.json). Auto-detects
certificate-signed (Fulcio) vs key-signed bundles. Defaults to public
sigstore; use --trusted-root or --tuf-url + --tuf-root for a private
deployment.

Signer identity is not enforced by default — pass --expected-san /
--expected-issuer to opt in.`,
	Example: `  # Public sigstore, crypto-only verification
  stamp verify attestation.sigstore.json --rekor

  # Enforce signer identity
  stamp verify attestation.sigstore.json --rekor \
      --expected-san 'https://github.com/org/repo/.github/workflows/build.yaml@refs/heads/main' \
      --expected-issuer https://token.actions.githubusercontent.com

  # Enforce signer identity via regex
  stamp verify attestation.sigstore.json --rekor \
      --expected-san-regex '^https://github\.com/org/.*' \
      --expected-issuer https://token.actions.githubusercontent.com

  # Private TUF
  stamp verify attestation.sigstore.json --rekor \
      --tuf-url https://tuf.example.com --tuf-root ./tuf-root.json

  # Offline (local trusted_root.json)
  stamp verify attestation.sigstore.json --rekor \
      --trusted-root ./trusted_root.json

  # Key-signed bundle
  stamp verify attestation.sigstore.json --public-key ./signer.pub --rekor

  # Save JSON result for scripting
  stamp verify attestation.sigstore.json --rekor --output-verification result.json`,
	Args: cobra.ExactArgs(1),
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		if cmd.Flags().Changed("trusted-root") && cmd.Flags().Changed("tuf-url") {
			return errors.NewUsageError(
				"choose one trust source",
				"Pass --trusted-root for a local trusted_root.json, or --tuf-url for a TUF repository, not both")
		}
		return nil
	},
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
	_ = plugincobra.ApplyFlagGroup(verifyCmd, flags.RekorVerifyEnableFlags)
	_ = plugincobra.ApplyFlagGroup(verifyCmd, flags.VerifyFlags)
	_ = plugincobra.ApplyFlagGroup(verifyCmd, flags.VerifyTrustFlags)

	rootCmd.AddCommand(verifyCmd)
}
