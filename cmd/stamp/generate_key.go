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

var generateKeyCmd = &cobra.Command{
	Use:   "generate-key",
	Short: "Generate a new key pair for file-based signing",
	Long: `Generate a new key pair for use with file-based signing.

This utility generates cryptographic key pairs for signing attestations when using
the 'key' signing backend. Both private and public keys are generated:
  • Private key: stored securely with 0600 permissions, named <base>.key
  • Public key: stored with 0644 permissions, named <base>.pub

Supported key types:
  • rsa    - RSA 2048-bit key (widely supported)
  • ecdsa  - ECDSA P-256 key (smaller, faster)`,
	Example: `  # Generate unencrypted RSA key pair
  stamp generate-key --type rsa --output examplekey

  # Generate encrypted ECDSA key pair (secure prompt for password)

  stamp generate-key --type ecdsa --output examplekey --prompt

  # Generate with password from file
  stamp generate-key --type rsa --output examplekey --password-file ./pass.txt

  # Overwrite existing key pair
  stamp generate-key --type rsa --output examplekey --overwrite`,
	RunE: func(cmd *cobra.Command, args []string) error {
		op := operations.NewGenerateKeyOp(rootConfig, rootLogger, rootOutput)

		return op.Execute(cmd.Context(), args)
	},
}

func init() {
	_ = plugincobra.ApplyFlagGroup(generateKeyCmd, flags.GenerateKeyFlags)
	_ = plugincobra.ApplyFlagGroup(generateKeyCmd, flags.PasswordFlags)

	rootCmd.AddCommand(generateKeyCmd)
}
