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

package stamp

import (
	"github.com/spf13/cobra"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	"github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/operations"
	plugincobra "github.com/thomsonreuters/stamp/plugins/cobra"
)

var containerSignCmd = &cobra.Command{
	Use:   "sign <image-reference>",
	Short: "Sign a container image and emit a sigstore Bundle v0.3",
	Long: `Sign a container image and emit a sigstore Bundle v0.3.

The image reference is resolved to a manifest digest, wrapped in a
cosign-shaped in-toto Statement, and signed via sigstore-go's sign.Bundle.
Fulcio keyless signing is supported via --signer fulcio.

Transparency:
  Pass --rekor to upload the signed bundle to a transparency log
  (--rekor-url overrides the default endpoint).

Registry authentication:
  Set REGISTRY_USERNAME and REGISTRY_PASSWORD in the environment for
  authenticated registries; leaving them unset falls back to the Docker
  keychain (which covers anonymous pulls of public images).`,
	Example: `  # Key-based signing (no Rekor upload)
  stamp container sign registry.example.com/app:v1 \
      --signer key --private-key ./cosign.key \
      --bundle-output ./bundle.json

  # Encrypted key: prompt for the password at runtime and overwrite any
  # existing bundle file at --bundle-output.
  stamp container sign registry.example.com/app:v1 \
      --signer key --private-key ./cosign.key --prompt \
      --bundle-output ./bundle.json --overwrite

  # Keyless signing with a custom Rekor instance
  stamp container sign registry.example.com/app:v1 \
      --signer fulcio --oidc-token-file ./token \
      --rekor --rekor-url https://rekor.example.com \
      --bundle-output ./bundle.json

  # Signing an ECR image using AWS-derived static credentials
  export REGISTRY_USERNAME=AWS
  export REGISTRY_PASSWORD=$(aws ecr get-login-password --region us-east-1)
  stamp container sign \
      123456789012.dkr.ecr.us-east-1.amazonaws.com/app:v1 \
      --signer key --private-key ./cosign.key --bundle-output bundle.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.NewUsageError("exactly one image reference required",
				"Example: stamp container sign registry.example.com/app:v1")
		}

		op := operations.NewContainerSignOp(rootConfig, rootLogger, rootOutput)
		if err := op.Validate(args[0]); err != nil {
			return err
		}
		return op.Execute(cmd.Context(), args[0])
	},
}

func init() {
	_ = plugincobra.ApplyFlagGroup(containerSignCmd, flags.SigningFlags)
	_ = plugincobra.ApplyFlagGroup(containerSignCmd, flags.FulcioServerFlags)
	_ = plugincobra.ApplyFlagGroup(containerSignCmd, flags.PrivateKeyFlags)
	_ = plugincobra.ApplyFlagGroup(containerSignCmd, flags.PasswordFlags)
	_ = plugincobra.ApplyFlagGroup(containerSignCmd, flags.RekorEnableFlags)
	_ = plugincobra.ApplyFlagGroup(containerSignCmd, flags.RekorServerFlags)
	_ = plugincobra.ApplyFlagGroup(containerSignCmd, flags.RekorVersionFlags)
	_ = plugincobra.ApplyFlagGroup(containerSignCmd, flags.TSAServerFlags)
	_ = plugincobra.ApplyFlagGroup(containerSignCmd, flags.TrustFlags)
	_ = plugincobra.ApplyFlagGroup(containerSignCmd, flags.ContainerSignFlags)

	containerSignCmd.MarkFlagsMutuallyExclusive("trusted-root", "tuf-url")

	containerCmd.AddCommand(containerSignCmd)
}
