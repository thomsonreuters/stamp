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

package operations

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	"github.com/thomsonreuters/stamp/pkg/crypto/keys"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/output"
	"github.com/thomsonreuters/stamp/pkg/sign/container"
	"github.com/thomsonreuters/stamp/pkg/signing"
	"github.com/thomsonreuters/stamp/pkg/signing/fulcio"
	"github.com/thomsonreuters/stamp/pkg/types"
	"github.com/thomsonreuters/stamp/pkg/utils"
	"github.com/thomsonreuters/stamp/pkg/validation"
)

const (
	envRegistryUsername = "REGISTRY_USERNAME"
	envRegistryPassword = "REGISTRY_PASSWORD"
)

// ContainerSignOp signs a container image and emits a sigstore Bundle v0.3.
type ContainerSignOp struct {
	config config.ConfigurationIface
	logger logger.Logger
	output output.OutputIface
}

func (o *ContainerSignOp) Validate(imageRef string) error {
	validator := pkgerrors.NewValidator()

	if imageRef == "" {
		validator.AddError("arguments", "image reference is required")
	}

	backend := o.config.GetString(flags.Signer)
	switch backend {
	case types.SignerKey.String():
		keyPath := o.config.GetString(flags.PrivateKey)
		if keyPath == "" {
			validator.AddError("private-key", fmt.Sprintf("--private-key is required with --signer %s", types.SignerKey))
		}
	case types.SignerFulcio.String():
		fulcioURL := o.config.GetString(flags.FulcioURL)
		insecure := o.config.GetBool(flags.Insecure)
		if err := validation.ValidateURLFormat(fulcioURL, insecure, "Fulcio URL"); err != nil {
			validator.AddError("fulcio-url", fmt.Sprintf("invalid Fulcio URL: %v", err))
		}
	case "":
		validator.AddError("signer", fmt.Sprintf("--signer is required (%s)", strings.Join(types.ValidSigners, " or ")))
	default:
		validator.AddError("signer", fmt.Sprintf("unsupported signer %q (expected %s)", backend, strings.Join(types.ValidSigners, " or ")))
	}

	if o.config.GetBool(flags.TransparencyEnable) {
		rekorURL := o.config.GetString(flags.RekorURL)
		insecure := o.config.GetBool(flags.Insecure)
		if err := validation.ValidateURLFormat(rekorURL, insecure, "Rekor URL"); err != nil {
			validator.AddError("rekor-url", fmt.Sprintf("invalid Rekor URL: %v", err))
		}
	}

	user, pass := os.Getenv(envRegistryUsername), os.Getenv(envRegistryPassword)
	if (user == "") != (pass == "") {
		validator.AddError("registry", fmt.Sprintf("%s and %s must be set together", envRegistryUsername, envRegistryPassword))
	}

	if validator.HasErrors() {
		_ = validator.Suggest(
			"Provide an image reference (e.g. registry.example.com/app:tag)",
			fmt.Sprintf("Select a signer: --signer %s --private-key <path> OR --signer %s --oidc-token <token>", types.SignerKey, types.SignerFulcio),
			"For keyless signing, ensure --fulcio-url points at a reachable Fulcio instance",
			"Export REGISTRY_USERNAME and REGISTRY_PASSWORD for the source registry (for ECR: password from `aws ecr get-login-password`)",
		)
		return validator
	}
	return nil
}

func (o *ContainerSignOp) Execute(ctx context.Context, imageRef string) error {
	o.logger.InfoContext(ctx, "starting container image signing", "image", imageRef)
	o.output.Progress("Signing container image: %s", imageRef)

	opts, err := o.buildSignOptions(ctx)
	if err != nil {
		return err
	}

	signer := container.NewSigner(o.logger)
	res, err := signer.Sign(ctx, imageRef, opts)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "container", "sign",
			fmt.Sprintf("failed to sign container image: %s", imageRef)).
			Suggest(
				"Verify the image reference is pullable (docker credentials in keychain)",
				"For keyless: ensure the OIDC token is trusted by the target Fulcio",
				"For key-based: check --private-key path and password",
			)
	}

	if err := o.writeBundle(ctx, res); err != nil {
		return err
	}

	o.output.Success("Container image signed")
	o.output.List("Image: %s", imageRef)
	o.output.List("Digest: %s", res.Digest)
	if opts.Rekor != nil {
		o.output.List("Rekor: %s", opts.Rekor.URL)
	}
	return nil
}

func (o *ContainerSignOp) buildSignOptions(ctx context.Context) (container.Options, error) {
	opts := container.Options{}

	switch o.config.GetString(flags.Signer) {
	case types.SignerKey.String():
		keyOpts, err := o.buildKeyOptions()
		if err != nil {
			return opts, err
		}
		opts.Key = keyOpts
	case types.SignerFulcio.String():
		token, err := o.resolveFulcioToken(ctx)
		if err != nil {
			return opts, err
		}
		opts.Fulcio = &container.FulcioOptions{
			URL:     o.config.GetString(flags.FulcioURL),
			IDToken: token,
		}
	}

	if o.config.GetBool(flags.TransparencyEnable) {
		opts.Rekor = &container.RekorOptions{
			URL: o.config.GetString(flags.RekorURL),
		}
	}

	if creds := registryCredsFromEnv(); creds != nil {
		opts.Registry = creds
	}
	return opts, nil
}

// registryCredsFromEnv returns nil if either env var is empty, so a
// partial credential never reaches authn (which would fail with a
// misleading error).
func registryCredsFromEnv() *container.RegistryOptions {
	user := os.Getenv(envRegistryUsername)
	pass := os.Getenv(envRegistryPassword)
	if user == "" || pass == "" {
		return nil
	}
	return &container.RegistryOptions{Username: user, Password: pass}
}

func (o *ContainerSignOp) buildKeyOptions() (*container.KeyOptions, error) {
	keyPath := o.config.GetString(flags.PrivateKey)
	password, err := o.resolveKeyPassword()
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "container", "sign", "failed to resolve key password")
	}
	loaded, err := keys.LoadPrivateKeyFromFile(keyPath, password)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "container", "sign", "failed to load private key")
	}
	signer, ok := loaded.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, pkgerrors.NewWithContext("container", "sign",
			fmt.Sprintf("private key type %T does not implement crypto.Signer", loaded.PrivateKey))
	}
	fingerprint, err := keys.Fingerprint(loaded.PrivateKey)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "container", "sign", "failed to compute key fingerprint")
	}
	return &container.KeyOptions{
		Signer: signer,
		Hint:   []byte(fingerprint),
	}, nil
}

// resolveKeyPassword precedence: --password > --password-file > --prompt.
// Empty return means "no password" (unencrypted key). Flag mutual
// exclusion is enforced upstream.
func (o *ContainerSignOp) resolveKeyPassword() (string, error) {
	if password := o.config.GetString(flags.CryptographyKeyPassword); password != "" {
		return password, nil
	}
	if file := o.config.GetString(flags.CryptographyKeyPasswordFile); file != "" {
		return utils.ReadPasswordFromFile(file)
	}
	if o.config.GetBool(flags.CryptographyKeyPasswordPrompt) {
		return utils.PromptPassword("Enter password for private key")
	}
	return "", nil
}

func (o *ContainerSignOp) resolveFulcioToken(ctx context.Context) (string, error) {
	cfg := signing.FulcioSignerConfig{
		FulcioURL:        o.config.GetString(flags.FulcioURL),
		Token:            o.config.GetString(flags.OIDCToken),
		TokenPath:        o.config.GetString(flags.OIDCTokenFile),
		UseSpire:         o.config.GetBool(flags.UseSpire),
		SpireAgentSocket: o.config.GetString(flags.SPIRESocket),
		UseGitHub:        o.config.GetBool(flags.UseGitHub),
		Insecure:         o.config.GetBool(flags.Insecure),
	}
	token, err := fulcio.ResolveToken(ctx, cfg)
	if err != nil {
		return "", pkgerrors.WrapWithContext(err, "container", "sign", "failed to resolve OIDC token")
	}
	return token, nil
}

func (o *ContainerSignOp) writeBundle(ctx context.Context, res *container.Result) error {
	dest := o.config.GetString(flags.ContainerSignOutput)
	if dest == "" {
		if _, err := os.Stdout.Write(res.BundleJSON); err != nil {
			return pkgerrors.WrapWithContext(err, "container", "sign", "failed to write bundle to stdout")
		}
		if _, err := os.Stdout.Write([]byte("\n")); err != nil {
			return pkgerrors.WrapWithContext(err, "container", "sign", "failed to write bundle newline")
		}
		return nil
	}
	openFlags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !o.config.GetBool(flags.ContainerSignOverwrite) {
		openFlags |= os.O_EXCL
	}
	f, err := os.OpenFile(dest, openFlags, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			bundleErr := pkgerrors.NewWithContext("container", "sign",
				fmt.Sprintf("bundle file already exists: %s", dest))
			_ = bundleErr.Suggest(
				"Pass --overwrite to replace the existing bundle",
				"Or choose a different --bundle-output path",
			)
			return bundleErr
		}
		return pkgerrors.WrapWithContext(err, "container", "sign",
			fmt.Sprintf("failed to open bundle for writing: %s", dest))
	}
	if _, err := f.Write(res.BundleJSON); err != nil {
		_ = f.Close()
		return pkgerrors.WrapWithContext(err, "container", "sign",
			fmt.Sprintf("failed to write bundle to %s", dest))
	}
	// Close explicitly (not deferred) so a flush failure surfaces to
	// the caller as an error instead of being silently discarded.
	if err := f.Close(); err != nil {
		return pkgerrors.WrapWithContext(err, "container", "sign",
			fmt.Sprintf("failed to close bundle: %s", dest))
	}
	o.logger.InfoContext(ctx, "bundle written", "path", dest, "size", len(res.BundleJSON))
	o.output.Success("Bundle saved to: %s", dest)
	return nil
}

func NewContainerSignOp(config config.ConfigurationIface, logger logger.Logger, output output.OutputIface) *ContainerSignOp {
	return &ContainerSignOp{
		config: config,
		logger: logger,
		output: output,
	}
}
