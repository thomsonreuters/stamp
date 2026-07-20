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

package sigstore

import (
	"context"
	"crypto"
	"fmt"

	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	"github.com/thomsonreuters/stamp/pkg/crypto/keys"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/signing"
	"github.com/thomsonreuters/stamp/pkg/signing/fulcio"
	"github.com/thomsonreuters/stamp/pkg/types"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

// BuildOptionsFromConfig assembles sigstore.Options from the standard
// signer flags (--signer, --private-key, --password*, --fulcio-url,
// --oidc-token*, --rekor, --rekor-url, etc.). Attestor call sites should
// use this so that flag translation stays in one place.
func BuildOptionsFromConfig(ctx context.Context, cfg config.ConfigurationIface) (Options, error) {
	opts := Options{}

	switch cfg.GetString(flags.Signer) {
	case types.SignerKey.String():
		keyOpts, err := BuildKeyOptions(cfg)
		if err != nil {
			return opts, err
		}
		opts.Key = keyOpts
	case types.SignerFulcio.String():
		fulcioOpts, err := BuildFulcioOptions(ctx, cfg)
		if err != nil {
			return opts, err
		}
		opts.Fulcio = fulcioOpts
	}

	if cfg.GetBool(flags.TransparencyEnable) {
		opts.Rekor = &RekorOptions{URL: cfg.GetString(flags.RekorURL)}
	}
	return opts, nil
}

// BuildKeyOptions loads the private key from --private-key using a password
// resolved via --password / --password-file / --prompt, and returns a
// KeyOptions populated with the crypto.Signer and its fingerprint.
func BuildKeyOptions(cfg config.ConfigurationIface) (*KeyOptions, error) {
	keyPath := cfg.GetString(flags.PrivateKey)

	password, err := utils.ResolveKeyPassword(utils.KeyPasswordConfig{
		Password:      cfg.GetString(flags.CryptographyKeyPassword),
		PasswordFile:  cfg.GetString(flags.CryptographyKeyPasswordFile),
		PromptEnabled: cfg.GetBool(flags.CryptographyKeyPasswordPrompt),
	})
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "sigstore", "build_opts", "failed to resolve key password")
	}

	loaded, err := keys.LoadPrivateKeyFromFile(keyPath, password)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "sigstore", "build_opts", "failed to load private key")
	}
	signer, ok := loaded.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, pkgerrors.NewWithContext("sigstore", "build_opts",
			fmt.Sprintf("private key type %T does not implement crypto.Signer", loaded.PrivateKey))
	}
	fingerprint, err := keys.Fingerprint(loaded.PrivateKey)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "sigstore", "build_opts", "failed to compute key fingerprint")
	}
	return &KeyOptions{
		Signer: signer,
		Hint:   []byte(fingerprint),
	}, nil
}

// BuildFulcioOptions reads Fulcio flags, resolves the OIDC token (via
// direct value, file, SPIRE, or GitHub Actions), and returns a
// FulcioOptions ready to sign with.
func BuildFulcioOptions(ctx context.Context, cfg config.ConfigurationIface) (*FulcioOptions, error) {
	fulcioURL := cfg.GetString(flags.FulcioURL)
	fulcioCfg := signing.FulcioSignerConfig{
		FulcioURL:        fulcioURL,
		Token:            cfg.GetString(flags.OIDCToken),
		TokenPath:        cfg.GetString(flags.OIDCTokenFile),
		UseSpire:         cfg.GetBool(flags.UseSpire),
		SpireAgentSocket: cfg.GetString(flags.SPIRESocket),
		UseGitHub:        cfg.GetBool(flags.UseGitHub),
		Insecure:         cfg.GetBool(flags.Insecure),
	}
	token, err := fulcio.ResolveToken(ctx, fulcioCfg)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "sigstore", "build_opts", "failed to resolve OIDC token")
	}
	return &FulcioOptions{
		URL:     fulcioURL,
		IDToken: token,
	}, nil
}
