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
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	"github.com/thomsonreuters/stamp/pkg/crypto/keys"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/signing"
	"github.com/thomsonreuters/stamp/pkg/signing/fulcio"
	"github.com/thomsonreuters/stamp/pkg/trust"
	"github.com/thomsonreuters/stamp/pkg/types"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

// BuildOptionsFromConfig assembles sigstore.Options from CLI flags and trust configuration.
func BuildOptionsFromConfig(ctx context.Context, cfg config.ConfigurationIface, log logger.Logger) (Options, error) {
	opts := Options{}
	trustOpts := trust.OptionsFromConfig(cfg)

	resolver, err := trust.NewResolver(trustOpts, log)
	if err != nil {
		return opts, pkgerrors.WrapWithContext(err, "sigstore", "build_opts", "trust config error")
	}
	tr, err := resolver.Resolve(ctx)
	if err != nil {
		return opts, pkgerrors.WrapWithContext(err, "sigstore", "build_opts", "failed to resolve trusted root")
	}
	opts.TrustedRoot = tr

	scResolver, err := trust.NewSigningConfigResolver(trustOpts, log)
	if err != nil {
		return opts, pkgerrors.WrapWithContext(err, "sigstore", "build_opts", "signing config error")
	}
	sc, err := scResolver.Resolve(ctx)
	if err != nil {
		return opts, pkgerrors.WrapWithContext(err, "sigstore", "build_opts", "failed to resolve signing config")
	}
	if sc != nil && hasExplicitServiceURL(cfg) {
		return opts, pkgerrors.WrapWithContext(trust.ErrSigningConfigURLConflict, "sigstore", "build_opts", "signing config conflict")
	}
	opts.SigningConfig = sc

	urls, err := resolveEffectiveURLs(cfg, sc)
	if err != nil {
		return opts, pkgerrors.WrapWithContext(err, "sigstore", "build_opts", "failed to resolve effective service URLs")
	}

	switch cfg.GetString(flags.Signer) {
	case types.SignerKey.String():
		keyOpts, err := BuildKeyOptions(cfg)
		if err != nil {
			return opts, err
		}
		opts.Key = keyOpts
	case types.SignerFulcio.String():
		fulcioOpts, err := BuildFulcioOptions(ctx, cfg, urls.fulcio)
		if err != nil {
			return opts, err
		}
		opts.Fulcio = fulcioOpts
	}

	if cfg.GetBool(flags.TransparencyEnable) {
		opts.Rekor = &RekorOptions{URL: urls.rekor, Version: urls.rekorVersion}
	}
	if urls.tsa != "" {
		opts.TSA = &TSAOptions{URL: urls.tsa}
	}
	return opts, nil
}

// hasExplicitServiceURL returns true if the user explicitly set a service URL that conflicts with SigningConfig.
func hasExplicitServiceURL(cfg config.ConfigurationIface) bool {
	if cfg.GetString(flags.Signer) == types.SignerFulcio.String() && cfg.IsSet(flags.FulcioURL) {
		return true
	}
	if cfg.GetBool(flags.TransparencyEnable) && cfg.IsSet(flags.RekorURL) {
		return true
	}
	return cfg.IsSet(flags.TSAURL)
}

type effectiveURLs struct {
	fulcio       string
	rekor        string
	tsa          string
	rekorVersion uint32
}

// resolveEffectiveURLs computes service URLs, preferring SigningConfig over CLI flags.
func resolveEffectiveURLs(cfg config.ConfigurationIface, sc *root.SigningConfig) (effectiveURLs, error) {
	urls := effectiveURLs{
		fulcio:       cfg.GetString(flags.FulcioURL),
		rekor:        cfg.GetString(flags.RekorURL),
		tsa:          cfg.GetString(flags.TSAURL),
		rekorVersion: uint32(cfg.GetInt(flags.RekorVersion)),
	}
	if urls.rekorVersion == 0 {
		urls.rekorVersion = 1
	}
	if sc == nil {
		return urls, nil
	}

	now := time.Now()

	if svc, err := root.SelectService(sc.FulcioCertificateAuthorityURLs(), []uint32{1}, now); err != nil {
		return urls, fmt.Errorf("signing config: fulcio URL: %w", err)
	} else {
		urls.fulcio = svc.URL
	}

	if svc, err := root.SelectService(sc.RekorLogURLs(), []uint32{urls.rekorVersion}, now); err != nil {
		return urls, fmt.Errorf("signing config: rekor URL (v%d): %w", urls.rekorVersion, err)
	} else {
		urls.rekor = svc.URL
	}

	if urls.tsa == "" && urls.rekorVersion == 2 {
		svc, err := root.SelectService(sc.TimestampAuthorityURLs(), []uint32{1}, now)
		if err != nil {
			return urls, fmt.Errorf("signing config: tsa URL required for rekor v2: %w", err)
		}
		urls.tsa = svc.URL
	}
	return urls, nil
}

// BuildKeyOptions loads the private key and returns KeyOptions with crypto.Signer and fingerprint.
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

// BuildFulcioOptions resolves the OIDC token and returns FulcioOptions.
func BuildFulcioOptions(ctx context.Context, cfg config.ConfigurationIface, fulcioURL string) (*FulcioOptions, error) {
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
