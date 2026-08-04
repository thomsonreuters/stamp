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

package trust

import (
	"context"
	"os"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

const envTUFRoot = "TUF_ROOT"

const DefaultTUFURL = flags.DefaultTUFURL

// Options is the input to NewResolver. Bytes fields let in-process consumers
// bypass file I/O; they take precedence over their Path counterparts.
type Options struct {
	TUFURL          string
	TUFRootPath     string
	TUFRootChecksum string
	TUFRootBytes    []byte
	CachePath       string

	TrustedRootPath  string
	TrustedRootBytes []byte

	FulcioURL           string
	FulcioCertChainPath string
	RekorURL            string
	RekorPublicKeyPath  string
	TSAURL              string
	TSACertChainPath    string

	UseSigningConfig   bool
	SigningConfigPath  string
	SigningConfigBytes []byte

	Insecure bool
}

type Resolver interface {
	Resolve(ctx context.Context) (*root.TrustedRoot, error)
}

func OptionsFromConfig(cfg config.ConfigurationIface) Options {
	return Options{
		TUFURL:              cfg.GetString(flags.TUFURL),
		TUFRootPath:         cfg.GetString(flags.TUFRootPath),
		TUFRootChecksum:     cfg.GetString(flags.TUFRootChecksum),
		CachePath:           os.Getenv(envTUFRoot),
		TrustedRootPath:     cfg.GetString(flags.TrustedRootPath),
		FulcioURL:           cfg.GetString(flags.FulcioURL),
		FulcioCertChainPath: cfg.GetString(flags.FulcioCertChain),
		RekorURL:            cfg.GetString(flags.RekorURL),
		RekorPublicKeyPath:  cfg.GetString(flags.RekorPublicKey),
		TSAURL:              cfg.GetString(flags.TSAURL),
		TSACertChainPath:    cfg.GetString(flags.TSACertChain),
		UseSigningConfig:    cfg.GetBool(flags.UseSigningConfig),
		SigningConfigPath:   cfg.GetString(flags.SigningConfigPath),
		Insecure:            cfg.GetBool(flags.Insecure),
	}
}

// NewResolver dispatches by flag presence: file > explicit > TUF.
func NewResolver(opts Options, log logger.Logger) (Resolver, error) {
	switch {
	case hasFileSource(opts):
		log.Info("trust: using local file mode",
			"path", opts.TrustedRootPath,
			"bytes", len(opts.TrustedRootBytes) > 0,
		)
		return &fileResolver{
			path:  opts.TrustedRootPath,
			bytes: opts.TrustedRootBytes,
		}, nil

	case hasExplicitArtifact(opts):
		if err := validateExplicit(opts); err != nil {
			return nil, err
		}
		log.Info("trust: using explicit URL mode",
			"fulcio", opts.FulcioURL,
			"rekor", opts.RekorURL,
			"tsa", opts.TSAURL,
		)
		return &explicitResolver{opts: opts}, nil

	default:
		url := opts.TUFURL
		if url == "" {
			url = DefaultTUFURL
		}
		log.Info("trust: using TUF mode",
			"url", url,
			"root", opts.TUFRootPath,
			"root_bytes", len(opts.TUFRootBytes) > 0,
		)
		return newTUFResolver(url, opts, log), nil
	}
}

func hasFileSource(o Options) bool {
	return o.TrustedRootPath != "" || len(o.TrustedRootBytes) > 0
}

func hasExplicitArtifact(o Options) bool {
	return o.FulcioCertChainPath != "" ||
		o.RekorPublicKeyPath != "" ||
		o.TSACertChainPath != ""
}

func validateExplicit(o Options) error {
	if o.FulcioURL != "" && o.FulcioCertChainPath == "" {
		return ErrFulcioCertChainRequired
	}
	if o.RekorURL != "" && o.RekorPublicKeyPath == "" {
		return ErrRekorKeyRequired
	}
	if o.TSAURL != "" && o.TSACertChainPath == "" {
		return ErrTSACertRequired
	}
	return nil
}
