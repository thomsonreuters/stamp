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
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// SigningConfigResolver returns nil to signal "no SigningConfig configured".
type SigningConfigResolver interface {
	Resolve(ctx context.Context) (*root.SigningConfig, error)
}

func NewSigningConfigResolver(opts Options, log logger.Logger) (SigningConfigResolver, error) {
	switch {
	case len(opts.SigningConfigBytes) > 0:
		log.Info("trust: signing config from bytes")
		return &fileSigningConfigResolver{bytes: opts.SigningConfigBytes}, nil
	case opts.SigningConfigPath != "":
		log.Info("trust: signing config from file", "path", opts.SigningConfigPath)
		return &fileSigningConfigResolver{path: opts.SigningConfigPath}, nil
	case opts.UseSigningConfig:
		url := opts.TUFURL
		if url == "" {
			url = DefaultTUFURL
		}
		log.Info("trust: signing config from TUF", "url", url)
		return newTUFSigningConfigResolver(url, opts, log), nil
	default:
		return nilSigningConfigResolver{}, nil
	}
}

type nilSigningConfigResolver struct{}

func (nilSigningConfigResolver) Resolve(_ context.Context) (*root.SigningConfig, error) {
	return nil, nil
}

type fileSigningConfigResolver struct {
	path  string
	bytes []byte
}

func (r *fileSigningConfigResolver) Resolve(_ context.Context) (*root.SigningConfig, error) {
	if len(r.bytes) > 0 {
		sc, err := root.NewSigningConfigFromJSON(r.bytes)
		if err != nil {
			return nil, fmt.Errorf("trust: parse signing config bytes: %w", err)
		}
		return sc, nil
	}
	sc, err := root.NewSigningConfigFromPath(r.path)
	if err != nil {
		return nil, fmt.Errorf("trust: load signing config from %q: %w", r.path, err)
	}
	return sc, nil
}

type tufSigningConfigResolver struct {
	url  string
	opts Options
	log  logger.Logger
}

func newTUFSigningConfigResolver(url string, opts Options, log logger.Logger) *tufSigningConfigResolver {
	return &tufSigningConfigResolver{url: url, opts: opts, log: log}
}

func (r *tufSigningConfigResolver) Resolve(ctx context.Context) (*root.SigningConfig, error) {
	httpClient := NewHTTPClient(r.log, r.opts.Insecure)
	rootBytes, err := resolveTUFRootBytes(ctx, r.opts, httpClient)
	if err != nil {
		return nil, err
	}
	tufOpts := buildTUFOptions(ctx, r.url, r.opts.CachePath, rootBytes, httpClient)
	sc, err := root.FetchSigningConfigWithOptions(tufOpts)
	if err != nil {
		return nil, fmt.Errorf("trust: fetch signing config via TUF %q: %w", r.url, err)
	}
	return sc, nil
}
