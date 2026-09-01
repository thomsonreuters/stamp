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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/root"
	sgtuf "github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

type tufResolver struct {
	url        string
	opts       Options
	httpClient *http.Client
	log        logger.Logger
}

func newTUFResolver(url string, opts Options, log logger.Logger) *tufResolver {
	return &tufResolver{
		url:        url,
		opts:       opts,
		httpClient: NewHTTPClient(log, opts.Insecure),
		log:        log,
	}
}

func (r *tufResolver) Resolve(ctx context.Context) (*root.TrustedRoot, error) {
	rootBytes, err := resolveTUFRootBytes(ctx, r.opts, r.httpClient)
	if err != nil {
		return nil, err
	}
	tufOpts := buildTUFOptions(ctx, r.url, r.opts.CachePath, rootBytes, r.httpClient)
	tr, err := root.FetchTrustedRootWithOptions(tufOpts)
	if err != nil {
		return nil, fmt.Errorf("trust: fetch trusted root via TUF %q: %w", r.url, err)
	}
	return tr, nil
}

func resolveTUFRootBytes(ctx context.Context, opts Options, httpClient *http.Client) ([]byte, error) {
	if len(opts.TUFRootBytes) > 0 {
		return opts.TUFRootBytes, nil
	}
	if opts.TUFRootPath == "" {
		if opts.TUFRootChecksum != "" {
			return nil, errors.New("trust: --tuf-root-checksum has no effect without --tuf-root")
		}
		return nil, nil
	}
	if isHTTPURL(opts.TUFRootPath) {
		if strings.HasPrefix(opts.TUFRootPath, "http://") && !opts.Insecure {
			return nil, errors.New("trust: --tuf-root=http:// requires --insecure (no transport integrity); use https or a filesystem path")
		}
		return fetchRootFromURL(ctx, opts.TUFRootPath, opts.TUFRootChecksum, httpClient)
	}
	b, err := os.ReadFile(opts.TUFRootPath)
	if err != nil {
		return nil, fmt.Errorf("trust: read tuf root %q: %w", opts.TUFRootPath, err)
	}
	return b, nil
}

func buildTUFOptions(ctx context.Context, url, cachePath string, rootBytes []byte, httpClient *http.Client) *sgtuf.Options {
	f := fetcher.NewDefaultFetcher()
	f.SetHTTPClient(httpClient)

	opts := sgtuf.DefaultOptions().
		WithContext(ctx).
		WithRepositoryBaseURL(url).
		WithFetcher(f).
		WithCacheValidity(1)
	if rootBytes != nil {
		opts = opts.WithRoot(rootBytes)
	}
	if cachePath != "" {
		opts = opts.WithCachePath(cachePath)
	}
	return opts
}

// Real TUF roots are 5-15 KB; anything above this is hostile or misconfigured.
const maxTUFRootSize = 1 << 20

func fetchRootFromURL(ctx context.Context, rawURL, checksum string, httpClient *http.Client) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("trust: parse tuf root url: %w", err)
	}
	safeURL := parsed.Redacted()

	if checksum == "" {
		return nil, fmt.Errorf("trust: --tuf-root=%s requires --tuf-root-checksum", safeURL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("trust: build request for %q: %w", safeURL, err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("trust: fetch tuf root from %q: %w", safeURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trust: fetch tuf root from %q: unexpected status %d", safeURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTUFRootSize+1))
	if err != nil {
		return nil, fmt.Errorf("trust: read tuf root body from %q: %w", safeURL, err)
	}
	if len(body) > maxTUFRootSize {
		return nil, fmt.Errorf("trust: tuf root at %q exceeds %d bytes (possible hostile or misconfigured server)", safeURL, maxTUFRootSize)
	}

	if checksum != "" {
		sum := sha256.Sum256(body)
		got := hex.EncodeToString(sum[:])
		want := strings.ToLower(strings.TrimSpace(checksum))
		if got != want {
			return nil, fmt.Errorf("trust: tuf root checksum mismatch: got %s, want %s", got, want)
		}
	}
	return body, nil
}

func isHTTPURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}
