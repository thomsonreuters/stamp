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
	"crypto/tls"
	"net/http"
	"time"

	"github.com/thomsonreuters/stamp/pkg/logger"
)

const defaultHTTPTimeout = 30 * time.Second

// URL query strings are NOT redacted; req.URL.Redacted only masks userinfo.
var redactedHeaders = map[string]struct{}{
	"Authorization":       {},
	"Cookie":              {},
	"Set-Cookie":          {},
	"Proxy-Authorization": {},
	"X-Api-Key":           {},
}

type LoggingTransport struct {
	Base http.RoundTripper
	Log  logger.Logger
}

func (t *LoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	start := time.Now()
	t.Log.DebugContext(req.Context(), "trust: http request",
		"method", req.Method,
		"url", req.URL.Redacted(),
		"headers", redactHeaders(req.Header),
	)
	resp, err := base.RoundTrip(req)
	dur := time.Since(start)
	if err != nil {
		t.Log.ErrorContext(req.Context(), "trust: http error",
			"method", req.Method,
			"url", req.URL.Redacted(),
			"duration_ms", dur.Milliseconds(),
			"error", err,
		)
		return nil, err
	}
	t.Log.DebugContext(req.Context(), "trust: http response",
		"method", req.Method,
		"url", req.URL.Redacted(),
		"status", resp.StatusCode,
		"duration_ms", dur.Milliseconds(),
		"content_length", resp.ContentLength,
	)
	return resp, nil
}

func redactHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		if _, sensitive := redactedHeaders[http.CanonicalHeaderKey(k)]; sensitive {
			out[k] = []string{"[REDACTED]"}
			continue
		}
		out[k] = v
	}
	return out
}

func NewHTTPClient(log logger.Logger, insecure bool) *http.Client {
	var base = http.DefaultTransport
	if insecure {
		dt, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return &http.Client{Timeout: defaultHTTPTimeout, Transport: &LoggingTransport{Base: base, Log: log}}
		}
		t := dt.Clone()
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in via --insecure
		base = t
	}
	return &http.Client{
		Timeout:   defaultHTTPTimeout,
		Transport: &LoggingTransport{Base: base, Log: log},
	}
}
