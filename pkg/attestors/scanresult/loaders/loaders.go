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

// Package loaders converts scanner output into the vendor-neutral scan-result
// predicate. Each input format (a ready predicate, a stamp-owned normalized
// findings document, or a supported scanner's native output) is handled by a
// registered Loader, keyed by the attestor's input-format configuration. This
// keeps all scanner-format awareness inside stamp so a standalone stamp CLI can
// turn scanner output into a signed attestation without an external normalizer.
package loaders

import (
	"fmt"
	"sort"

	scanpredicate "github.com/thomsonreuters/stamp/pkg/predicates/scanresult/v1"
)

// Input format identifiers accepted by the scan-result attestor.
const (
	// FormatPredicate ingests an already-built scan-result predicate JSON file.
	// It is the default and preserves backward compatibility.
	FormatPredicate = "predicate"
	// FormatNormalized ingests the stamp-owned vendor-neutral normalized findings
	// document. Producers (e.g. SecPipe) map their scanner output onto this schema.
	FormatNormalized = "normalized"
	// FormatSnyk ingests native Snyk output: `snyk test --json` for SCA and the
	// SARIF emitted by `snyk code test --sarif` for SAST. Reference loader.
	FormatSnyk = "snyk"
)

// Options carries scan-level context the attestor resolves from configuration and
// passes to a loader. ScanClass selects which findings a loader emits and, for
// native scanner output, which section of the report to parse.
type Options struct {
	ScanClass scanpredicate.ScanClass
}

// Loader turns raw input bytes into a scan-result predicate.
type Loader interface {
	// Load parses content into a predicate. It must not hash or sign; the attestor
	// owns digesting the raw input and binding the subject.
	Load(content []byte, opts Options) (scanpredicate.Predicate, error)
}

var registry = map[string]Loader{
	FormatPredicate:  predicateLoader{},
	FormatNormalized: normalizedLoader{},
	FormatSnyk:       snykLoader{},
}

// Get returns the loader registered for the given input format.
func Get(format string) (Loader, error) {
	l, ok := registry[format]
	if !ok {
		return nil, fmt.Errorf("unsupported input-format %q; supported: %v", format, Formats())
	}
	return l, nil
}

// IsValidFormat reports whether format has a registered loader.
func IsValidFormat(format string) bool {
	_, ok := registry[format]
	return ok
}

// Formats returns the registered input formats in sorted order.
func Formats() []string {
	formats := make([]string, 0, len(registry))
	for f := range registry {
		formats = append(formats, f)
	}
	sort.Strings(formats)
	return formats
}
