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

// Package purl builds Package URLs (purl) for dependency components from their
// ecosystem, name, and version. It is vendor-agnostic and used by the scan-result
// loaders to populate the PURL-first component identity of SCA findings.
package purl

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnsupportedEcosystem is the sentinel returned (wrapped) when ComponentPURL is
// asked to emit a package URL for an ecosystem that has not been explicitly
// implemented. Callers should treat this as a signal that the ecosystem must be
// added deliberately rather than silently degrading to a component without a PURL.
var ErrUnsupportedEcosystem = errors.New("unsupported package ecosystem")

// UnsupportedEcosystemError carries the offending ecosystem value alongside the
// ErrUnsupportedEcosystem sentinel so callers can both errors.Is it and report the
// specific ecosystem that needs implementing.
type UnsupportedEcosystemError struct {
	Ecosystem string
}

func (e *UnsupportedEcosystemError) Error() string {
	return fmt.Sprintf("%s: %q", ErrUnsupportedEcosystem.Error(), e.Ecosystem)
}

func (e *UnsupportedEcosystemError) Unwrap() error { return ErrUnsupportedEcosystem }

// ecosystemToPURLType maps scanner ecosystem labels (and common aliases) to their
// canonical Package-URL "type". Extend this map to support a new ecosystem.
var ecosystemToPURLType = map[string]string{
	"npm":       "npm",
	"maven":     "maven",
	"gradle":    "maven",
	"pypi":      "pypi",
	"pip":       "pypi",
	"python":    "pypi",
	"go":        "golang",
	"golang":    "golang",
	"gomodules": "golang",
	"gem":       "gem",
	"rubygems":  "gem",
	"ruby":      "gem",
	"nuget":     "nuget",
	"dotnet":    "nuget",
	"cargo":     "cargo",
	"crates":    "cargo",
	"rust":      "cargo",
	"composer":  "composer",
	"php":       "composer",
	"packagist": "composer",
	"apk":       "apk",
	"alpine":    "apk",
	"deb":       "deb",
	"debian":    "deb",
	"ubuntu":    "deb",
	"rpm":       "rpm",
	"redhat":    "rpm",
	"rhel":      "rpm",
	"hex":       "hex",
	"erlang":    "hex",
	"elixir":    "hex",
	"pub":       "pub",
	"dart":      "pub",
	"conan":     "conan",
	"swift":     "swift",
	"cocoapods": "cocoapods",
	"pod":       "cocoapods",
}

// ComponentPURL builds a Package URL (pkg: scheme) for a dependency component from
// its ecosystem, name, and version. An ecosystem that is empty or not present in
// the supported map yields a *UnsupportedEcosystemError so callers can require it
// to be explicitly implemented rather than emit a component with no PURL.
//
// Examples:
//   - ComponentPURL("npm", "lodash", "4.17.21")            -> pkg:npm/lodash@4.17.21
//   - ComponentPURL("Maven", "com.google:guava", "32.1.3") -> pkg:maven/com.google/guava@32.1.3
//   - ComponentPURL("golang", "github.com/x/y", "v1.2.3")  -> pkg:golang/github.com/x/y@v1.2.3
func ComponentPURL(ecosystem, name, version string) (string, error) {
	key := strings.ToLower(strings.TrimSpace(ecosystem))
	if key == "" {
		return "", &UnsupportedEcosystemError{Ecosystem: ecosystem}
	}

	purlType, ok := ecosystemToPURLType[key]
	if !ok {
		return "", &UnsupportedEcosystemError{Ecosystem: ecosystem}
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("component name is required to build a PURL")
	}

	var namespace string
	switch {
	case purlType == "maven" && strings.Contains(name, ":"):
		// Maven identifies packages as group:artifact; PURL splits into namespace/name.
		parts := strings.SplitN(name, ":", 2)
		namespace, name = parts[0], parts[1]
	case strings.LastIndex(name, "/") != -1:
		// Namespaced identity (Go module path, scoped npm package, etc.).
		idx := strings.LastIndex(name, "/")
		namespace, name = name[:idx], name[idx+1:]
	}

	var sb strings.Builder
	sb.WriteString("pkg:")
	sb.WriteString(purlType)
	sb.WriteString("/")
	if namespace != "" {
		sb.WriteString(namespace)
		sb.WriteString("/")
	}
	sb.WriteString(name)
	if version = strings.TrimSpace(version); version != "" {
		sb.WriteString("@")
		sb.WriteString(version)
	}
	return sb.String(), nil
}
