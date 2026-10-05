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

package fulcio

import (
	"net/url"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
)

// deriveAudienceFromURL extracts the hostname from a URL to use as the JWT audience.
func deriveAudienceFromURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", pkgerrors.NewWithContext("fulcio", "audience", "Fulcio URL is required to derive audience")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", pkgerrors.WrapWithContext(err, "fulcio", "audience", "failed to parse Fulcio URL")
	}

	if parsed.Host == "" {
		return "", pkgerrors.NewWithContext("fulcio", "audience", "Fulcio URL has no host")
	}

	return parsed.Host, nil
}
