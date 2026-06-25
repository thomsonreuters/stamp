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

package utils

import "net/url"

// SanitizeURL strips any embedded credentials (userinfo) from a URL.
// This prevents accidental leaking of PATs or passwords in logs and attestations.
func SanitizeURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err == nil && parsed.User != nil {
		parsed.User = nil
		return parsed.String()
	}
	return rawURL
}
