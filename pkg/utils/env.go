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

import (
	"fmt"
	"maps"
	"os"
	"strings"
)

const expectedEnvParts = 2

// BuildEnv parses environment variables and applies overrides.
func BuildEnv(baseEnv []string, overrides map[string]string) []string {
	envMap := make(map[string]string)

	for _, e := range baseEnv {
		parts := strings.SplitN(e, "=", expectedEnvParts)
		if len(parts) == expectedEnvParts {
			envMap[parts[0]] = parts[1]
		}
		// Silently skip malformed entries (no `=` found)
	}

	maps.Copy(envMap, overrides)

	result := make([]string, 0, len(envMap))
	for k, v := range envMap {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}

	return result
}

func ReadAllEnvVariables() map[string]string {
	envVariables := make(map[string]string)
	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", expectedEnvParts)
		if len(parts) == expectedEnvParts && parts[0] != "" {
			envVariables[parts[0]] = parts[1]
		}
	}
	return envVariables
}
