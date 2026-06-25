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

package flags

import (
	"fmt"

	plugincobra "github.com/thomsonreuters/stamp/plugins/cobra"
)

// GetAllFlagGroups returns all flag groups defined in the registry.
func GetAllFlagGroups() map[string]plugincobra.FlagGroup {
	return map[string]plugincobra.FlagGroup{
		"execution":     ExecutionFlags,
		"fetch":         FetchFlags,
		"fulcio:server": FulcioServerFlags,
		"generate-key":  GenerateKeyFlags,
		"global":        GlobalFlags,
		"keys:private":  PrivateKeyFlags,
		"keys:public":   PublicKeyFlags,
		"list":          ListFlags,
		"output":        OutputFlags,
		"password":      PasswordFlags,
		"rekor:enable":  RekorEnableFlags,
		"rekor:server":  RekorServerFlags,
		"rekor:upload":  RekorUploadFlags,
		"run":           RunFlags,
		"security":      SecurityFlags,
		"signing":       SigningFlags,
		"upload":        UploadFlags,
		"verify":        VerifyFlags,
	}
}

// AllGroups returns all flag groups as a slice for use with validation functions.
func AllGroups() []plugincobra.FlagGroup {
	groups := GetAllFlagGroups()
	result := make([]plugincobra.FlagGroup, 0, len(groups))
	for _, g := range groups {
		result = append(result, g)
	}
	return result
}

// ValidateAllGroups validates all flag groups for consistency.
func ValidateAllGroups() error {
	for groupName, group := range GetAllFlagGroups() {
		for flagName, def := range group {
			if flagName != def.Name {
				return fmt.Errorf("%w: group %s, key %s, flag name %s", plugincobra.ErrFlagNameMismatch, groupName, flagName, def.Name)
			}

			if err := def.Validate(); err != nil {
				return fmt.Errorf("%w: group %s, flag %s: %w", plugincobra.ErrFlagValidation, groupName, flagName, err)
			}
		}
	}
	return nil
}

// init performs registry validation at package initialization.
func init() {
	if err := ValidateAllGroups(); err != nil {
		panic(fmt.Sprintf("flag registry validation failed: %v", err))
	}
}
