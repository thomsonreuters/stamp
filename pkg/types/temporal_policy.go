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

package types

import "slices"

// TemporalPolicy defines how temporal validation is handled.
type TemporalPolicy string

func (p TemporalPolicy) String() string {
	return string(p)
}

const (
	TemporalPolicyStrict TemporalPolicy = "strict"
	TemporalPolicyWarn   TemporalPolicy = "warn"
	TemporalPolicyIgnore TemporalPolicy = "ignore"
)

// ValidTemporalPolicies contains all valid temporal policy values.
var ValidTemporalPolicies = []string{
	TemporalPolicyStrict.String(),
	TemporalPolicyWarn.String(),
	TemporalPolicyIgnore.String(),
}

// IsValidTemporalPolicy checks if the given value is a valid temporal policy.
func IsValidTemporalPolicy(policy string) bool {
	return slices.Contains(ValidTemporalPolicies, policy)
}
