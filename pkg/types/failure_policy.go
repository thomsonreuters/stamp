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

// FailurePolicy defines how pipeline execution handles errors.
type FailurePolicy string

// String returns the string representation of the failure policy.
func (f FailurePolicy) String() string {
	return string(f)
}

const (
	// FailurePolicyFailFast stops execution on first error.
	FailurePolicyFailFast FailurePolicy = "fail-fast"

	// FailurePolicyContinue continues execution despite errors.
	FailurePolicyContinue FailurePolicy = "continue"
)

// ValidFailurePolicies contains all valid failure policy values.
var ValidFailurePolicies = []string{
	string(FailurePolicyFailFast),
	string(FailurePolicyContinue),
}

// IsValidFailurePolicy checks if the given value is a valid failure policy.
func IsValidFailurePolicy(policy string) bool {
	return slices.Contains(ValidFailurePolicies, policy)
}
