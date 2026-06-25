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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFailurePolicy_String(t *testing.T) {
	assert.Equal(t, "fail-fast", FailurePolicyFailFast.String())
	assert.Equal(t, "continue", FailurePolicyContinue.String())
}

func TestIsValidFailurePolicy(t *testing.T) {
	tests := []struct {
		policy   string
		expected bool
	}{
		{"fail-fast", true},
		{"continue", true},
		{"", false},
		{"invalid", false},
		{"FAIL-FAST", false},
		{"CONTINUE", false},
	}

	for _, tt := range tests {
		t.Run(tt.policy, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsValidFailurePolicy(tt.policy))
		})
	}
}

func TestValidFailurePolicies(t *testing.T) {
	assert.Contains(t, ValidFailurePolicies, "fail-fast")
	assert.Contains(t, ValidFailurePolicies, "continue")
	assert.Len(t, ValidFailurePolicies, 2)
}
