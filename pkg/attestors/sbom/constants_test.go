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

package sbom

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidationBehavior_String(t *testing.T) {
	tests := []struct {
		name     string
		behavior ValidationBehavior
		expected string
	}{
		{
			name:     "Allow",
			behavior: ValidationBehaviorAllow,
			expected: "allow",
		},
		{
			name:     "Warn",
			behavior: ValidationBehaviorWarn,
			expected: "warn",
		},
		{
			name:     "Fail",
			behavior: ValidationBehaviorFail,
			expected: "fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.behavior.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidationBehaviorConstants(t *testing.T) {
	assert.Equal(t, ValidationBehaviorAllow, ValidationBehavior("allow"))
	assert.Equal(t, ValidationBehaviorWarn, ValidationBehavior("warn"))
	assert.Equal(t, ValidationBehaviorFail, ValidationBehavior("fail"))
}

func TestValidationBehaviorValues(t *testing.T) {
	assert.Len(t, ValidationBehaviorValues, 3)
	assert.Contains(t, ValidationBehaviorValues, ValidationBehaviorAllow)
	assert.Contains(t, ValidationBehaviorValues, ValidationBehaviorWarn)
	assert.Contains(t, ValidationBehaviorValues, ValidationBehaviorFail)
}
