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

func TestTemporalPolicy_String(t *testing.T) {
	tests := []struct {
		name   string
		policy TemporalPolicy
		want   string
	}{
		{
			name:   "strict policy",
			policy: TemporalPolicyStrict,
			want:   "strict",
		},
		{
			name:   "warn policy",
			policy: TemporalPolicyWarn,
			want:   "warn",
		},
		{
			name:   "ignore policy",
			policy: TemporalPolicyIgnore,
			want:   "ignore",
		},
		{
			name:   "custom policy",
			policy: TemporalPolicy("custom"),
			want:   "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.policy.String())
		})
	}
}

func TestValidTemporalPolicies(t *testing.T) {
	assert.Len(t, ValidTemporalPolicies, 3)
	assert.Contains(t, ValidTemporalPolicies, TemporalPolicyStrict.String())
	assert.Contains(t, ValidTemporalPolicies, TemporalPolicyWarn.String())
	assert.Contains(t, ValidTemporalPolicies, TemporalPolicyIgnore.String())
}

func TestIsValidTemporalPolicy(t *testing.T) {
	tests := []struct {
		policy   string
		expected bool
	}{
		{"strict", true},
		{"warn", true},
		{"ignore", true},
		{"", false},
		{"invalid", false},
		{"STRICT", false},
	}

	for _, tt := range tests {
		t.Run(tt.policy, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsValidTemporalPolicy(tt.policy))
		})
	}
}
