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

func TestIsValidOutputMode(t *testing.T) {
	tests := []struct {
		mode     string
		expected bool
	}{
		{"individual", true},
		{"collection", true},
		{"both", true},
		{"", false},
		{"invalid", false},
		{"INDIVIDUAL", false},
		{"COLLECTION", false},
		{"BOTH", false},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsValidOutputMode(tt.mode))
		})
	}
}

func TestValidOutputModes(t *testing.T) {
	assert.Contains(t, ValidOutputModes, "individual")
	assert.Contains(t, ValidOutputModes, "collection")
	assert.Contains(t, ValidOutputModes, "both")
	assert.Len(t, ValidOutputModes, 3)
}

func TestOutputModeConstants(t *testing.T) {
	assert.Equal(t, "individual", OutputModeIndividual.String())
	assert.Equal(t, "collection", OutputModeCollection.String())
	assert.Equal(t, "both", OutputModeBoth.String())
}
