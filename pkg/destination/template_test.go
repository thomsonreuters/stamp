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

package destination

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveTemplate(t *testing.T) {
	tests := []struct {
		name         string
		template     string
		attestation  *Attestation
		workflowName string
		expected     string
		wantErr      bool
	}{
		{
			name:     "empty template returns empty string",
			template: "",
			expected: "",
		},
		{
			name:     "resolves id and attestor from dollar-brace syntax",
			template: "attestations/${id}/${attestor}.json",
			attestation: &Attestation{
				ID:         "abc-123",
				AttestorID: "git",
			},
			expected: "attestations/abc-123/git.json",
		},
		{
			name:     "resolves go-template dot syntax equivalently",
			template: "attestations/{{.id}}/{{.attestor}}.json",
			attestation: &Attestation{
				ID:         "abc-123",
				AttestorID: "git",
			},
			expected: "attestations/abc-123/git.json",
		},
		{
			name:     "resolves go-template dot syntax equivalently",
			template: "attestations/{{ .id}}/{{.attestor }}.json",
			attestation: &Attestation{
				ID:         "abc-123",
				AttestorID: "git",
			},
			expected: "attestations/abc-123/git.json",
		},
		{
			name:     "sanitizes predicate type for path and derives short predicate type",
			template: "${predicate_type}/${short_predicate_type}.json",
			attestation: &Attestation{
				PredicateType: "https://slsa.dev/provenance/v1",
			},
			expected: "https_slsa.dev_provenance_v1/provenance_v1.json",
		},
		{
			name:         "workflowName parameter takes precedence over attestation workflow name",
			template:     "${workflow}.json",
			attestation:  &Attestation{WorkflowName: "attestation-workflow"},
			workflowName: "param-workflow",
			expected:     "param-workflow.json",
		},
		{
			name:        "falls back to attestation workflow name when parameter is empty",
			template:    "${workflow}.json",
			attestation: &Attestation{WorkflowName: "attestation-workflow"},
			expected:    "attestation-workflow.json",
		},
		{
			name:     "resolves environment variable with default when unset",
			template: "${TEST_STAMP_RESOLVE_TEMPLATE_UNSET_VAR:fallback}.json",
			expected: "fallback.json",
		},
		{
			// ${id} has no value (nil attestation) and there's no ID env var either,
			// so it can't be resolved either as a template variable or as a fallback
			// environment variable.
			name:     "errors when a dollar-brace variable has no value and no env var fallback",
			template: "${id}/${attestor}.json",
			wantErr:  true,
		},
		{
			// Unlike ${var}, {{.var}} has no environment-variable fallback, so an
			// unresolved name always errors.
			name:     "errors when a go-template dot variable is unresolved",
			template: "attestations/{{.id}}.json",
			wantErr:  true,
		},
		{
			// "unknown_var" isn't a known template variable and isn't set as an
			// environment variable, and no default was given.
			name:     "errors on an unknown variable with no env var and no default",
			template: "${unknown_var}.json",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := ResolveTemplate(tt.template, tt.attestation, tt.workflowName)
			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, actual)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
