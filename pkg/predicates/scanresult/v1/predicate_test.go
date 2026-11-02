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

package v1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPredicateURI(t *testing.T) {
	assert.Equal(t, "https://github.com/thomsonreuters/stamp/scan-result/v1", PredicateURI)
}

func TestScanClass_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		class ScanClass
		valid bool
	}{
		{"sast", ScanClassSAST, true},
		{"sca", ScanClassSCA, true},
		{"unknown", ScanClass("secrets"), false},
		{"empty", ScanClass(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.class.IsValid())
			assert.Equal(t, string(tt.class), tt.class.String())
		})
	}
}

func TestPredicate_RoundTrip_SAST(t *testing.T) {
	p := Predicate{
		SchemaVersion: SchemaVersion,
		ScanClass:     ScanClassSAST,
		Scan:          Scan{Status: StatusSuccess, Scope: "source"},
		Scanner:       Scanner{Name: "wiz"},
		Findings: []Finding{
			{
				ID:       "finding-1",
				Severity: "HIGH",
				Title:    "SQL Injection",
				Rule:     &Rule{ID: "sql-injection"},
				Weakness: &Weakness{ID: "CWE-89", Name: "SQL Injection"},
				Location: &Location{FilePath: "app/db.go", StartLine: 10, EndLine: 12},
				Source:   &SCMContext{CommitID: "abc123"},
			},
		},
		Summary: Summary{Findings: 1, BySeverity: map[string]int{"high": 1}},
	}

	data, err := json.Marshal(p)
	require.NoError(t, err)

	var got Predicate
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, p, got)

	// SCA-only fields must be absent for a SAST predicate.
	assert.NotContains(t, string(data), "\"inventory\"")
	assert.NotContains(t, string(data), "\"component\"")
	assert.NotContains(t, string(data), "\"vulnerability\"")
}

func TestPredicate_RoundTrip_SCA(t *testing.T) {
	direct := false
	p := Predicate{
		SchemaVersion: SchemaVersion,
		ScanClass:     ScanClassSCA,
		Scan:          Scan{Status: StatusSuccess, Scope: "sbom"},
		Scanner: Scanner{
			Name:     "wiz",
			Database: &ScannerDB{Name: "wiz-advisory-db", Version: "2026-09-08"},
		},
		Inventory: &Inventory{
			Format: "cyclonedx-json",
			Digest: &Digest{SHA256: "deadbeef"},
		},
		Findings: []Finding{
			{
				ID:       "finding-2",
				Severity: "CRITICAL",
				Component: &Component{
					PURL:      "pkg:npm/lodash@4.17.21",
					Name:      "lodash",
					Version:   "4.17.21",
					Ecosystem: "npm",
					Direct:    &direct,
				},
				Vulnerability: &Vulnerability{
					ID:            "CVE-2021-12345",
					Source:        "NVD",
					FixedVersions: []string{"4.17.22"},
					CVSS:          []CVSS{{Version: "3.1", Source: "NVD", Score: 9.8}},
					KEV:           &KEV{Known: true},
				},
			},
		},
		Summary: Summary{Components: 1, Findings: 1, BySeverity: map[string]int{"critical": 1}},
		RawReport: &Artifact{
			MediaType: "application/json",
			URI:       "s3://bucket/report.json",
			Digest:    &Digest{SHA256: "cafebabe"},
		},
	}

	data, err := json.Marshal(p)
	require.NoError(t, err)

	var got Predicate
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, p, got)
}
