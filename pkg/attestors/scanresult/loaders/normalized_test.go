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

package loaders

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	scanpredicate "github.com/thomsonreuters/stamp/pkg/predicates/scanresult/v1"
)

func sampleInput() NormalizedInput {
	return NormalizedInput{
		ScanID:  "scan-123",
		Scanner: NormalizedScanner{Name: "wiz"},
		Findings: []NormalizedFinding{
			{
				ScanType:  "sast",
				Severity:  "HIGH",
				RuleID:    "sql-injection",
				RuleLink:  "https://example/rules/sql",
				Title:     "SQL Injection",
				Details:   "Untrusted input reaches a query",
				Category:  "CWE-89 Improper Neutralization",
				FilePath:  "app/db.go",
				StartLine: 10,
				EndLine:   12,
				CommitID:  "abc123",
				RepoURL:   "https://github.com/tr/secpipe",
			},
			{
				ScanType:            "vulnerability",
				Severity:            "CRITICAL",
				RuleID:              "CVE-2021-12345",
				PackageName:         "lodash@4.17.21",
				Ecosystem:           "npm",
				VulnerabilitySource: "NVD",
				CVSSv3:              "CVSS:3.1/AV:N",
				CVSSv3Score:         9.8,
				FixedIn:             []string{"4.17.22"},
				HasCisaKevExploit:   true,
				CisaKevDueDate:      "2026-01-01",
				EPSSProbability:     "0.5",
			},
		},
	}
}

func marshalInput(t *testing.T, in NormalizedInput) []byte {
	t.Helper()
	data, err := json.Marshal(in)
	require.NoError(t, err)
	return data
}

func TestNormalizedLoader_SAST(t *testing.T) {
	pred, err := normalizedLoader{}.Load(marshalInput(t, sampleInput()), Options{ScanClass: scanpredicate.ScanClassSAST})
	require.NoError(t, err)

	assert.Equal(t, scanpredicate.ScanClassSAST, pred.ScanClass)
	assert.Equal(t, scanpredicate.SchemaVersion, pred.SchemaVersion)
	assert.Equal(t, "scan-123", pred.Scan.ID)
	require.Len(t, pred.Findings, 1)

	f := pred.Findings[0]
	assert.Equal(t, "SQL Injection", f.Title)
	require.NotNil(t, f.Rule)
	assert.Equal(t, "sql-injection", f.Rule.ID)
	require.NotNil(t, f.Weakness)
	assert.Equal(t, "CWE-89 Improper Neutralization", f.Weakness.Name)
	require.NotNil(t, f.Location)
	assert.Equal(t, "app/db.go", f.Location.FilePath)
	require.NotNil(t, f.Source)
	assert.Equal(t, "abc123", f.Source.CommitID)
	assert.Nil(t, f.Component)
	assert.Nil(t, f.Vulnerability)
	assert.NotEmpty(t, f.ID)

	assert.Equal(t, 1, pred.Summary.Findings)
	assert.Equal(t, 1, pred.Summary.BySeverity["high"])
	assert.Zero(t, pred.Summary.Components)
}

func TestNormalizedLoader_SCA(t *testing.T) {
	in := sampleInput()
	in.Inventory = &NormalizedInventory{Format: "cyclonedx-json", Digest: "deadbeef"}
	in.RawReport = &NormalizedArtifact{URI: "s3://bucket/report.json", Digest: "cafebabe"}

	pred, err := normalizedLoader{}.Load(marshalInput(t, in), Options{ScanClass: scanpredicate.ScanClassSCA})
	require.NoError(t, err)

	assert.Equal(t, scanpredicate.ScanClassSCA, pred.ScanClass)
	require.NotNil(t, pred.Inventory)
	assert.Equal(t, "deadbeef", pred.Inventory.Digest.SHA256)
	require.NotNil(t, pred.RawReport)
	assert.Equal(t, "cafebabe", pred.RawReport.Digest.SHA256)

	require.Len(t, pred.Findings, 1)
	f := pred.Findings[0]
	require.NotNil(t, f.Component)
	assert.Equal(t, "lodash", f.Component.Name)
	assert.Equal(t, "4.17.21", f.Component.Version)
	assert.Equal(t, "pkg:npm/lodash@4.17.21", f.Component.PURL)
	require.NotNil(t, f.Vulnerability)
	assert.Equal(t, "CVE-2021-12345", f.Vulnerability.ID)
	require.Len(t, f.Vulnerability.CVSS, 1)
	assert.InDelta(t, 9.8, f.Vulnerability.CVSS[0].Score, 0.001)
	require.NotNil(t, f.Vulnerability.KEV)
	assert.True(t, f.Vulnerability.KEV.Known)
	require.NotNil(t, f.Vulnerability.EPSS)

	assert.Equal(t, 1, pred.Summary.Findings)
	assert.Equal(t, 1, pred.Summary.Components)
	assert.Equal(t, 1, pred.Summary.BySeverity["critical"])
}

func TestNormalizedLoader_NoEcosystemOmitsPURL(t *testing.T) {
	in := sampleInput()
	in.Findings[1].Ecosystem = ""

	pred, err := normalizedLoader{}.Load(marshalInput(t, in), Options{ScanClass: scanpredicate.ScanClassSCA})
	require.NoError(t, err)
	require.Len(t, pred.Findings, 1)
	assert.Empty(t, pred.Findings[0].Component.PURL)
}

func TestNormalizedLoader_UnsupportedEcosystemFails(t *testing.T) {
	in := sampleInput()
	in.Findings[1].Ecosystem = "cobol-packages"

	_, err := normalizedLoader{}.Load(marshalInput(t, in), Options{ScanClass: scanpredicate.ScanClassSCA})
	require.Error(t, err)
}

func TestNormalizedLoader_InvalidClass(t *testing.T) {
	_, err := normalizedLoader{}.Load(marshalInput(t, sampleInput()), Options{ScanClass: scanpredicate.ScanClass("secrets")})
	require.Error(t, err)
}

func TestNormalizedLoader_UnknownFieldFailsClosed(t *testing.T) {
	_, err := normalizedLoader{}.Load([]byte(`{"findings":[],"unexpected":true}`), Options{ScanClass: scanpredicate.ScanClassSAST})
	require.Error(t, err)
}

func TestSplitPackage(t *testing.T) {
	name, version := splitPackage("lodash@4.17.21")
	assert.Equal(t, "lodash", name)
	assert.Equal(t, "4.17.21", version)

	name, version = splitPackage("openssl")
	assert.Equal(t, "openssl", name)
	assert.Empty(t, version)
}
