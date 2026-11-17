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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	scanpredicate "github.com/thomsonreuters/stamp/pkg/predicates/scanresult/v1"
)

const snykSCAJSON = `{
  "vulnerabilities": [
    {
      "id": "SNYK-JS-LODASH-567746",
      "title": "Prototype Pollution",
      "CVSSv3": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cvssScore": 7.4,
      "severity": "high",
      "fixedIn": ["4.17.21"],
      "packageName": "lodash",
      "version": "4.17.20",
      "packageManager": "npm",
      "identifiers": { "CVE": ["CVE-2020-8203"], "CWE": ["CWE-1321"] },
      "epssDetails": { "probability": "0.012", "percentile": "0.84" }
    }
  ],
  "ok": false,
  "dependencyCount": 42,
  "packageManager": "npm",
  "projectName": "demo-app"
}`

func TestSnykLoader_SCA(t *testing.T) {
	pred, err := snykLoader{}.Load([]byte(snykSCAJSON), Options{ScanClass: scanpredicate.ScanClassSCA})
	require.NoError(t, err)

	assert.Equal(t, scanpredicate.ScanClassSCA, pred.ScanClass)
	assert.Equal(t, "snyk", pred.Scanner.Name)
	require.Len(t, pred.Findings, 1)

	f := pred.Findings[0]
	assert.Equal(t, "high", f.Severity)
	require.NotNil(t, f.Component)
	assert.Equal(t, "lodash", f.Component.Name)
	assert.Equal(t, "4.17.20", f.Component.Version)
	assert.Equal(t, "pkg:npm/lodash@4.17.20", f.Component.PURL)
	require.NotNil(t, f.Vulnerability)
	assert.Equal(t, "CVE-2020-8203", f.Vulnerability.ID)
	require.Len(t, f.Vulnerability.CVSS, 1)
	assert.InDelta(t, 7.4, f.Vulnerability.CVSS[0].Score, 0.001)
	require.NotNil(t, f.Vulnerability.EPSS)
	assert.Equal(t, "0.012", f.Vulnerability.EPSS.Probability)

	assert.Equal(t, 1, pred.Summary.Findings)
	assert.Equal(t, 1, pred.Summary.Components)
	assert.Equal(t, 1, pred.Summary.BySeverity["high"])
}

func TestSnykLoader_SCA_Array(t *testing.T) {
	pred, err := snykLoader{}.Load([]byte("["+snykSCAJSON+"]"), Options{ScanClass: scanpredicate.ScanClassSCA})
	require.NoError(t, err)
	require.Len(t, pred.Findings, 1)
	assert.Equal(t, "pkg:npm/lodash@4.17.20", pred.Findings[0].Component.PURL)
}

func TestSnykLoader_SCA_FallsBackToSnykID(t *testing.T) {
	const noCVE = `{
  "vulnerabilities": [
    { "id": "SNYK-JS-FOO-1", "severity": "medium", "packageName": "foo", "version": "1.0.0", "packageManager": "npm", "identifiers": {} }
  ],
  "packageManager": "npm"
}`
	pred, err := snykLoader{}.Load([]byte(noCVE), Options{ScanClass: scanpredicate.ScanClassSCA})
	require.NoError(t, err)
	require.Len(t, pred.Findings, 1)
	assert.Equal(t, "SNYK-JS-FOO-1", pred.Findings[0].Vulnerability.ID)
}

const snykSARIF = `{
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "SnykCode",
          "rules": [
            { "id": "javascript/Sqli", "helpUri": "https://snyk.io/rules/javascript/Sqli", "properties": { "cwe": ["CWE-89"] } }
          ]
        }
      },
      "results": [
        {
          "ruleId": "javascript/Sqli",
          "level": "error",
          "message": { "text": "Unsanitized input flows into a SQL query." },
          "locations": [
            { "physicalLocation": { "artifactLocation": { "uri": "src/db.js" }, "region": { "startLine": 42, "endLine": 44 } } }
          ]
        }
      ]
    }
  ]
}`

func TestSnykLoader_SAST(t *testing.T) {
	pred, err := snykLoader{}.Load([]byte(snykSARIF), Options{ScanClass: scanpredicate.ScanClassSAST})
	require.NoError(t, err)

	assert.Equal(t, scanpredicate.ScanClassSAST, pred.ScanClass)
	require.Len(t, pred.Findings, 1)

	f := pred.Findings[0]
	assert.Equal(t, "HIGH", f.Severity)
	assert.Equal(t, "Unsanitized input flows into a SQL query.", f.Title)
	require.NotNil(t, f.Rule)
	assert.Equal(t, "javascript/Sqli", f.Rule.ID)
	assert.Equal(t, "https://snyk.io/rules/javascript/Sqli", f.Rule.Link)
	require.NotNil(t, f.Weakness)
	assert.Equal(t, "CWE-89", f.Weakness.Name)
	require.NotNil(t, f.Location)
	assert.Equal(t, "src/db.js", f.Location.FilePath)
	assert.Equal(t, 42, f.Location.StartLine)

	assert.Equal(t, 1, pred.Summary.BySeverity["high"])
}

func TestSnykLoader_MissingScanClass(t *testing.T) {
	_, err := snykLoader{}.Load([]byte(snykSCAJSON), Options{})
	require.Error(t, err)
}

func TestSnykLoader_RejectsWrongShape(t *testing.T) {
	tests := []struct {
		name    string
		class   scanpredicate.ScanClass
		content string
		wantErr string
	}{
		{"sarif as sca", scanpredicate.ScanClassSCA, snykSARIF, "expected snyk test JSON"},
		{"sca as sast", scanpredicate.ScanClassSAST, snykSCAJSON, "expected snyk code SARIF JSON"},
		{"null sca", scanpredicate.ScanClassSCA, `null`, "expected snyk test JSON"},
		{"empty sca object", scanpredicate.ScanClassSCA, `{}`, "expected snyk test JSON"},
		{"empty sca array", scanpredicate.ScanClassSCA, `[]`, "expected snyk test JSON"},
		{"null vulnerabilities", scanpredicate.ScanClassSCA, `{"vulnerabilities":null}`, "expected snyk test JSON"},
		{"empty applications", scanpredicate.ScanClassSCA, `{"applications":[]}`, "expected snyk test JSON"},
		{"mixed sca reports", scanpredicate.ScanClassSCA, `[` + snykSCAJSON + `,{}]`, "report 1"},
		{"invalid nested application", scanpredicate.ScanClassSCA, `{"applications":[{"vulnerabilities":[]},{}]}`, "application 1"},
		{"null sast", scanpredicate.ScanClassSAST, `null`, "expected snyk code SARIF JSON"},
		{"empty sast object", scanpredicate.ScanClassSAST, `{}`, "expected snyk code SARIF JSON"},
		{"null runs", scanpredicate.ScanClassSAST, `{"runs":null}`, "expected snyk code SARIF JSON"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pred, err := snykLoader{}.Load([]byte(tt.content), Options{ScanClass: tt.class})
			require.ErrorContains(t, err, tt.wantErr)
			assert.Equal(t, scanpredicate.Predicate{}, pred)
		})
	}
}

func TestSnykLoader_EmptyFindings(t *testing.T) {
	tests := []struct {
		name    string
		class   scanpredicate.ScanClass
		content string
	}{
		{"sca object", scanpredicate.ScanClassSCA, `{"vulnerabilities":[]}`},
		{"sca array", scanpredicate.ScanClassSCA, `[{"vulnerabilities":[]}]`},
		{"nested sca", scanpredicate.ScanClassSCA, `{"applications":[{"applications":[{"vulnerabilities":[]}]}]}`},
		{"sast", scanpredicate.ScanClassSAST, `{"runs":[{"tool":{"driver":{"name":"SnykCode"}},"results":[]}]}`},
		{"sast omitted results", scanpredicate.ScanClassSAST, `{"runs":[{"tool":{"driver":{"name":"SnykCode"}}}]}`},
		{"sast empty runs", scanpredicate.ScanClassSAST, `{"runs":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pred, err := snykLoader{}.Load([]byte(tt.content), Options{ScanClass: tt.class})
			require.NoError(t, err)
			assert.Empty(t, pred.Findings)
			assert.Zero(t, pred.Summary.Findings)
			assert.Equal(t, scanpredicate.StatusSuccess, pred.Scan.Status)
		})
	}
}
