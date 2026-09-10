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

package scanresult

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/crypto/hash"
	"github.com/thomsonreuters/stamp/pkg/logger"
	scanpredicate "github.com/thomsonreuters/stamp/pkg/predicates/scanresult/v1"
)

func newTestAttestor() *Attestor {
	return &Attestor{
		logger: logger.NewNoop(),
		hasher: hash.New(hash.Config{Algorithms: []string{hash.AlgorithmSHA256}}),
	}
}

func writeReport(t *testing.T, p scanpredicate.Predicate) string {
	t.Helper()
	data, err := json.Marshal(p)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "scan-result.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestIdentity(t *testing.T) {
	a := newTestAttestor()
	assert.Equal(t, "scan-result", a.ID())
	assert.Equal(t, "https://github.com/thomsonreuters/stamp/scan-result/v1", a.PredicateURI())
	assert.NotEmpty(t, a.Name())
	assert.NotEmpty(t, a.Description())
}

func TestValidateConfig(t *testing.T) {
	path := writeReport(t, scanpredicate.Predicate{ScanClass: scanpredicate.ScanClassSAST})
	a := newTestAttestor()

	require.NoError(t, a.ValidateConfig(core.Config{keyReportPath: path}))

	err := a.ValidateConfig(core.Config{})
	require.Error(t, err, "missing report-path must fail")

	err = a.ValidateConfig(core.Config{keyReportPath: filepath.Join(t.TempDir(), "missing.json")})
	require.Error(t, err, "non-existent report must fail")

	err = a.ValidateConfig(core.Config{keyReportPath: path, keyScanClass: "secrets"})
	require.Error(t, err, "invalid scan-class must fail")
}

func TestAttest_SAST_SubjectIsReportDigest(t *testing.T) {
	p := scanpredicate.Predicate{
		ScanClass: scanpredicate.ScanClassSAST,
		Scan:      scanpredicate.Scan{Status: scanpredicate.StatusSuccess},
		Scanner:   scanpredicate.Scanner{Name: "wiz"},
		Findings:  []scanpredicate.Finding{{ID: "f1", Severity: "HIGH"}},
		Summary:   scanpredicate.Summary{Findings: 1, BySeverity: map[string]int{"high": 1}},
	}
	path := writeReport(t, p)

	a := newTestAttestor()
	cfg := core.Config{keyReportPath: path}
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.NoError(t, a.Attest(context.Background(), cfg))

	subjects := a.Subjects(cfg)
	require.Len(t, subjects, 1)
	assert.Equal(t, "scan-result+sast", subjects[0].Name)
	assert.NotEmpty(t, subjects[0].Digest["sha256"])

	pred, err := a.GeneratePredicate(cfg)
	require.NoError(t, err)
	got, ok := pred.(scanpredicate.Predicate)
	require.True(t, ok)
	assert.Equal(t, scanpredicate.ScanClassSAST, got.ScanClass)
	assert.Equal(t, scanpredicate.SchemaVersion, got.SchemaVersion)
}

func TestAttest_SCA_SubjectPrefersInventoryDigest(t *testing.T) {
	p := scanpredicate.Predicate{
		ScanClass: scanpredicate.ScanClassSCA,
		Scanner:   scanpredicate.Scanner{Name: "wiz"},
		Inventory: &scanpredicate.Inventory{
			Format: "cyclonedx-json",
			Digest: &scanpredicate.Digest{SHA256: "deadbeefdeadbeef"},
		},
		Summary: scanpredicate.Summary{BySeverity: map[string]int{}},
	}
	path := writeReport(t, p)

	a := newTestAttestor()
	cfg := core.Config{keyReportPath: path}
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.NoError(t, a.Attest(context.Background(), cfg))

	subjects := a.Subjects(cfg)
	require.Len(t, subjects, 1)
	assert.Equal(t, "deadbeefdeadbeef", subjects[0].Digest["sha256"])
}

func TestAttest_SubjectDigestOverride(t *testing.T) {
	p := scanpredicate.Predicate{ScanClass: scanpredicate.ScanClassSCA, Summary: scanpredicate.Summary{BySeverity: map[string]int{}}}
	path := writeReport(t, p)

	a := newTestAttestor()
	cfg := core.Config{
		keyReportPath:    path,
		keySubjectDigest: "abc123",
		keySubjectName:   "sbom+app.cdx.json",
	}
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.NoError(t, a.Attest(context.Background(), cfg))

	subjects := a.Subjects(cfg)
	require.Len(t, subjects, 1)
	assert.Equal(t, "sbom+app.cdx.json", subjects[0].Name)
	assert.Equal(t, "abc123", subjects[0].Digest["sha256"])
}

func TestAttest_InvalidScanClassFails(t *testing.T) {
	// A report with no scan class and no override must be rejected during Attest.
	path := writeReport(t, scanpredicate.Predicate{Summary: scanpredicate.Summary{BySeverity: map[string]int{}}})

	a := newTestAttestor()
	cfg := core.Config{keyReportPath: path}
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.Error(t, a.Attest(context.Background(), cfg))
}

func TestSchema(t *testing.T) {
	a := newTestAttestor()
	schema := a.Schema()
	require.NotNil(t, schema)
	assert.Equal(t, "Scan Result Attestation", schema.Title)
}
