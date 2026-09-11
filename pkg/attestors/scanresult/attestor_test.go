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

// Real 64-character lowercase hex SHA-256 digests for subject binding tests.
const (
	validSHA256    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	validSHA256Alt = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
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
		Scan:      scanpredicate.Scan{Status: scanpredicate.StatusSuccess},
		Scanner:   scanpredicate.Scanner{Name: "wiz"},
		Inventory: &scanpredicate.Inventory{
			Format: "cyclonedx-json",
			Digest: &scanpredicate.Digest{SHA256: validSHA256},
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
	assert.Equal(t, validSHA256, subjects[0].Digest["sha256"])
}

func TestAttest_SubjectDigestOverride(t *testing.T) {
	p := scanpredicate.Predicate{
		ScanClass: scanpredicate.ScanClassSCA,
		Scan:      scanpredicate.Scan{Status: scanpredicate.StatusSuccess},
		Summary:   scanpredicate.Summary{BySeverity: map[string]int{}},
	}
	path := writeReport(t, p)

	a := newTestAttestor()
	cfg := core.Config{
		keyReportPath:    path,
		keySubjectDigest: validSHA256Alt,
		keySubjectName:   "sbom+app.cdx.json",
	}
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.NoError(t, a.Attest(context.Background(), cfg))

	subjects := a.Subjects(cfg)
	require.Len(t, subjects, 1)
	assert.Equal(t, "sbom+app.cdx.json", subjects[0].Name)
	assert.Equal(t, validSHA256Alt, subjects[0].Digest["sha256"])
}

// Item 1: malformed SHA-256 subject digests must be rejected, not signed.
func TestAttest_RejectsInvalidSubjectDigest(t *testing.T) {
	p := scanpredicate.Predicate{
		ScanClass: scanpredicate.ScanClassSCA,
		Scan:      scanpredicate.Scan{Status: scanpredicate.StatusSuccess},
		Summary:   scanpredicate.Summary{BySeverity: map[string]int{}},
	}
	path := writeReport(t, p)

	badDigests := map[string]string{
		"short":     "abc123",
		"uppercase": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
		"non-hex":   "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"prefixed":  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b785",
	}
	for name, digest := range badDigests {
		t.Run(name, func(t *testing.T) {
			a := newTestAttestor()
			cfg := core.Config{keyReportPath: path, keySubjectDigest: digest}
			require.NoError(t, a.PreAttest(context.Background(), cfg))
			require.Error(t, a.Attest(context.Background(), cfg))
		})
	}
}

// Item 1: a malformed inventory digest must be rejected before it becomes the subject.
func TestAttest_RejectsInvalidInventoryDigest(t *testing.T) {
	p := scanpredicate.Predicate{
		ScanClass: scanpredicate.ScanClassSCA,
		Scan:      scanpredicate.Scan{Status: scanpredicate.StatusSuccess},
		Scanner:   scanpredicate.Scanner{Name: "wiz"},
		Inventory: &scanpredicate.Inventory{Digest: &scanpredicate.Digest{SHA256: "deadbeef"}},
		Summary:   scanpredicate.Summary{BySeverity: map[string]int{}},
	}
	path := writeReport(t, p)

	a := newTestAttestor()
	cfg := core.Config{keyReportPath: path}
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.Error(t, a.Attest(context.Background(), cfg))
}

// Item 1: ValidateConfig rejects a malformed --subject-digest up front.
func TestValidateConfig_RejectsInvalidSubjectDigest(t *testing.T) {
	path := writeReport(t, scanpredicate.Predicate{ScanClass: scanpredicate.ScanClassSAST})
	a := newTestAttestor()
	err := a.ValidateConfig(core.Config{keyReportPath: path, keySubjectDigest: "nothex"})
	require.Error(t, err)
}

// Item 2: an unknown/misspelled top-level field must be rejected, not dropped.
func TestAttest_RejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan-result.json")
	raw := `{"scanClass":"sast","scan":{"status":"success"},"findings":[],"summary":{"findings":0,"bySeverity":{}},"scanClas":"typo"}`
	require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))

	a := newTestAttestor()
	cfg := core.Config{keyReportPath: path}
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.Error(t, a.Attest(context.Background(), cfg))
}

// Item 2: a summary whose finding count disagrees with len(findings) is rejected.
func TestAttest_RejectsInconsistentSummary(t *testing.T) {
	p := scanpredicate.Predicate{
		ScanClass: scanpredicate.ScanClassSAST,
		Scan:      scanpredicate.Scan{Status: scanpredicate.StatusSuccess},
		Scanner:   scanpredicate.Scanner{Name: "wiz"},
		Findings:  []scanpredicate.Finding{{ID: "f1"}},
		Summary:   scanpredicate.Summary{Findings: 5, BySeverity: map[string]int{}},
	}
	path := writeReport(t, p)

	a := newTestAttestor()
	cfg := core.Config{keyReportPath: path}
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.Error(t, a.Attest(context.Background(), cfg))
}

// Item 2: a report with an unrecognized scan status is rejected.
func TestAttest_RejectsUnknownScanStatus(t *testing.T) {
	p := scanpredicate.Predicate{
		ScanClass: scanpredicate.ScanClassSAST,
		Scan:      scanpredicate.Scan{Status: scanpredicate.ScanStatus("bogus")},
		Scanner:   scanpredicate.Scanner{Name: "wiz"},
		Summary:   scanpredicate.Summary{BySeverity: map[string]int{}},
	}
	path := writeReport(t, p)

	a := newTestAttestor()
	cfg := core.Config{keyReportPath: path}
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.Error(t, a.Attest(context.Background(), cfg))
}

// Item 2: a well-formed, self-consistent report still passes (happy path).
func TestAttest_HappyPathPasses(t *testing.T) {
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

// Item 3: the generated schema must enforce the required-field contract.
func TestSchema_MarksRequiredFields(t *testing.T) {
	a := newTestAttestor()
	schema := a.Schema()
	require.NotNil(t, schema)

	def, ok := schema.Definitions["Predicate"]
	require.True(t, ok, "Predicate definition must be present in schema")

	for _, field := range []string{"schemaVersion", "scanClass", "scan", "scanner", "findings", "summary"} {
		assert.Contains(t, def.Required, field, "field %q must be marked required", field)
	}
}
