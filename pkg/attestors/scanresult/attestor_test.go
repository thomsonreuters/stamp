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
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/attestors/scanresult/loaders"
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

func writeReport(t *testing.T, in loaders.NormalizedInput) string {
	t.Helper()
	data, err := json.Marshal(in)
	require.NoError(t, err)
	return writeRawReport(t, string(data))
}

// keepTmpEnv, when set to a true value, preserves test report files for inspection.
const keepTmpEnv = "SCANRESULT_ATTESTOR_KEEP_TMP"

func keepTmp() bool {
	keep, err := strconv.ParseBool(os.Getenv(keepTmpEnv))
	return err == nil && keep
}

func writeRawReport(t *testing.T, raw string) string {
	t.Helper()
	if keepTmp() {
		// t.TempDir is always removed by the testing package, so use a directory
		// that outlives the test run.
		dir, err := os.MkdirTemp("", "scanresult-attestor-") //nolint:usetesting // t.TempDir would delete the kept report
		require.NoError(t, err)
		path := filepath.Join(dir, "scan-result.json")
		require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))
		t.Logf("%s set; keeping report at %s", keepTmpEnv, path)
		return path
	}

	path := filepath.Join(t.TempDir(), "scan-result.json")
	require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))
	cleanupReport(t, path)
	return path
}

// cleanupReport registers a t.Cleanup that removes the scan-result.json written
// for a test so no report file survives the run.
func cleanupReport(t *testing.T, path string) {
	t.Helper()
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Errorf("cleanup: removing %s: %v", path, err)
		}
	})
}

func sastInput() loaders.NormalizedInput {
	return loaders.NormalizedInput{
		Scanner: loaders.NormalizedScanner{Name: "wiz"},
		Scan:    loaders.NormalizedScan{Status: "success"},
		Findings: []loaders.NormalizedFinding{
			{ScanType: "sast", Severity: "HIGH", RuleID: "rule-1", FilePath: "main.go", StartLine: 10},
		},
	}
}

func scaInput() loaders.NormalizedInput {
	return loaders.NormalizedInput{
		Scanner:  loaders.NormalizedScanner{Name: "wiz"},
		Scan:     loaders.NormalizedScan{Status: "success"},
		Findings: []loaders.NormalizedFinding{},
	}
}

func TestIdentity(t *testing.T) {
	a := newTestAttestor()
	assert.Equal(t, "scan-result", a.ID())
	assert.Equal(t, "https://github.com/thomsonreuters/stamp/scan-result/v1", a.PredicateURI())
	assert.NotEmpty(t, a.Name())
	assert.NotEmpty(t, a.Description())
}

func TestValidateConfig(t *testing.T) {
	path := writeReport(t, sastInput())
	a := newTestAttestor()

	require.NoError(t, a.ValidateConfig(core.Config{keyReportPath: path, keyScanClass: "sast"}))

	err := a.ValidateConfig(core.Config{keyScanClass: "sast"})
	require.Error(t, err, "missing report-path must fail")

	err = a.ValidateConfig(core.Config{
		keyReportPath: filepath.Join(t.TempDir(), "missing.json"),
		keyScanClass:  "sast",
	})
	require.Error(t, err, "non-existent report must fail")

	err = a.ValidateConfig(core.Config{keyReportPath: path, keyScanClass: "secrets"})
	require.Error(t, err, "invalid scan-class must fail")
}

// The normalized format is the default when input-format is omitted.
func TestAttest_DefaultsToNormalizedInputFormat(t *testing.T) {
	path := writeReport(t, sastInput())

	a := newTestAttestor()
	cfg := core.Config{keyReportPath: path, keyScanClass: "sast"}
	require.NoError(t, a.ValidateConfig(cfg))
	assert.Equal(t, loaders.FormatNormalized, a.config.InputFormat)
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.NoError(t, a.Attest(context.Background(), cfg))
}

func TestAttest_SAST_SubjectIsReportDigest(t *testing.T) {
	path := writeReport(t, sastInput())

	a := newTestAttestor()
	cfg := core.Config{keyReportPath: path, keyScanClass: "sast"}
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
	assert.Len(t, got.Findings, 1)
}

func TestAttest_SCA_SubjectPrefersInventoryDigest(t *testing.T) {
	in := scaInput()
	in.Inventory = &loaders.NormalizedInventory{Format: "cyclonedx-json", Digest: validSHA256}
	path := writeReport(t, in)

	a := newTestAttestor()
	cfg := core.Config{keyReportPath: path, keyScanClass: "sca"}
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.NoError(t, a.Attest(context.Background(), cfg))

	subjects := a.Subjects(cfg)
	require.Len(t, subjects, 1)
	assert.Equal(t, validSHA256, subjects[0].Digest["sha256"])
}

func TestAttest_SubjectDigestOverride(t *testing.T) {
	path := writeReport(t, scaInput())

	a := newTestAttestor()
	cfg := core.Config{
		keyReportPath:    path,
		keyScanClass:     "sca",
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
	path := writeReport(t, scaInput())

	badDigests := map[string]string{
		"short":     "abc123",
		"uppercase": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
		"non-hex":   "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"prefixed":  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b785",
	}
	for name, digest := range badDigests {
		t.Run(name, func(t *testing.T) {
			a := newTestAttestor()
			cfg := core.Config{keyReportPath: path, keyScanClass: "sca", keySubjectDigest: digest}
			require.NoError(t, a.PreAttest(context.Background(), cfg))
			require.Error(t, a.Attest(context.Background(), cfg))
		})
	}
}

// Item 1: a malformed inventory digest must be rejected before it becomes the subject.
func TestAttest_RejectsInvalidInventoryDigest(t *testing.T) {
	in := scaInput()
	in.Inventory = &loaders.NormalizedInventory{Digest: "deadbeef"}
	path := writeReport(t, in)

	a := newTestAttestor()
	cfg := core.Config{keyReportPath: path, keyScanClass: "sca"}
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.Error(t, a.Attest(context.Background(), cfg))
}

// Item 1: ValidateConfig rejects a malformed --subject-digest up front.
func TestValidateConfig_RejectsInvalidSubjectDigest(t *testing.T) {
	path := writeReport(t, sastInput())
	a := newTestAttestor()
	err := a.ValidateConfig(core.Config{keyReportPath: path, keyScanClass: "sast", keySubjectDigest: "nothex"})
	require.Error(t, err)
}

// Item 2: an unknown/misspelled top-level field must be rejected, not dropped.
func TestAttest_RejectsUnknownField(t *testing.T) {
	path := writeRawReport(t, `{"scanner":{"name":"wiz"},"findings":[],"scanerr":"typo"}`)

	a := newTestAttestor()
	cfg := core.Config{keyReportPath: path, keyScanClass: "sast"}
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.Error(t, a.Attest(context.Background(), cfg))
}

// Item 2: a summary whose finding count disagrees with len(findings) is rejected.
// Loaders always derive the summary, so this guards validatePredicate directly.
func TestValidatePredicate_RejectsInconsistentSummary(t *testing.T) {
	a := newTestAttestor()
	a.predicate = scanpredicate.Predicate{
		ScanClass: scanpredicate.ScanClassSAST,
		Scan:      scanpredicate.Scan{Status: scanpredicate.StatusSuccess},
		Scanner:   scanpredicate.Scanner{Name: "wiz"},
		Findings:  []scanpredicate.Finding{{ID: "f1"}},
		Summary:   scanpredicate.Summary{Findings: 5, BySeverity: map[string]int{}},
	}
	require.Error(t, a.validatePredicate())

	a.predicate.Summary.Findings = 1
	require.NoError(t, a.validatePredicate())
}

// Item 2: a report with an unrecognized scan status is rejected.
func TestAttest_RejectsUnknownScanStatus(t *testing.T) {
	in := sastInput()
	in.Scan.Status = "bogus"
	path := writeReport(t, in)

	a := newTestAttestor()
	cfg := core.Config{keyReportPath: path, keyScanClass: "sast"}
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.Error(t, a.Attest(context.Background(), cfg))
}

// Item 2: a well-formed, self-consistent report still passes (happy path).
func TestAttest_HappyPathPasses(t *testing.T) {
	path := writeReport(t, sastInput())

	a := newTestAttestor()
	cfg := core.Config{keyReportPath: path, keyScanClass: "sast"}
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.NoError(t, a.Attest(context.Background(), cfg))
}

func TestAttest_InvalidScanClassFails(t *testing.T) {
	// Without a scan-class the attestor cannot project findings and must fail.
	path := writeReport(t, sastInput())

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

// Native scanner output is ingested through a loader and projected onto the
// predicate, with the subject bound to a digest of the raw input.
func TestAttest_SnykInputFormat(t *testing.T) {
	const snykSCA = `{
  "vulnerabilities": [
    {
      "id": "SNYK-JS-LODASH-1", "title": "Prototype Pollution", "severity": "high",
      "cvssScore": 7.4, "packageName": "lodash", "version": "4.17.20", "packageManager": "npm",
      "identifiers": { "CVE": ["CVE-2020-8203"] }
    }
  ],
  "packageManager": "npm"
}`
	path := filepath.Join(t.TempDir(), "snyk.json")
	require.NoError(t, os.WriteFile(path, []byte(snykSCA), 0o600))

	a := newTestAttestor()
	cfg := core.Config{keyReportPath: path, keyInputFormat: "snyk", keyScanClass: "sca"}
	require.NoError(t, a.ValidateConfig(cfg))
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.NoError(t, a.Attest(context.Background(), cfg))

	pred, err := a.GeneratePredicate(cfg)
	require.NoError(t, err)
	if got, ok := pred.(scanpredicate.Predicate); assert.True(t, ok) {
		assert.Equal(t, scanpredicate.ScanClassSCA, got.ScanClass)
		require.Len(t, got.Findings, 1)
		assert.Equal(t, "pkg:npm/lodash@4.17.20", got.Findings[0].Component.PURL)
		require.Len(t, a.Subjects(cfg), 1)
	}
}

// The normalized input-format maps stamp's vendor-neutral findings document.
func TestAttest_NormalizedInputFormat(t *testing.T) {
	const normalized = `{
  "scanner": { "name": "wiz" },
  "findings": [
    { "scanType": "vulnerability", "severity": "CRITICAL", "ruleId": "CVE-1", "packageName": "lodash@4.17.21", "ecosystem": "npm" }
  ]
}`
	path := filepath.Join(t.TempDir(), "normalized.json")
	require.NoError(t, os.WriteFile(path, []byte(normalized), 0o600))

	a := newTestAttestor()
	cfg := core.Config{keyReportPath: path, keyInputFormat: "normalized", keyScanClass: "sca"}
	require.NoError(t, a.ValidateConfig(cfg))
	require.NoError(t, a.PreAttest(context.Background(), cfg))
	require.NoError(t, a.Attest(context.Background(), cfg))

	pred, err := a.GeneratePredicate(cfg)
	require.NoError(t, err)
	if got, ok := pred.(scanpredicate.Predicate); assert.True(t, ok) {
		assert.Equal(t, scanpredicate.ScanClassSCA, got.ScanClass)
		require.Len(t, got.Findings, 1)
		assert.Equal(t, "pkg:npm/lodash@4.17.21", got.Findings[0].Component.PURL)
	}
}

// Every input format requires an explicit scan-class.
func TestValidateConfig_RequiresScanClass(t *testing.T) {
	snykPath := filepath.Join(t.TempDir(), "snyk.json")
	require.NoError(t, os.WriteFile(snykPath, []byte(`{"vulnerabilities":[]}`), 0o600))
	normalizedPath := writeReport(t, sastInput())

	a := newTestAttestor()
	require.Error(t, a.ValidateConfig(core.Config{keyReportPath: snykPath, keyInputFormat: "snyk"}))
	require.Error(t, a.ValidateConfig(core.Config{keyReportPath: normalizedPath}))
	require.Error(t, a.ValidateConfig(core.Config{keyReportPath: normalizedPath, keyScanClass: ""}))
}

// An unregistered input-format, including the internal predicate format, is
// rejected up front.
func TestValidateConfig_RejectsUnknownInputFormat(t *testing.T) {
	path := writeReport(t, sastInput())
	a := newTestAttestor()
	for _, format := range []string{"bogus", "predicate"} {
		err := a.ValidateConfig(core.Config{keyReportPath: path, keyScanClass: "sast", keyInputFormat: format})
		require.Error(t, err, format)
	}
}
