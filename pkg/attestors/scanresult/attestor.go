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

// Package scanresult provides an attestor for normalized SAST and SCA security
// scan results. It is deliberately vendor-agnostic: the producer (for example
// SecPipe) normalizes a scanner's native output into the scan-result predicate
// schema and writes it to a JSON file; this attestor ingests that file, binds it
// to a subject, and emits the in-toto statement. A single attestor handles both
// scan classes, discriminated by the predicate's ScanClass field.
package scanresult

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/crypto/hash"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	scanpredicate "github.com/thomsonreuters/stamp/pkg/predicates/scanresult/v1"
)

func init() {
	_ = core.RegisterAttestor(func(log logger.Logger) core.Attestor {
		return &Attestor{
			logger: log.With("attestor_id", id),
			hasher: hash.New(hash.Config{
				Algorithms: []string{hash.AlgorithmSHA256},
			}),
		}
	})
}

// Config holds the parsed attestor configuration.
type Config struct {
	ReportPath    string `json:"report-path"`
	ScanClass     string `json:"scan-class"`
	SubjectName   string `json:"subject-name"`
	SubjectDigest string `json:"subject-digest"`
}

// Attestor implements core.Attestor for normalized scan-result ingestion.
type Attestor struct {
	logger logger.Logger
	hasher hash.Hasher
	config Config

	reportPath   string
	reportDigest string
	predicate    scanpredicate.Predicate
	subject      intoto.Subject
}

func (a *Attestor) ID() string           { return id }
func (a *Attestor) PredicateURI() string { return scanpredicate.PredicateURI }
func (a *Attestor) Name() string         { return name }
func (a *Attestor) Description() string  { return description }

func (a *Attestor) ConfigSchema() []core.ConfigField {
	return []core.ConfigField{
		{
			Name:        keyReportPath,
			Type:        "string",
			Default:     "",
			Required:    true,
			Description: "Path to the normalized scan-result predicate JSON file to attest",
			Example:     "/path/to/scan-result.json",
		},
		{
			Name:        keyScanClass,
			Type:        "string",
			Default:     "",
			Required:    false,
			Description: "Optional scan class override ('sast' or 'sca'); defaults to the value in the report",
			Example:     "sca",
		},
		{
			Name:        keySubjectName,
			Type:        "string",
			Default:     "",
			Required:    false,
			Description: "Optional subject name override; defaults to a class-derived descriptor",
			Example:     "sbom+app.cdx.json",
		},
		{
			Name:        keySubjectDigest,
			Type:        "string",
			Default:     "",
			Required:    false,
			Description: "Optional SHA-256 of the scanned artifact (e.g. the SBOM) to bind as the subject; defaults to the report digest",
			Example:     "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		},
	}
}

func (a *Attestor) parseConfig(config core.Config) {
	a.config = Config{
		ReportPath:    config.GetString(keyReportPath, ""),
		ScanClass:     config.GetString(keyScanClass, ""),
		SubjectName:   config.GetString(keySubjectName, ""),
		SubjectDigest: config.GetString(keySubjectDigest, ""),
	}
}

// PreAttest resolves and stores the report file path.
func (a *Attestor) PreAttest(ctx context.Context, config core.Config) error {
	start := time.Now()
	a.logger.InfoContext(ctx, "starting scan-result attestor pre-attestation setup")

	a.parseConfig(config)

	absPath, err := filepath.Abs(a.config.ReportPath)
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "pre-attest",
			"failed to resolve report path to absolute path")
	}
	a.reportPath = absPath

	a.logger.InfoContext(ctx, "scan-result attestor pre-attestation setup completed",
		"report_path", a.reportPath,
		"duration_ms", time.Since(start).Milliseconds())
	return nil
}

// Attest reads the normalized report, computes its digest, and derives the subject.
func (a *Attestor) Attest(ctx context.Context, config core.Config) error {
	start := time.Now()
	a.logger.InfoContext(ctx, "starting scan-result attestation collection")

	content, err := os.ReadFile(a.reportPath)
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "collect", "failed to read report file")
	}

	// Fail closed: reject unknown/misspelled fields rather than silently dropping
	// them, so a producer's mapping mistakes surface instead of being signed away.
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&a.predicate); err != nil {
		return pkgerrors.WrapWithContext(err, id, "collect", "failed to parse scan-result JSON")
	}

	// A config override takes precedence over the report's embedded class.
	if a.config.ScanClass != "" {
		a.predicate.ScanClass = scanpredicate.ScanClass(a.config.ScanClass)
	}
	if !a.predicate.ScanClass.IsValid() {
		return pkgerrors.NewWithContext(id, "collect",
			fmt.Sprintf("scan class must be 'sast' or 'sca', got '%s'", a.predicate.ScanClass))
	}

	if a.predicate.SchemaVersion == "" {
		a.predicate.SchemaVersion = scanpredicate.SchemaVersion
	}

	if err := a.validatePredicate(); err != nil {
		return err
	}

	result, err := a.hasher.HashBytes(ctx, content, a.reportPath)
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "collect", "failed to hash report file")
	}
	a.reportDigest = result.Digests[hash.AlgorithmSHA256]

	a.subject = a.deriveSubject()

	a.logger.InfoContext(ctx, "scan-result attestation collection completed",
		"scan_class", a.predicate.ScanClass,
		"findings", len(a.predicate.Findings),
		"subject_name", a.subject.Name,
		"duration_ms", time.Since(start).Milliseconds())
	return nil
}

// deriveSubject binds the attestation to what was scanned. Precedence:
//  1. an explicit --subject-digest,
//  2. for SCA, the analyzed SBOM digest from inventory,
//  3. otherwise a sha256 over the normalized report bytes.
//
// All externally supplied digests are validated by validatePredicate before this
// runs, so only known-good SHA-256 values reach the subject here.
func (a *Attestor) deriveSubject() intoto.Subject {
	if a.config.SubjectDigest != "" {
		return intoto.Subject{
			Name:   a.subjectName(),
			Digest: map[string]string{"sha256": a.config.SubjectDigest},
		}
	}

	if a.predicate.ScanClass == scanpredicate.ScanClassSCA &&
		a.predicate.Inventory != nil &&
		a.predicate.Inventory.Digest != nil &&
		a.predicate.Inventory.Digest.SHA256 != "" {
		name := a.config.SubjectName
		if name == "" {
			name = "sbom+scan-result"
		}
		return intoto.Subject{
			Name:   name,
			Digest: map[string]string{"sha256": a.predicate.Inventory.Digest.SHA256},
		}
	}

	return intoto.Subject{
		Name:   a.subjectName(),
		Digest: map[string]string{"sha256": a.reportDigest},
	}
}

// validatePredicate fails closed on a structurally invalid or self-inconsistent
// report before any part of it is hashed and signed.
func (a *Attestor) validatePredicate() error {
	if a.config.SubjectDigest != "" && !isValidSHA256(a.config.SubjectDigest) {
		return pkgerrors.NewWithContext(id, "collect",
			"subject-digest must be a 64-character lowercase hex SHA-256 digest")
	}

	if a.predicate.ScanClass == scanpredicate.ScanClassSCA &&
		a.predicate.Inventory != nil &&
		a.predicate.Inventory.Digest != nil &&
		a.predicate.Inventory.Digest.SHA256 != "" &&
		!isValidSHA256(a.predicate.Inventory.Digest.SHA256) {
		return pkgerrors.NewWithContext(id, "collect",
			"inventory.digest.sha256 must be a 64-character lowercase hex SHA-256 digest")
	}

	if !a.predicate.Scan.Status.IsValid() {
		return pkgerrors.NewWithContext(id, "collect",
			fmt.Sprintf("scan.status must be 'success', 'partial' or 'failed', got '%s'",
				a.predicate.Scan.Status))
	}

	if a.predicate.Summary.Findings != len(a.predicate.Findings) {
		return pkgerrors.NewWithContext(id, "collect",
			fmt.Sprintf("summary.findings (%d) does not match the number of findings (%d)",
				a.predicate.Summary.Findings, len(a.predicate.Findings)))
	}

	if a.predicate.ScanClass == scanpredicate.ScanClassSCA &&
		a.predicate.Summary.Components > 0 &&
		a.predicate.Inventory != nil &&
		a.predicate.Inventory.ComponentsScanned > 0 &&
		a.predicate.Summary.Components > a.predicate.Inventory.ComponentsScanned {
		return pkgerrors.NewWithContext(id, "collect",
			fmt.Sprintf("summary.components (%d) exceeds inventory.componentsScanned (%d)",
				a.predicate.Summary.Components, a.predicate.Inventory.ComponentsScanned))
	}

	return nil
}

func (a *Attestor) subjectName() string {
	if a.config.SubjectName != "" {
		return a.config.SubjectName
	}
	return fmt.Sprintf("scan-result+%s", a.predicate.ScanClass)
}

// PostAttest performs post-attestation cleanup (no-op).
func (a *Attestor) PostAttest(ctx context.Context, config core.Config) error {
	return nil
}

// GeneratePredicate returns the ingested scan-result predicate.
func (a *Attestor) GeneratePredicate(config core.Config) (any, error) {
	if !a.predicate.ScanClass.IsValid() {
		return nil, pkgerrors.NewWithContext(id, "generate",
			"cannot generate predicate before a valid report has been collected")
	}
	return a.predicate, nil
}

// Subjects returns the single subject bound during Attest.
func (a *Attestor) Subjects(config core.Config) []intoto.Subject {
	if a.subject.Name == "" || len(a.subject.Digest) == 0 {
		return []intoto.Subject{}
	}
	return []intoto.Subject{a.subject}
}

// Schema returns the JSON schema for the scan-result predicate.
func (a *Attestor) Schema() *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		AllowAdditionalProperties:  false,
		RequiredFromJSONSchemaTags: true,
	}

	schema := reflector.Reflect(&scanpredicate.Predicate{})
	schema.Title = "Scan Result Attestation"
	schema.Description = "Normalized SAST/SCA security scan result attestation predicate"
	return schema
}
