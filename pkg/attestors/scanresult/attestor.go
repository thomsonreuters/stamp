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

// Package scanresult provides an attestor for SAST and SCA security scan results.
// It uses a loader selected by input-format to build a scan-result predicate from
// a normalized document or supported native scanner output. The required
// scan-class configuration selects which findings the predicate includes. The
// attestor binds the predicate to a subject and emits the in-toto statement.
package scanresult

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/thomsonreuters/stamp/pkg/attestors/scanresult/loaders"
	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	scanpredicate "github.com/thomsonreuters/stamp/pkg/predicates/scanresult/v1"
)

func init() {
	_ = core.RegisterAttestor(func(log logger.Logger) core.Attestor {
		return &Attestor{
			logger: log.With("attestor_id", id),
		}
	})
}

// Config holds the parsed attestor configuration.
type Config struct {
	ReportPath             string `json:"report-path"`
	ScanClass              string `json:"scan-class"`
	InputFormat            string `json:"input-format"`
	SubjectName            string `json:"subject-name"`
	SubjectDigestAlgorithm string `json:"subject-digest-algorithm"`
	SubjectDigest          string `json:"subject-digest"`
}

// Attestor implements core.Attestor for loader-based scan-result ingestion.
type Attestor struct {
	logger logger.Logger
	config Config

	reportPath string
	predicate  scanpredicate.Predicate
	subject    intoto.Subject
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
			Description: "Path to the scan report file to attest, in the format selected by input-format",
			Example:     "/path/to/scan-result.json",
		},
		{
			Name:        keyScanClass,
			Type:        "string",
			Default:     "",
			Required:    true,
			Description: "Scan class ('sast' or 'sca') selecting which findings in the report are attested",
			Example:     "sca",
		},
		{
			Name:        keyInputFormat,
			Type:        "string",
			Default:     loaders.FormatNormalized,
			Required:    false,
			Description: "Format of the report file: 'normalized' (stamp's vendor-neutral findings document, default) or 'snyk' (native `snyk test`/`snyk code` output)",
			Example:     "snyk",
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
			Name:        keySubjectDigestAlgorithm,
			Type:        "string",
			Default:     "",
			Required:    true,
			Description: "Digest algorithm for the scanned target: 'gitCommit' for source/pre-build scans or 'sha256' for built artifacts",
			Example:     "gitCommit",
		},
		{
			Name:        keySubjectDigest,
			Type:        "string",
			Default:     "",
			Required:    true,
			Description: "Digest value of the scanned target, using subject-digest-algorithm",
			Example:     "0123456789abcdef0123456789abcdef01234567",
		},
	}
}

func (a *Attestor) parseConfig(config core.Config) {
	a.config = Config{
		ReportPath:             config.GetString(keyReportPath, ""),
		ScanClass:              config.GetString(keyScanClass, ""),
		InputFormat:            config.GetString(keyInputFormat, loaders.FormatNormalized),
		SubjectName:            config.GetString(keySubjectName, ""),
		SubjectDigestAlgorithm: config.GetString(keySubjectDigestAlgorithm, ""),
		SubjectDigest:          config.GetString(keySubjectDigest, ""),
	}
}

// PreAttest resolves and stores the report file path.
func (a *Attestor) PreAttest(ctx context.Context, config core.Config) error {
	start := time.Now()
	a.logger.InfoContext(ctx, "starting scan-result attestor pre-attestation setup")

	a.parseConfig(config)

	if err := a.resolveReportPath("pre-attest", "failed to resolve report path to absolute path"); err != nil {
		return err
	}

	a.logger.InfoContext(ctx, "scan-result attestor pre-attestation setup completed",
		"report_path", a.reportPath,
		"duration_ms", time.Since(start).Milliseconds())
	return nil
}

// Attest reads the report, loads it into a predicate, and derives the subject.
func (a *Attestor) Attest(ctx context.Context, config core.Config) error {
	start := time.Now()
	a.logger.InfoContext(ctx, "starting scan-result attestation collection")

	content, err := os.ReadFile(a.reportPath)
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "collect", "failed to read report file")
	}

	loader, err := loaders.Get(a.config.InputFormat)
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "collect", "failed to resolve input-format loader")
	}

	// The loader turns the input (stamp's normalized findings document or native
	// scanner output) into a predicate for the configured scan class. Strict formats
	// fail closed on unknown fields so a producer's mapping mistakes surface instead
	// of being signed away.
	a.predicate, err = loader.Load(content, loaders.Options{
		ScanClass: scanpredicate.ScanClass(a.config.ScanClass),
	})
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "collect", "failed to load scan-result input")
	}

	if a.predicate.SchemaVersion == "" {
		a.predicate.SchemaVersion = scanpredicate.SchemaVersion
	}

	if err = a.validatePredicate(); err != nil {
		return err
	}

	a.subject = a.deriveSubject()

	a.logger.InfoContext(ctx, "scan-result attestation collection completed",
		"scan_class", a.predicate.ScanClass,
		"findings", len(a.predicate.Findings),
		"subject_name", a.subject.Name,
		"duration_ms", time.Since(start).Milliseconds())
	return nil
}

// deriveSubject binds the attestation to the explicitly configured scan target.
func (a *Attestor) deriveSubject() intoto.Subject {
	return intoto.Subject{
		Name:   a.subjectName(),
		Digest: map[string]string{a.config.SubjectDigestAlgorithm: a.config.SubjectDigest},
	}
}

// validatePredicate fails closed on a structurally invalid or self-inconsistent
// report before any part of it is hashed and signed.
func (a *Attestor) validatePredicate() error {
	if err := validateSubjectDigest(a.config.SubjectDigestAlgorithm, a.config.SubjectDigest, "collect"); err != nil {
		return err
	}

	if inventoryDigest, ok := a.predicate.InventoryDigest("sha256"); ok && !isValidSHA256(inventoryDigest) {
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
