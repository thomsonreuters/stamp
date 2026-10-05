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

// Package v1 provides the common scan-result attestation predicate for SAST and
// SCA security scan findings. A single predicate type carries both classes; the
// ScanClass field discriminates between them. The predicate is a stable,
// vendor-neutral projection of a scanner's normalized output — producers map their
// native results onto these types rather than emitting raw scanner dumps.
package v1

// PredicateURI is the in-toto predicateType URI for scan-result attestations.
const PredicateURI = "https://github.com/thomsonreuters/stamp/scan-result/v1"

// SchemaVersion is the current version of the predicate contract.
const SchemaVersion = "1.0"

// ScanClass discriminates the kind of security scan a predicate represents.
type ScanClass string

const (
	// ScanClassSAST is a static application security testing scan.
	ScanClassSAST ScanClass = "sast"
	// ScanClassSCA is a software composition analysis (dependency) scan.
	ScanClassSCA ScanClass = "sca"
)

// String returns the scan class as a string.
func (s ScanClass) String() string { return string(s) }

// IsValid reports whether the scan class is a recognized value.
func (s ScanClass) IsValid() bool {
	switch s {
	case ScanClassSAST, ScanClassSCA:
		return true
	default:
		return false
	}
}

// ScanStatus captures the execution result of the scan itself, independent of
// whether findings were reported.
type ScanStatus string

const (
	// StatusSuccess indicates the scan completed and analyzed all intended inputs.
	StatusSuccess ScanStatus = "success"
	// StatusPartial indicates the scan completed but skipped some inputs.
	StatusPartial ScanStatus = "partial"
	// StatusFailed indicates the scan did not complete successfully.
	StatusFailed ScanStatus = "failed"
)

// String returns the scan status as a string.
func (s ScanStatus) String() string { return string(s) }

// IsValid reports whether the scan status is a recognized value.
func (s ScanStatus) IsValid() bool {
	switch s {
	case StatusSuccess, StatusPartial, StatusFailed:
		return true
	default:
		return false
	}
}

// Predicate is the top-level scan-result attestation predicate.
type Predicate struct {
	SchemaVersion string        `json:"schemaVersion"       jsonschema:"required"`
	ScanClass     ScanClass     `json:"scanClass"           jsonschema:"required"`
	Scan          Scan          `json:"scan"                jsonschema:"required"`
	Scanner       Scanner       `json:"scanner"             jsonschema:"required"`
	Inventory     *Inventory    `json:"inventory,omitempty"`
	Findings      []Finding     `json:"findings"            jsonschema:"required"`
	Summary       Summary       `json:"summary"             jsonschema:"required"`
	Policy        *PolicyResult `json:"policy,omitempty"`
	RawReport     *Artifact     `json:"rawReport,omitempty"`
}

// Scan holds metadata about a single scan execution.
type Scan struct {
	ID         string     `json:"id,omitempty"`
	Status     ScanStatus `json:"status"`
	StartedOn  string     `json:"startedOn,omitempty"`
	FinishedOn string     `json:"finishedOn,omitempty"`
	Scope      string     `json:"scope,omitempty"`
}

// Scanner identifies the tool that produced the findings.
type Scanner struct {
	Name          string         `json:"name"`
	Vendor        string         `json:"vendor,omitempty"`
	Version       string         `json:"version,omitempty"`
	Hash          *Digest        `json:"hash,omitempty"`
	Configuration map[string]any `json:"configuration,omitempty"`
	Database      *ScannerDB     `json:"database,omitempty"`
}

// ScannerDB captures the vulnerability/advisory database snapshot used (SCA).
type ScannerDB struct {
	Name    string  `json:"name,omitempty"`
	Version string  `json:"version,omitempty"`
	Digest  *Digest `json:"digest,omitempty"`
}

// Digest is a content digest set. Only sha256 is carried in v1.
type Digest struct {
	SHA256 string `json:"sha256,omitempty"`
}

// Inventory describes the SBOM or manifest set that an SCA scan analyzed.
type Inventory struct {
	Format            string  `json:"format,omitempty"`
	URI               string  `json:"uri,omitempty"`
	Digest            *Digest `json:"digest,omitempty"`
	Completeness      string  `json:"completeness,omitempty"`
	ComponentsScanned int     `json:"componentsScanned,omitempty"`
}

// Finding unifies SAST and SCA findings. SAST findings populate Rule/Weakness/
// Location; SCA findings populate Component/Vulnerability. Both may carry Source.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity,omitempty"`
	Title    string `json:"title,omitempty"`
	Details  string `json:"details,omitempty"`

	Rule     *Rule     `json:"rule,omitempty"`
	Weakness *Weakness `json:"weakness,omitempty"`
	Location *Location `json:"location,omitempty"`

	Component     *Component     `json:"component,omitempty"`
	Vulnerability *Vulnerability `json:"vulnerability,omitempty"`

	Source *SCMContext `json:"source,omitempty"`

	// Extensions preserves scanner-native fields not represented above.
	Extensions map[string]any `json:"extensions,omitempty"`
}

// Rule identifies the analyzer rule that produced a SAST finding.
type Rule struct {
	ID   string `json:"id,omitempty"`
	Link string `json:"link,omitempty"`
}

// Weakness is a CWE mapping for a SAST finding.
type Weakness struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// Location is a source position for a SAST finding.
type Location struct {
	FilePath    string `json:"filePath,omitempty"`
	StartLine   int    `json:"startLine,omitempty"`
	EndLine     int    `json:"endLine,omitempty"`
	StartColumn int    `json:"startColumn,omitempty"`
	EndColumn   int    `json:"endColumn,omitempty"`
}

// Component is the affected package for an SCA finding, PURL-first.
type Component struct {
	PURL      string `json:"purl,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Type      string `json:"type,omitempty"`
	// Direct distinguishes direct from transitive dependencies; nil means unknown.
	Direct *bool `json:"direct,omitempty"`
}

// Vulnerability is advisory metadata for an SCA finding.
type Vulnerability struct {
	ID               string   `json:"id"`
	Aliases          []string `json:"aliases,omitempty"`
	Source           string   `json:"source,omitempty"`
	InstalledVersion string   `json:"installedVersion,omitempty"`
	FixedVersions    []string `json:"fixedVersions,omitempty"`
	FixState         string   `json:"fixState,omitempty"`
	Severity         string   `json:"severity,omitempty"`
	CVSS             []CVSS   `json:"cvss,omitempty"`
	EPSS             *EPSS    `json:"epss,omitempty"`
	KEV              *KEV     `json:"kev,omitempty"`
	PublishedOn      string   `json:"publishedOn,omitempty"`
	UpdatedOn        string   `json:"updatedOn,omitempty"`
}

// CVSS is a scored CVSS vector from a named source.
type CVSS struct {
	Version string  `json:"version,omitempty"`
	Source  string  `json:"source,omitempty"`
	Vector  string  `json:"vector,omitempty"`
	Score   float64 `json:"score,omitempty"`
}

// EPSS is Exploit Prediction Scoring System data.
type EPSS struct {
	Probability string `json:"probability,omitempty"`
	Percentile  string `json:"percentile,omitempty"`
	Severity    string `json:"severity,omitempty"`
}

// KEV is CISA Known Exploited Vulnerabilities catalog data.
type KEV struct {
	Known       bool   `json:"known"`
	ReleaseDate string `json:"releaseDate,omitempty"`
	DueDate     string `json:"dueDate,omitempty"`
}

// SCMContext records source-control coordinates for a finding.
type SCMContext struct {
	RepoURL  string `json:"repoUrl,omitempty"`
	CommitID string `json:"commitId,omitempty"`
	SCMLink  string `json:"scmLink,omitempty"`
}

// Summary aggregates finding counts for cheap policy evaluation.
//
// Suppression/VEX fields are intentionally omitted in v1 and may be added
// additively later without a schema break.
type Summary struct {
	Components int            `json:"components,omitempty"`
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"bySeverity"`
}

// PolicyResult records a CI gate decision, when one was evaluated.
type PolicyResult struct {
	Name        string       `json:"name,omitempty"`
	Version     string       `json:"version,omitempty"`
	Decision    string       `json:"decision,omitempty"`
	EvaluatedOn string       `json:"evaluatedOn,omitempty"`
	Rules       []PolicyRule `json:"rules,omitempty"`
}

// PolicyRule is a single evaluated policy rule.
type PolicyRule struct {
	ID              string   `json:"id"`
	Result          string   `json:"result"`
	MatchedFindings []string `json:"matchedFindings,omitempty"`
}

// Artifact references an out-of-band object by URI and digest.
type Artifact struct {
	MediaType string  `json:"mediaType,omitempty"`
	URI       string  `json:"uri,omitempty"`
	Digest    *Digest `json:"digest,omitempty"`
}
