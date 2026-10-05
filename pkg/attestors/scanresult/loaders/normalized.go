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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/thomsonreuters/stamp/pkg/attestors/scanresult/internal/purl"
	scanpredicate "github.com/thomsonreuters/stamp/pkg/predicates/scanresult/v1"
)

// scanType values a normalized finding uses to declare its class. These mirror the
// values producers emit and are matched against the requested ScanClass.
const (
	scanTypeSAST          = "sast"
	scanTypeVulnerability = "vulnerability"
)

// NormalizedInput is stamp's vendor-neutral scan-result input document. Producers
// map their scanner output onto this stable schema; the normalized loader projects
// it onto the scan-result predicate. It is deliberately independent of any
// producer's internal model so open-source consumers can target it directly.
type NormalizedInput struct {
	ScanID    string               `json:"scanId,omitempty"`
	Scanner   NormalizedScanner    `json:"scanner,omitempty"`
	Scan      NormalizedScan       `json:"scan,omitempty"`
	Inventory *NormalizedInventory `json:"inventory,omitempty"`
	RawReport *NormalizedArtifact  `json:"rawReport,omitempty"`
	Findings  []NormalizedFinding  `json:"findings"`
}

// NormalizedScanner identifies the tool that produced the findings.
type NormalizedScanner struct {
	Name    string `json:"name,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
	Version string `json:"version,omitempty"`
}

// NormalizedScan holds scan execution metadata.
type NormalizedScan struct {
	Status     string `json:"status,omitempty"`
	Scope      string `json:"scope,omitempty"`
	StartedOn  string `json:"startedOn,omitempty"`
	FinishedOn string `json:"finishedOn,omitempty"`
}

// NormalizedInventory describes the SBOM/manifest an SCA scan analyzed.
type NormalizedInventory struct {
	Format       string `json:"format,omitempty"`
	URI          string `json:"uri,omitempty"`
	Digest       string `json:"digest,omitempty"`
	Completeness string `json:"completeness,omitempty"`
}

// NormalizedArtifact references an out-of-band object by URI and digest.
type NormalizedArtifact struct {
	MediaType string `json:"mediaType,omitempty"`
	URI       string `json:"uri,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

// NormalizedFinding is a single vendor-neutral finding. SAST findings populate the
// rule/location fields; SCA (vulnerability) findings populate the package and
// advisory fields. ScanType declares which class the finding belongs to.
type NormalizedFinding struct {
	ScanType string `json:"scanType,omitempty"`
	Severity string `json:"severity,omitempty"`
	RuleID   string `json:"ruleId,omitempty"`
	RuleLink string `json:"ruleLink,omitempty"`
	Title    string `json:"title,omitempty"`
	Details  string `json:"details,omitempty"`
	Category string `json:"category,omitempty"`

	// SAST location.
	FilePath  string `json:"filePath,omitempty"`
	StartLine int    `json:"startLine,omitempty"`
	EndLine   int    `json:"endLine,omitempty"`

	// SCM context.
	CommitID string `json:"commitId,omitempty"`
	RepoURL  string `json:"repoUrl,omitempty"`
	SCMLink  string `json:"scmLink,omitempty"`

	// SCA component.
	PackageName string `json:"packageName,omitempty"`
	Ecosystem   string `json:"ecosystem,omitempty"`

	// SCA vulnerability metadata.
	VulnerabilitySource string   `json:"vulnerabilitySource,omitempty"`
	CVSSv3              string   `json:"cvssV3,omitempty"`
	CVSSv3Score         float64  `json:"cvssV3Score,omitempty"`
	CVSSv4              string   `json:"cvssV4,omitempty"`
	WeightedSeverity    string   `json:"weightedSeverity,omitempty"`
	EPSSProbability     string   `json:"epssProbability,omitempty"`
	EPSSPercentile      string   `json:"epssPercentile,omitempty"`
	EPSSseverity        string   `json:"epssSeverity,omitempty"`
	HasCisaKevExploit   bool     `json:"hasCisaKevExploit,omitempty"`
	CisaKevReleaseDate  string   `json:"cisaKevReleaseDate,omitempty"`
	CisaKevDueDate      string   `json:"cisaKevDueDate,omitempty"`
	FixedIn             []string `json:"fixedIn,omitempty"`
}

// normalizedLoader projects a NormalizedInput document onto a scan-result
// predicate for the requested scan class.
type normalizedLoader struct{}

// Load decodes the normalized document (failing closed on unknown fields) and maps
// it to a predicate. Only findings whose scanType matches opts.ScanClass are
// included. It errors if a component's ecosystem is present but unsupported.
func (normalizedLoader) Load(content []byte, opts Options) (scanpredicate.Predicate, error) {
	if !opts.ScanClass.IsValid() {
		return scanpredicate.Predicate{}, fmt.Errorf("a valid scan-class is required for the normalized input-format, got %q", opts.ScanClass)
	}

	var input NormalizedInput
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return scanpredicate.Predicate{}, fmt.Errorf("failed to parse normalized scan-result JSON: %w", err)
	}

	return normalize(opts.ScanClass, input)
}

// normalize builds a predicate for class from the normalized input.
func normalize(class scanpredicate.ScanClass, input NormalizedInput) (scanpredicate.Predicate, error) {
	status := scanpredicate.ScanStatus(input.Scan.Status)
	if status == "" {
		status = scanpredicate.StatusSuccess
	}

	pred := scanpredicate.Predicate{
		SchemaVersion: scanpredicate.SchemaVersion,
		ScanClass:     class,
		Scan: scanpredicate.Scan{
			ID:         input.ScanID,
			Status:     status,
			Scope:      input.Scan.Scope,
			StartedOn:  input.Scan.StartedOn,
			FinishedOn: input.Scan.FinishedOn,
		},
		Scanner: scanpredicate.Scanner{
			Name:    input.Scanner.Name,
			Vendor:  input.Scanner.Vendor,
			Version: input.Scanner.Version,
		},
		Findings: []scanpredicate.Finding{},
	}

	if class == scanpredicate.ScanClassSCA && input.Inventory != nil && input.Inventory.Digest != "" {
		pred.Inventory = &scanpredicate.Inventory{
			Format:       input.Inventory.Format,
			URI:          input.Inventory.URI,
			Completeness: input.Inventory.Completeness,
			Digest:       &scanpredicate.Digest{SHA256: input.Inventory.Digest},
		}
	}

	if input.RawReport != nil && (input.RawReport.URI != "" || input.RawReport.Digest != "") {
		mediaType := input.RawReport.MediaType
		if mediaType == "" {
			mediaType = "application/json"
		}
		pred.RawReport = &scanpredicate.Artifact{
			MediaType: mediaType,
			URI:       input.RawReport.URI,
			Digest:    digestOrNil(input.RawReport.Digest),
		}
	}

	bySeverity := map[string]int{}
	components := map[string]struct{}{}

	for _, f := range input.Findings {
		if !matchesClass(class, f.ScanType) {
			continue
		}

		finding, comp, err := mapFinding(class, f)
		if err != nil {
			return scanpredicate.Predicate{}, err
		}

		pred.Findings = append(pred.Findings, finding)
		if sev := strings.ToLower(strings.TrimSpace(f.Severity)); sev != "" {
			bySeverity[sev]++
		}
		if comp != "" {
			components[comp] = struct{}{}
		}
	}

	pred.Summary = scanpredicate.Summary{
		Findings:   len(pred.Findings),
		BySeverity: bySeverity,
	}
	if class == scanpredicate.ScanClassSCA {
		pred.Summary.Components = len(components)
	}

	return pred, nil
}

func matchesClass(class scanpredicate.ScanClass, scanType string) bool {
	switch class {
	case scanpredicate.ScanClassSAST:
		return strings.EqualFold(scanType, scanTypeSAST)
	case scanpredicate.ScanClassSCA:
		return strings.EqualFold(scanType, scanTypeVulnerability)
	default:
		return false
	}
}

// mapFinding converts one normalized finding into a predicate Finding. The second
// return value is a component-identity key (empty for SAST) used for the unique
// component count in the summary.
func mapFinding(class scanpredicate.ScanClass, f NormalizedFinding) (scanpredicate.Finding, string, error) {
	finding := scanpredicate.Finding{
		Severity: f.Severity,
		Title:    f.Title,
		Details:  f.Details,
		Source:   scmContext(f),
	}

	switch class {
	case scanpredicate.ScanClassSAST:
		finding.Rule = ruleOrNil(f.RuleID, f.RuleLink)
		if f.Category != "" {
			finding.Weakness = &scanpredicate.Weakness{Name: f.Category}
		}
		finding.Location = locationOrNil(f)
		finding.ID = stableID(string(class), f.RuleID, f.FilePath, strconv.Itoa(f.StartLine))
		return finding, "", nil

	case scanpredicate.ScanClassSCA:
		comp, err := component(f)
		if err != nil {
			return scanpredicate.Finding{}, "", err
		}
		finding.Component = comp
		finding.Vulnerability = vulnerability(f)
		finding.ID = stableID(string(class), f.RuleID, f.PackageName, "")
		return finding, f.PackageName, nil

	default:
		return scanpredicate.Finding{}, "", fmt.Errorf("unsupported scan class %q", class)
	}
}

// component builds the SCA component. A PURL is emitted only when an ecosystem is
// available; an unsupported ecosystem surfaces as an error.
func component(f NormalizedFinding) (*scanpredicate.Component, error) {
	name, version := splitPackage(f.PackageName)
	if name == "" {
		return nil, nil
	}

	comp := &scanpredicate.Component{
		Name:    name,
		Version: version,
	}

	ecosystem := strings.TrimSpace(f.Ecosystem)
	if ecosystem != "" {
		comp.Ecosystem = ecosystem
		purlStr, err := purl.ComponentPURL(ecosystem, name, version)
		if err != nil {
			var unsupported *purl.UnsupportedEcosystemError
			if errors.As(err, &unsupported) {
				return nil, fmt.Errorf("cannot build component PURL for %q: %w", f.PackageName, err)
			}
			return nil, err
		}
		comp.PURL = purlStr
	}

	return comp, nil
}

func vulnerability(f NormalizedFinding) *scanpredicate.Vulnerability {
	v := &scanpredicate.Vulnerability{
		ID:            f.RuleID,
		Source:        f.VulnerabilitySource,
		FixedVersions: f.FixedIn,
		Severity:      f.WeightedSeverity,
	}

	if cvss := cvssEntries(f); len(cvss) > 0 {
		v.CVSS = cvss
	}
	if e := epss(f); e != nil {
		v.EPSS = e
	}
	if f.HasCisaKevExploit {
		v.KEV = &scanpredicate.KEV{
			Known:       true,
			ReleaseDate: f.CisaKevReleaseDate,
			DueDate:     f.CisaKevDueDate,
		}
	}

	if v.ID == "" && v.Source == "" && len(v.FixedVersions) == 0 &&
		len(v.CVSS) == 0 && v.EPSS == nil && v.KEV == nil && v.Severity == "" {
		return nil
	}
	return v
}

func cvssEntries(f NormalizedFinding) []scanpredicate.CVSS {
	entries := make([]scanpredicate.CVSS, 0, 2)
	if f.CVSSv3 != "" || f.CVSSv3Score != 0 {
		entries = append(entries, scanpredicate.CVSS{
			Version: "3.1",
			Source:  f.VulnerabilitySource,
			Vector:  f.CVSSv3,
			Score:   f.CVSSv3Score,
		})
	}
	if f.CVSSv4 != "" {
		entries = append(entries, scanpredicate.CVSS{
			Version: "4.0",
			Source:  f.VulnerabilitySource,
			Vector:  f.CVSSv4,
		})
	}
	return entries
}

func epss(f NormalizedFinding) *scanpredicate.EPSS {
	if f.EPSSProbability == "" && f.EPSSPercentile == "" && f.EPSSseverity == "" {
		return nil
	}
	return &scanpredicate.EPSS{
		Probability: f.EPSSProbability,
		Percentile:  f.EPSSPercentile,
		Severity:    f.EPSSseverity,
	}
}

func scmContext(f NormalizedFinding) *scanpredicate.SCMContext {
	if f.RepoURL == "" && f.CommitID == "" && f.SCMLink == "" {
		return nil
	}
	return &scanpredicate.SCMContext{
		RepoURL:  f.RepoURL,
		CommitID: f.CommitID,
		SCMLink:  f.SCMLink,
	}
}

func ruleOrNil(id, link string) *scanpredicate.Rule {
	if id == "" && link == "" {
		return nil
	}
	return &scanpredicate.Rule{ID: id, Link: link}
}

func locationOrNil(f NormalizedFinding) *scanpredicate.Location {
	if f.FilePath == "" && f.StartLine == 0 && f.EndLine == 0 {
		return nil
	}
	return &scanpredicate.Location{
		FilePath:  f.FilePath,
		StartLine: f.StartLine,
		EndLine:   f.EndLine,
	}
}

func digestOrNil(sha256hex string) *scanpredicate.Digest {
	if sha256hex == "" {
		return nil
	}
	return &scanpredicate.Digest{SHA256: sha256hex}
}

// splitPackage splits a "name@version" package identity. A missing version yields
// an empty version string.
func splitPackage(pkg string) (name, version string) {
	pkg = strings.TrimSpace(pkg)
	if pkg == "" {
		return "", ""
	}
	if idx := strings.LastIndex(pkg, "@"); idx > 0 {
		return pkg[:idx], pkg[idx+1:]
	}
	return pkg, ""
}

// stableID derives a deterministic finding identifier from its distinguishing parts.
func stableID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "finding:" + hex.EncodeToString(sum[:])[:32]
}
