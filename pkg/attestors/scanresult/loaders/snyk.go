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
	"encoding/json"
	"fmt"
	"strings"

	scanpredicate "github.com/thomsonreuters/stamp/pkg/predicates/scanresult/v1"
)

// snykLoader is the reference loader for native Snyk output. SCA findings come
// from `snyk test --json`; SAST findings come from the SARIF produced by
// `snyk code test --sarif`. It converts either into the stamp normalized findings
// shape and reuses the shared normalized mapping, so the predicate projection is
// identical regardless of the input format.
type snykLoader struct{}

const (
	snykScannerName = "snyk"
	snykVendor      = "Snyk"
)

// Load dispatches on scan class: SCA parses the dependency test report, SAST parses
// the SARIF code report.
func (snykLoader) Load(content []byte, opts Options) (scanpredicate.Predicate, error) {
	switch opts.ScanClass {
	case scanpredicate.ScanClassSCA:
		return loadSnykSCA(content)
	case scanpredicate.ScanClassSAST:
		return loadSnykSAST(content)
	default:
		return scanpredicate.Predicate{}, fmt.Errorf("a valid scan-class ('sast' or 'sca') is required for the snyk input-format, got %q", opts.ScanClass)
	}
}

// --- SCA: `snyk test --json` -------------------------------------------------

type snykSCAReport struct {
	Vulnerabilities []snykVuln      `json:"vulnerabilities"`
	Applications    []snykSCAReport `json:"applications"`
	PackageManager  string          `json:"packageManager"`
	ProjectName     string          `json:"projectName"`
}

type snykVuln struct {
	ID             string          `json:"id"`
	Title          string          `json:"title"`
	CVSSv3         string          `json:"CVSSv3"`
	CVSSScore      float64         `json:"cvssScore"`
	Severity       string          `json:"severity"`
	FixedIn        []string        `json:"fixedIn"`
	PackageName    string          `json:"packageName"`
	Version        string          `json:"version"`
	PackageManager string          `json:"packageManager"`
	Identifiers    snykIdentifiers `json:"identifiers"`
	EPSSDetails    *snykEPSS       `json:"epssDetails"`
}

type snykIdentifiers struct {
	CVE []string `json:"CVE"`
	CWE []string `json:"CWE"`
}

type snykEPSS struct {
	Probability string `json:"probability"`
	Percentile  string `json:"percentile"`
}

func loadSnykSCA(content []byte) (scanpredicate.Predicate, error) {
	reports, err := decodeSnykSCA(content)
	if err != nil {
		return scanpredicate.Predicate{}, err
	}

	input := NormalizedInput{
		Scanner: NormalizedScanner{Name: snykScannerName, Vendor: snykVendor},
	}
	for _, r := range reports {
		collectSnykVulns(r, &input)
	}

	return normalize(scanpredicate.ScanClassSCA, input)
}

// decodeSnykSCA accepts either a single report object or a JSON array of reports
// (Snyk emits an array when several projects are scanned).
func decodeSnykSCA(content []byte) ([]snykSCAReport, error) {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var reports []snykSCAReport
		if err := json.Unmarshal(trimmed, &reports); err != nil {
			return nil, fmt.Errorf("failed to parse snyk test JSON array: %w", err)
		}
		return reports, nil
	}

	var report snykSCAReport
	if err := json.Unmarshal(trimmed, &report); err != nil {
		return nil, fmt.Errorf("failed to parse snyk test JSON: %w", err)
	}
	return []snykSCAReport{report}, nil
}

// collectSnykVulns appends findings from a report and any nested applications.
func collectSnykVulns(r snykSCAReport, input *NormalizedInput) {
	ecosystem := r.PackageManager
	for _, v := range r.Vulnerabilities {
		input.Findings = append(input.Findings, snykVulnToFinding(v, ecosystem))
	}
	for _, app := range r.Applications {
		collectSnykVulns(app, input)
	}
}

func snykVulnToFinding(v snykVuln, ecosystem string) NormalizedFinding {
	pkgEcosystem := v.PackageManager
	if pkgEcosystem == "" {
		pkgEcosystem = ecosystem
	}

	f := NormalizedFinding{
		ScanType:            scanTypeVulnerability,
		Severity:            v.Severity,
		RuleID:              snykVulnID(v),
		Title:               v.Title,
		PackageName:         joinPackage(v.PackageName, v.Version),
		Ecosystem:           pkgEcosystem,
		VulnerabilitySource: snykVendor,
		CVSSv3:              v.CVSSv3,
		CVSSv3Score:         v.CVSSScore,
		FixedIn:             v.FixedIn,
	}
	if v.EPSSDetails != nil {
		f.EPSSProbability = v.EPSSDetails.Probability
		f.EPSSPercentile = v.EPSSDetails.Percentile
	}
	return f
}

// snykVulnID prefers a CVE identifier when present, falling back to the Snyk id.
func snykVulnID(v snykVuln) string {
	if len(v.Identifiers.CVE) > 0 && v.Identifiers.CVE[0] != "" {
		return v.Identifiers.CVE[0]
	}
	return v.ID
}

func joinPackage(name, version string) string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" {
		return ""
	}
	if version == "" {
		return name
	}
	return name + "@" + version
}

// --- SAST: SARIF from `snyk code test --sarif` -------------------------------

type sarifReport struct {
	Runs []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	HelpURI    string         `json:"helpUri"`
	Properties sarifRuleProps `json:"properties"`
}

type sarifRuleProps struct {
	CWE []string `json:"cwe"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine"`
}

func loadSnykSAST(content []byte) (scanpredicate.Predicate, error) {
	var report sarifReport
	if err := json.Unmarshal(bytes.TrimSpace(content), &report); err != nil {
		return scanpredicate.Predicate{}, fmt.Errorf("failed to parse snyk code SARIF JSON: %w", err)
	}

	input := NormalizedInput{
		Scanner: NormalizedScanner{Name: snykScannerName, Vendor: snykVendor},
	}
	for _, run := range report.Runs {
		rules := indexSarifRules(run.Tool.Driver.Rules)
		for _, res := range run.Results {
			input.Findings = append(input.Findings, sarifResultToFinding(res, rules))
		}
	}

	return normalize(scanpredicate.ScanClassSAST, input)
}

func indexSarifRules(rules []sarifRule) map[string]sarifRule {
	index := make(map[string]sarifRule, len(rules))
	for _, r := range rules {
		index[r.ID] = r
	}
	return index
}

func sarifResultToFinding(res sarifResult, rules map[string]sarifRule) NormalizedFinding {
	f := NormalizedFinding{
		ScanType: scanTypeSAST,
		Severity: sarifLevelToSeverity(res.Level),
		RuleID:   res.RuleID,
		Title:    res.Message.Text,
	}

	if rule, ok := rules[res.RuleID]; ok {
		f.RuleLink = rule.HelpURI
		if len(rule.Properties.CWE) > 0 {
			f.Category = rule.Properties.CWE[0]
		}
	}

	if len(res.Locations) > 0 {
		region := res.Locations[0].PhysicalLocation.Region
		f.FilePath = res.Locations[0].PhysicalLocation.ArtifactLocation.URI
		f.StartLine = region.StartLine
		f.EndLine = region.EndLine
	}

	return f
}

// sarifLevelToSeverity maps SARIF result levels onto scanner-normalized severities.
func sarifLevelToSeverity(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return "HIGH"
	case "warning":
		return "MEDIUM"
	case "note", "info":
		return "LOW"
	default:
		return ""
	}
}
