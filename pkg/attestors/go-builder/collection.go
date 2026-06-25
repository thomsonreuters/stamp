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

package gobuilder

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/thomsonreuters/stamp/pkg/buildenv"
	cryptohash "github.com/thomsonreuters/stamp/pkg/crypto/hash"
	gobuilderpredicate "github.com/thomsonreuters/stamp/pkg/predicates/go-builder/v1"
)

var fileHasher = cryptohash.New(cryptohash.Config{Algorithms: []string{cryptohash.AlgorithmSHA256}})

// collectAllData detects the build environment, executes the build,
// computes digests, and extracts provenance fields.
func (a *Attestor) collectAllData(ctx context.Context) error {
	a.logger.InfoContext(ctx, "detecting build environment")
	opts := buildenv.DetectOptions{
		WorkingDir:          a.config.WorkingDir,
		CaptureEventPayload: a.config.CaptureEvent,
	}

	detector := a.buildEnvDetector
	if detector == nil {
		detector = buildenv.DetectEnvironment
	}

	env, err := detector(ctx, a.logger, opts)
	if err != nil {
		a.logger.ErrorContext(ctx, "build environment detection failed", "error", err.Error())
		return fmt.Errorf("environment detection: %w", err)
	}
	a.buildEnv = env
	a.logger.InfoContext(ctx, "build environment detected", "type", a.buildEnv.Type())

	a.logger.InfoContext(ctx, "executing build", "working_dir", a.config.WorkingDir)
	a.metadata.StartedOn = time.Now().UTC().Format(time.RFC3339)
	if buildErr := a.executeBuild(ctx); buildErr != nil {
		a.logger.ErrorContext(ctx, "build execution failed", "error", buildErr.Error())
		return fmt.Errorf("build execution: %w", buildErr)
	}
	a.metadata.FinishedOn = time.Now().UTC().Format(time.RFC3339)
	a.logger.InfoContext(ctx, "build execution completed")

	a.logger.InfoContext(ctx, "computing binary artifact digest", "path", a.config.BinaryPath)
	binaryResult, err := fileHasher.HashFile(ctx, a.config.BinaryPath)
	if err != nil {
		return fmt.Errorf("computing binary digest: %w", err)
	}
	sha256Digest, ok := binaryResult.Digests[cryptohash.AlgorithmSHA256]
	if !ok {
		return fmt.Errorf("binary digest missing SHA-256 result for %s", a.config.BinaryPath)
	}
	a.binaryDigest = sha256Digest
	a.logger.InfoContext(ctx, "binary digest computed", "sha256", a.binaryDigest)

	if err := a.collectBuildConfigProvenance(ctx); err != nil {
		return fmt.Errorf("collecting build config provenance: %w", err)
	}

	a.extractProvenanceFields(ctx)

	return nil
}

// executeBuild runs go mod vendor followed by go build.
func (a *Attestor) executeBuild(ctx context.Context) error {
	a.logger.InfoContext(ctx, "running go mod vendor", "dir", a.config.WorkingDir)
	// Vendoring is required for SLSA compliance to ensure hermetic builds.
	// This follows the SLSA GitHub generator pattern for secure, reproducible builds.
	vendorCmd := a.executor.CommandContext(ctx, "go", "mod", "vendor")
	vendorCmd.SetDir(a.config.WorkingDir)
	if output, err := vendorCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go mod vendor: %w\n%s", err, string(output))
	}

	a.logger.InfoContext(ctx, "running go build", "command", a.config.GoCommand)
	buildCmd := a.executor.CommandContext(ctx, a.config.GoCommand[0], a.config.GoCommand[1:]...)
	buildCmd.SetDir(a.config.WorkingDir)
	if len(a.config.GoEnv) > 0 {
		buildCmd.SetEnv(append(os.Environ(), a.config.GoEnv...))
	}
	if output, err := buildCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build: %w\n%s", err, string(output))
	}

	return nil
}

// extractProvenanceFields populates attestor fields from the detected environment.
func (a *Attestor) extractProvenanceFields(ctx context.Context) {
	a.sourceURI = a.buildEnv.SourceURI()
	a.builderID = a.buildEnv.BuilderID(ctx)
	a.internalParams = a.buildEnv.InternalParameters()
	a.workflowInputs = a.buildEnv.WorkflowInputs()

	envDeps := a.buildEnv.ResolvedDependencies()
	a.resolvedDeps = make([]gobuilderpredicate.ResourceDescriptor, len(envDeps))
	for i, d := range envDeps {
		a.resolvedDeps[i] = gobuilderpredicate.ResourceDescriptor{
			Name:             d.Name,
			URI:              d.URI,
			Digest:           d.Digest,
			Content:          d.Content,
			DownloadLocation: d.DownloadLocation,
			MediaType:        d.MediaType,
			Annotations:      d.Annotations,
		}
	}

	if a.configDigest != "" {
		a.resolvedDeps = append(a.resolvedDeps, gobuilderpredicate.ResourceDescriptor{
			Name:   a.config.ConfigFile,
			Digest: map[string]string{"sha256": a.configDigest},
		})
	}

	a.metadata.InvocationID = a.buildEnv.InvocationID()

	a.logger.InfoContext(ctx, "provenance fields extracted",
		"source_uri", a.sourceURI,
		"builder_id", a.builderID,
		"resolved_deps_count", len(a.resolvedDeps))
}

// collectBuildConfigProvenance computes the config file digest and builds
// an evaluated config byproduct capturing what actually ran.
func (a *Attestor) collectBuildConfigProvenance(ctx context.Context) error {
	configResult, err := fileHasher.HashFile(ctx, a.config.ConfigFile)
	if err != nil {
		return fmt.Errorf("computing build config digest: %w", err)
	}
	configSHA256, ok := configResult.Digests[cryptohash.AlgorithmSHA256]
	if !ok {
		return fmt.Errorf("config digest missing SHA-256 result for %s", a.config.ConfigFile)
	}
	a.configDigest = configSHA256
	a.logger.InfoContext(ctx, "build config digest computed",
		"file", a.config.ConfigFile, "sha256", a.configDigest)

	evaluatedConfig := struct {
		Version int                            `json:"version"`
		Steps   []gobuilderpredicate.BuildStep `json:"steps"`
	}{
		Version: a.config.ConfigVersion,
		Steps: []gobuilderpredicate.BuildStep{
			{
				WorkingDir: a.config.WorkingDir,
				Command:    []string{"go", "mod", "vendor"},
				Env:        nil,
			},
			{
				WorkingDir: a.config.WorkingDir,
				Command:    a.config.GoCommand,
				Env:        a.config.GoEnv,
			},
		},
	}

	content, err := json.Marshal(evaluatedConfig)
	if err != nil {
		return fmt.Errorf("marshaling evaluated build config: %w", err)
	}

	contentHash := sha256.Sum256(content)
	a.byproducts = []gobuilderpredicate.ResourceDescriptor{
		{
			Name:      "buildConfig",
			MediaType: "application/json",
			Content:   content,
			Digest:    map[string]string{"sha256": hex.EncodeToString(contentHash[:])},
		},
	}

	a.logger.InfoContext(ctx, "build config byproduct created")
	return nil
}
