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

package buildenv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	gitclient "github.com/thomsonreuters/stamp/pkg/clients/git"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// GenericEnvironment represents a generic build environment.
type GenericEnvironment struct {
	logger    logger.Logger
	opts      DetectOptions
	hostname  string
	gitInfo   *gitclient.GitInfo
	gitClient gitclient.ClientIface
}

func NewGenericEnvironment(log logger.Logger, opts DetectOptions) *GenericEnvironment {
	return &GenericEnvironment{
		logger: log,
		opts:   opts,
	}
}

func (g *GenericEnvironment) Detect(ctx context.Context) (BuildEnvironment, error) {
	g.logger.InfoContext(ctx, "initializing generic build environment")

	hostname, err := os.Hostname()
	if err != nil {
		g.logger.WarnContext(ctx, "failed to get hostname", "error", err.Error())
		hostname = "unknown"
	}
	g.hostname = hostname

	if err := g.resolveWorkingDir(); err != nil {
		return nil, err
	}

	gitClient, gitErr := gitclient.New(ctx)
	if gitErr == nil {
		g.gitClient = gitClient
		if gitInfo, infoErr := g.gitClient.GetInfo(ctx, g.opts.WorkingDir); infoErr == nil {
			g.gitInfo = gitInfo
			g.logger.InfoContext(ctx, "collected git information for generic environment")
		} else {
			g.logger.WarnContext(ctx, "failed to collect git information", "error", infoErr.Error())
		}
	} else {
		g.logger.WarnContext(ctx, "git client initialization failed", "error", gitErr.Error())
	}

	g.logger.InfoContext(ctx, "build environment detected: generic")
	return g, nil
}

func (g *GenericEnvironment) Type() EnvironmentType { return EnvironmentGeneric }

// BuilderID returns the generic builder ID.
func (g *GenericEnvironment) BuilderID(_ context.Context) string {
	return BuilderIDGeneric
}

// SourceURI returns the git remote URL if available.
func (g *GenericEnvironment) SourceURI() string {
	if g.gitInfo == nil {
		return ""
	}
	return gitclient.GetSourceURI(g.gitInfo)
}

// SourceDigest returns the git commit SHA if available.
func (g *GenericEnvironment) SourceDigest() map[string]string {
	if g.gitInfo == nil || g.gitInfo.CommitHash == "" {
		return nil
	}
	return map[string]string{"gitCommit": g.gitInfo.CommitHash}
}

// InternalParameters returns minimal system information.
func (g *GenericEnvironment) InternalParameters() map[string]any {
	return map[string]any{
		"environment_type": string(EnvironmentGeneric),
	}
}

// ResolvedDependencies returns the source repository as a dependency.
func (g *GenericEnvironment) ResolvedDependencies() []ResourceDescriptor {
	var deps []ResourceDescriptor

	sourceURI := g.SourceURI()
	if sourceURI != "" {
		deps = append(deps, ResourceDescriptor{
			URI:    sourceURI,
			Digest: g.SourceDigest(),
		})
	}

	return deps
}

// InvocationID generates a globally unique ID for this build invocation.
func (g *GenericEnvironment) InvocationID() string {
	// This ensures global uniqueness without relying on environment assumptions
	return uuid.New().String()
}

// WorkflowInputs returns nil as generic environment doesn't have workflow inputs.
func (g *GenericEnvironment) WorkflowInputs() any {
	return nil
}

// resolveWorkingDir validates and resolves the working directory option.
func (g *GenericEnvironment) resolveWorkingDir() error {
	if g.opts.WorkingDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current working directory: %w", err)
		}
		g.opts.WorkingDir = cwd
		return nil
	}

	absPath, err := filepath.Abs(g.opts.WorkingDir)
	if err != nil {
		return fmt.Errorf("invalid working directory: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("working directory does not exist: %s", g.opts.WorkingDir)
		}
		return fmt.Errorf("failed to stat working directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("working directory is not a directory: %s", g.opts.WorkingDir)
	}

	g.opts.WorkingDir = absPath
	return nil
}
