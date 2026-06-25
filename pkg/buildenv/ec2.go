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
	"errors"
	"fmt"
	"os"
	"time"

	awsec2 "github.com/thomsonreuters/stamp/pkg/clients/aws/ec2"
	gitclient "github.com/thomsonreuters/stamp/pkg/clients/git"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

type EC2Environment struct {
	logger           logger.Logger
	opts             DetectOptions
	instanceID       string
	instanceType     string
	region           string
	availabilityZone string
	accountID        string
	imageID          string
	architecture     string
	gitInfo          *gitclient.GitInfo
	gitClient        gitclient.ClientIface
}

func NewEC2Environment(log logger.Logger, opts DetectOptions) *EC2Environment {
	return &EC2Environment{
		logger: log,
		opts:   opts,
	}
}

func (e *EC2Environment) Detect(ctx context.Context) (BuildEnvironment, error) {
	client := awsec2.New(e.logger)
	if client == nil {
		return nil, errors.New("failed to create EC2 client")
	}
	imdsOpts := &awsec2.IMDSOptions{
		Endpoint: awsec2.DefaultIMDSEndpoint,
		Version:  awsec2.IMDSVersionAuto,
		Timeout:  awsec2.IMDSAccessibilityCheckTimeout,
	}

	if err := client.CheckIMDSAccessibility(ctx, imdsOpts); err != nil {
		return nil, fmt.Errorf("IMDS not accessible: %w", err)
	}

	doc, err := client.GetInstanceIdentityDocument(ctx, imdsOpts)
	if err != nil {
		e.logger.WarnContext(ctx, "EC2 identity document unavailable", "error", err.Error())
		return nil, fmt.Errorf("EC2 identity document unavailable: %w", err)
	}

	e.instanceID = doc.InstanceID
	e.instanceType = doc.InstanceType
	e.region = doc.Region
	e.availabilityZone = doc.AvailabilityZone
	e.accountID = doc.AccountID
	e.imageID = doc.ImageID
	e.architecture = doc.Architecture

	e.logger.InfoContext(ctx, "build environment detected: AWS EC2",
		"instance_id", e.instanceID,
		"region", e.region,
		"instance_type", e.instanceType)

	e.collectGitInfo(ctx)

	if e.gitInfo == nil {
		return nil, &DetectionFatalError{
			Err: errors.New("EC2 environment detected but no git repository found: attestations require source traceability"),
		}
	}

	return e, nil
}

func (e *EC2Environment) Type() EnvironmentType { return EnvironmentEC2 }

func (e *EC2Environment) collectGitInfo(ctx context.Context) {
	workDir := e.opts.WorkingDir
	if workDir == "" {
		workDir = "."
	}

	gc, err := gitclient.New(ctx, gitclient.WithLogger(e.logger))
	if err != nil {
		e.logger.ErrorContext(ctx, "git client initialization failed - attestations require git repository", "error", err.Error())
		return
	}

	if !gc.IsGitRepository(ctx, workDir) {
		e.logger.ErrorContext(ctx, "not a git repository - attestations require source traceability", "path", workDir)
		return
	}

	info, err := gc.GetInfo(ctx, workDir)
	if err != nil {
		e.logger.ErrorContext(ctx, "git info collection failed", "error", err.Error())
		return
	}

	e.gitInfo = info
	e.gitClient = gc
	e.logger.InfoContext(ctx, "git info collected",
		"remote", e.gitClient.GetHTMLURL(info.RemoteOriginURL),
		"branch", info.Branch,
		"commit", info.CommitHash)
}

// BuilderID returns the EC2 builder URI.
func (e *EC2Environment) BuilderID(_ context.Context) string {
	return BuilderIDEC2
}

func (e *EC2Environment) SourceURI() string {
	if e.gitInfo == nil {
		return ""
	}
	return gitclient.GetSourceURI(e.gitInfo)
}

func (e *EC2Environment) SourceDigest() map[string]string {
	if e.gitInfo != nil && e.gitInfo.CommitHash != "" {
		return map[string]string{"gitCommit": e.gitInfo.CommitHash}
	}
	return nil
}

// InternalParameters returns EC2-specific instance information.
func (e *EC2Environment) InternalParameters() map[string]any {
	return map[string]any{
		"environment_type":  string(EnvironmentEC2),
		"instance_id":       e.instanceID,
		"instance_type":     e.instanceType,
		"region":            e.region,
		"availability_zone": e.availabilityZone,
		"account_id":        e.accountID,
		"image_id":          e.imageID,
		"architecture":      e.architecture,
	}
}

func (e *EC2Environment) ResolvedDependencies() []ResourceDescriptor {
	var deps []ResourceDescriptor

	if uri := e.SourceURI(); uri != "" {
		dep := ResourceDescriptor{URI: uri}
		if digest := e.SourceDigest(); digest != nil {
			dep.Digest = digest
		}
		deps = append(deps, dep)
	}

	if e.imageID != "" {
		deps = append(deps, ResourceDescriptor{
			URI: fmt.Sprintf("https://aws.amazon.com/ec2/ami/%s/%s", e.region, e.imageID),
		})
	}

	return deps
}

func (e *EC2Environment) InvocationID() string {
	timestamp := time.Now().UnixMicro()

	// Include CodeBuild identifier if available
	if buildID := os.Getenv("CODEBUILD_BUILD_ID"); buildID != "" {
		return fmt.Sprintf("%s:%s:%d", buildID, e.instanceID, timestamp)
	}

	// Include CodePipeline identifier if available
	if executionID := os.Getenv("CODEPIPELINE_EXECUTION_ID"); executionID != "" {
		return fmt.Sprintf("pipeline:%s:%s:%d", executionID, e.instanceID, timestamp)
	}

	// Fallback for plain EC2 instances
	return fmt.Sprintf("%s-%d", e.instanceID, timestamp)
}

func (e *EC2Environment) WorkflowInputs() any {
	return nil
}
