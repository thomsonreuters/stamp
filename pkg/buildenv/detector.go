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

// Package buildenv detects the build environment and collects provenance data.
package buildenv

import (
	"context"
	"errors"

	"github.com/thomsonreuters/stamp/pkg/logger"
)

type EnvironmentType string

const (
	EnvironmentGitHub  EnvironmentType = "github-actions"
	EnvironmentEC2     EnvironmentType = "ec2"
	EnvironmentGeneric EnvironmentType = "generic"
)

// ResourceDescriptor describes a software artifact or resource (in-toto spec).
type ResourceDescriptor struct {
	Name             string            `json:"name,omitempty"`
	URI              string            `json:"uri,omitempty"`
	Digest           map[string]string `json:"digest,omitempty"`
	Content          []byte            `json:"content,omitempty"`
	DownloadLocation string            `json:"downloadLocation,omitempty"`
	MediaType        string            `json:"mediaType,omitempty"`
	Annotations      map[string]any    `json:"annotations,omitempty"`
}

type BuildEnvironment interface {
	Type() EnvironmentType
	BuilderID(ctx context.Context) string
	SourceURI() string
	SourceDigest() map[string]string
	InternalParameters() map[string]any
	ResolvedDependencies() []ResourceDescriptor
	InvocationID() string
	WorkflowInputs() any
}

type DetectOptions struct {
	BuilderID           string
	WorkingDir          string
	CaptureEventPayload bool
}

type DetectionFatalError struct{ Err error }

func (e *DetectionFatalError) Error() string { return e.Err.Error() }
func (e *DetectionFatalError) Unwrap() error { return e.Err }

func DetectEnvironment(ctx context.Context, log logger.Logger, opts DetectOptions) (BuildEnvironment, error) {
	gh := NewGitHubEnvironment(log, opts)
	if env, err := gh.Detect(ctx); err == nil {
		return env, nil
	} else {
		if _, ok := errors.AsType[*DetectionFatalError](err); ok {
			return nil, err
		}
		log.DebugContext(ctx, "GitHub Actions environment not detected", "error", err.Error())
	}

	ec2 := NewEC2Environment(log, opts)
	if env, err := ec2.Detect(ctx); err == nil {
		return env, nil
	} else {
		if _, ok := errors.AsType[*DetectionFatalError](err); ok {
			return nil, err
		}
		log.DebugContext(ctx, "EC2 environment not detected", "error", err.Error())
	}

	log.InfoContext(ctx, "no specific environment detected, using generic environment")
	generic := NewGenericEnvironment(log, opts)
	return generic.Detect(ctx)
}
