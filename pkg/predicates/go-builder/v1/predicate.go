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

// Package v1 provides predicate definitions for the Go Builder attestor.
package v1

const (
	// PredicateURI is the predicate type URI shared by all builder attestors.
	PredicateURI = "https://slsa.dev/provenance/v1"
)

// Predicate represents the Go Builder attestor predicate.
type Predicate struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

// BuildDefinition describes the build in terms of its type, parameters, and dependencies.
type BuildDefinition struct {
	BuildType            string               `json:"buildType"`
	ExternalParameters   ExternalParameters   `json:"externalParameters"`
	InternalParameters   map[string]any       `json:"internalParameters"`
	ResolvedDependencies []ResourceDescriptor `json:"resolvedDependencies"`
}

// ExternalParameters represents user-controlled build parameters.
type ExternalParameters struct {
	Source            string `json:"source"`
	BuildConfigSource string `json:"buildConfigSource,omitempty"`
	Inputs            any    `json:"inputs"`
}

// RunDetails describes the execution of the build.
type RunDetails struct {
	Builder    Builder              `json:"builder"`
	Metadata   Metadata             `json:"metadata"`
	Byproducts []ResourceDescriptor `json:"byproducts"`
}

// Builder identifies the build platform.
type Builder struct {
	ID                  string               `json:"id"`
	BuilderDependencies []ResourceDescriptor `json:"builderDependencies"`
	Version             map[string]string    `json:"version"`
}

// Metadata contains information about the build invocation.
type Metadata struct {
	InvocationID string `json:"invocationId"`
	StartedOn    string `json:"startedOn"`
	FinishedOn   string `json:"finishedOn"`
}

// ResourceDescriptor is a size-efficient description of any software artifact or resource.
// Spec: https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md
// At minimum, one of uri, digest, or content MUST be specified.
type ResourceDescriptor struct {
	Name             string            `json:"name,omitempty"`
	URI              string            `json:"uri,omitempty"`
	Digest           map[string]string `json:"digest,omitempty"`
	Content          []byte            `json:"content,omitempty"`
	DownloadLocation string            `json:"downloadLocation,omitempty"`
	MediaType        string            `json:"mediaType,omitempty"`
	Annotations      map[string]any    `json:"annotations,omitempty"`
}

// BuildStep represents a single build step (used in buildConfig for internal reference).
type BuildStep struct {
	WorkingDir string   `json:"workingDir"`
	Command    []string `json:"command"`
	Env        []string `json:"env,omitempty"`
}
