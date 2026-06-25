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

// Package v1 provides version 1 predicate definitions for command execution attestations.
package v1

import "time"

const (
	// PredicateURI is the custom predicate type URI for command execution attestations.
	PredicateURI = "https://github.com/thomsonreuters/stamp/command/v1"
)

type Predicate struct {
	Command     CommandInfo     `json:"command"`
	Execution   ExecutionInfo   `json:"execution"`
	Environment EnvironmentInfo `json:"environment"`
	Output      *OutputInfo     `json:"output,omitempty"`
	Resources   *ResourceInfo   `json:"resources,omitempty"`
}

// CommandInfo describes the command that was executed.
type CommandInfo struct {
	CommandLine string   `json:"command_line"`
	Executable  string   `json:"executable,omitempty"`
	Arguments   []string `json:"arguments,omitempty"`
	Shell       string   `json:"shell,omitempty"`
}

// ExecutionInfo contains timing and status information.
type ExecutionInfo struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Duration  int64     `json:"duration"`
	ExitCode  int       `json:"exit_code"`
	Status    string    `json:"status"`
}

// EnvironmentInfo captures the execution environment.
type EnvironmentInfo struct {
	WorkingDirectory string       `json:"working_directory"`
	User             string       `json:"user,omitempty"`
	Hostname         string       `json:"hostname"`
	Platform         PlatformInfo `json:"platform"`
}

// PlatformInfo describes the operating system and architecture.
type PlatformInfo struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Version string `json:"version,omitempty"`
}

// OutputInfo holds command output with metadata.
type OutputInfo struct {
	Stdout         string       `json:"stdout,omitempty"`
	Stderr         string       `json:"stderr,omitempty"`
	StdoutEncoding string       `json:"stdout_encoding,omitempty"`
	StderrEncoding string       `json:"stderr_encoding,omitempty"`
	Truncated      bool         `json:"truncated,omitempty"`
	Size           OutputSize   `json:"size"`
	Digest         OutputDigest `json:"digest"`
}

// OutputSize tracks the size of stdout and stderr.
type OutputSize struct {
	Stdout int64 `json:"stdout"`
	Stderr int64 `json:"stderr"`
}

// OutputDigest contains hashes of the output.
type OutputDigest struct {
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
}

// ResourceInfo tracks resource usage during execution.
type ResourceInfo struct {
	CPU    CPUInfo    `json:"cpu"`
	Memory MemoryInfo `json:"memory"`
	IO     IOInfo     `json:"io"`
}

// CPUInfo contains CPU usage metrics.
type CPUInfo struct {
	User   float64 `json:"user,omitempty"`
	System float64 `json:"system,omitempty"`
	Peak   float64 `json:"peak,omitempty"`
}

// MemoryInfo contains memory usage metrics.
type MemoryInfo struct {
	Peak    int64 `json:"peak,omitempty"`
	Average int64 `json:"average,omitempty"`
}

// IOInfo contains I/O metrics.
type IOInfo struct {
	BytesRead    int64 `json:"bytes_read,omitempty"`
	BytesWritten int64 `json:"bytes_written,omitempty"`
	Operations   int64 `json:"operations,omitempty"`
}
