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

package command

import (
	"time"

	commandpredicate "github.com/thomsonreuters/stamp/pkg/predicates/command/v1"
)

type ExecutionMode string

const (
	ExecutionModeShell  ExecutionMode = "shell"
	ExecutionModeDirect ExecutionMode = "direct"
	ExecutionModeScript ExecutionMode = "script"
)

type Config struct {
	Command              string
	ExecutionMode        ExecutionMode
	WorkingDirectory     string
	Shell                string
	Timeout              int
	CaptureStdout        bool
	CaptureStderr        bool
	MaxOutputSize        int64
	RedactPatterns       []string
	AllowedExitCodes     []int
	FailOnError          bool
	EnvironmentVariables map[string]string
}

type ExecutionResult struct {
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	ExitCode  int
	Status    string
	Stdout    []byte
	Stderr    []byte
	Truncated bool
	TimedOut  bool
}

type CommandEvidence struct {
	Command     commandpredicate.CommandInfo
	Execution   commandpredicate.ExecutionInfo
	Environment commandpredicate.EnvironmentInfo
	Output      *commandpredicate.OutputInfo
	Resources   *commandpredicate.ResourceInfo
}
