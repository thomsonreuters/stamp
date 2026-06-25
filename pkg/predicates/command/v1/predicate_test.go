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

package v1

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPredicateURI(t *testing.T) {
	assert.Equal(t, "https://github.com/thomsonreuters/stamp/command/v1", PredicateURI)
}

func TestPredicate_JSONMarshal(t *testing.T) {
	startTime := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)
	endTime := time.Date(2025, 11, 12, 10, 0, 5, 0, time.UTC)

	predicate := Predicate{
		Command: CommandInfo{
			CommandLine: "go test ./...",
			Executable:  "/usr/local/bin/go",
			Arguments:   []string{"test", "./..."},
			Shell:       "/bin/bash",
		},
		Execution: ExecutionInfo{
			StartTime: startTime,
			EndTime:   endTime,
			Duration:  5000,
			ExitCode:  0,
			Status:    "success",
		},
		Environment: EnvironmentInfo{
			WorkingDirectory: "/workspace/project",
			User:             "developer",
			Hostname:         "build-server-01",
			Platform: PlatformInfo{
				OS:      "linux",
				Arch:    "amd64",
				Version: "Ubuntu 22.04",
			},
		},
		Output: &OutputInfo{
			Stdout:    "PASS\nok   \tproject\t0.123s",
			Stderr:    "",
			Truncated: false,
			Size: OutputSize{
				Stdout: 1024,
				Stderr: 0,
			},
			Digest: OutputDigest{
				Stdout: "sha256:abc123",
				Stderr: "",
			},
		},
		Resources: &ResourceInfo{
			CPU: CPUInfo{
				User:   1.5,
				System: 0.3,
				Peak:   25.5,
			},
			Memory: MemoryInfo{
				Peak:    104857600,
				Average: 52428800,
			},
			IO: IOInfo{
				BytesRead:    2048000,
				BytesWritten: 512000,
				Operations:   150,
			},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	assert.Contains(t, string(data), "command")
	assert.Contains(t, string(data), "execution")
	assert.Contains(t, string(data), "environment")
	assert.Contains(t, string(data), "output")
	assert.Contains(t, string(data), "resources")
}

func TestPredicate_JSONUnmarshal(t *testing.T) {
	jsonData := `{
		"command": {
			"command_line": "npm test",
			"executable": "/usr/bin/node",
			"arguments": ["test"],
			"shell": "/bin/sh"
		},
		"execution": {
			"start_time": "2025-11-12T10:00:00Z",
			"end_time": "2025-11-12T10:01:00Z",
			"duration": 60000,
			"exit_code": 0,
			"status": "success"
		},
		"environment": {
			"working_directory": "/app",
			"user": "node",
			"hostname": "container-123",
			"platform": {
				"os": "linux",
				"arch": "amd64",
				"version": "Alpine 3.18"
			}
		}
	}`

	var predicate Predicate
	err := json.Unmarshal([]byte(jsonData), &predicate)
	require.NoError(t, err)

	assert.Equal(t, "npm test", predicate.Command.CommandLine)
	assert.Equal(t, "/usr/bin/node", predicate.Command.Executable)
	assert.Equal(t, "success", predicate.Execution.Status)
	assert.Equal(t, "/app", predicate.Environment.WorkingDirectory)
	assert.Equal(t, "linux", predicate.Environment.Platform.OS)
}

func TestCommandInfo_Complete(t *testing.T) {
	command := CommandInfo{
		CommandLine: "docker build -t exampleapp:latest .",
		Executable:  "/usr/bin/docker",
		Arguments:   []string{"build", "-t", "exampleapp:latest", "."},
		Shell:       "/bin/bash",
	}

	data, err := json.Marshal(command)
	require.NoError(t, err)

	var result CommandInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, command.CommandLine, result.CommandLine)
	assert.Equal(t, command.Executable, result.Executable)
	assert.Len(t, result.Arguments, 4)
	assert.Equal(t, command.Shell, result.Shell)
}

func TestCommandInfo_OmitEmptyFields(t *testing.T) {
	command := CommandInfo{
		CommandLine: "echo hello",
	}

	data, err := json.Marshal(command)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "executable")
	assert.NotContains(t, string(data), "arguments")
	assert.NotContains(t, string(data), "shell")
}

func TestExecutionInfo_Complete(t *testing.T) {
	startTime := time.Date(2025, 11, 12, 14, 30, 0, 0, time.UTC)
	endTime := time.Date(2025, 11, 12, 14, 30, 10, 500000000, time.UTC)

	execution := ExecutionInfo{
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  10500,
		ExitCode:  0,
		Status:    "success",
	}

	data, err := json.Marshal(execution)
	require.NoError(t, err)

	var result ExecutionInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, startTime.Unix(), result.StartTime.Unix())
	assert.Equal(t, endTime.Unix(), result.EndTime.Unix())
	assert.Equal(t, int64(10500), result.Duration)
	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, "success", result.Status)
}

func TestExecutionInfo_StatusValues(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		exitCode int
	}{
		{
			name:     "Success",
			status:   "success",
			exitCode: 0,
		},
		{
			name:     "Failure",
			status:   "failure",
			exitCode: 1,
		},
		{
			name:     "Timeout",
			status:   "timeout",
			exitCode: 124,
		},
		{
			name:     "Killed",
			status:   "killed",
			exitCode: 137,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			execution := ExecutionInfo{
				StartTime: now,
				EndTime:   now.Add(5 * time.Second),
				Duration:  5000,
				ExitCode:  tt.exitCode,
				Status:    tt.status,
			}

			data, err := json.Marshal(execution)
			require.NoError(t, err)

			var result ExecutionInfo
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.status, result.Status)
			assert.Equal(t, tt.exitCode, result.ExitCode)
		})
	}
}

func TestEnvironmentInfo_Complete(t *testing.T) {
	environment := EnvironmentInfo{
		WorkingDirectory: "/home/user/project",
		User:             "testuser",
		Hostname:         "test-machine",
		Platform: PlatformInfo{
			OS:      "darwin",
			Arch:    "arm64",
			Version: "macOS 14.0",
		},
	}

	data, err := json.Marshal(environment)
	require.NoError(t, err)

	var result EnvironmentInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, environment.WorkingDirectory, result.WorkingDirectory)
	assert.Equal(t, environment.User, result.User)
	assert.Equal(t, environment.Hostname, result.Hostname)
	assert.Equal(t, environment.Platform.OS, result.Platform.OS)
	assert.Equal(t, environment.Platform.Arch, result.Platform.Arch)
}

func TestEnvironmentInfo_OmitEmptyUser(t *testing.T) {
	environment := EnvironmentInfo{
		WorkingDirectory: "/app",
		Hostname:         "container",
		Platform: PlatformInfo{
			OS:   "linux",
			Arch: "amd64",
		},
	}

	data, err := json.Marshal(environment)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "user")
}

func TestPlatformInfo_Complete(t *testing.T) {
	platform := PlatformInfo{
		OS:      "windows",
		Arch:    "amd64",
		Version: "Windows 11 Pro",
	}

	data, err := json.Marshal(platform)
	require.NoError(t, err)

	var result PlatformInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "windows", result.OS)
	assert.Equal(t, "amd64", result.Arch)
	assert.Equal(t, "Windows 11 Pro", result.Version)
}

func TestPlatformInfo_OmitEmptyVersion(t *testing.T) {
	platform := PlatformInfo{
		OS:   "linux",
		Arch: "amd64",
	}

	data, err := json.Marshal(platform)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "version")
}

func TestPlatformInfo_Architectures(t *testing.T) {
	architectures := []string{"amd64", "arm64", "386", "arm", "ppc64le", "s390x"}

	for _, arch := range architectures {
		t.Run(arch, func(t *testing.T) {
			platform := PlatformInfo{
				OS:   "linux",
				Arch: arch,
			}

			data, err := json.Marshal(platform)
			require.NoError(t, err)

			var result PlatformInfo
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, arch, result.Arch)
		})
	}
}

func TestPlatformInfo_OperatingSystems(t *testing.T) {
	tests := []struct {
		os      string
		version string
	}{
		{
			os:      "linux",
			version: "Ubuntu 22.04",
		},
		{
			os:      "darwin",
			version: "macOS 14.0",
		},
		{
			os:      "windows",
			version: "Windows Server 2022",
		},
		{
			os:      "freebsd",
			version: "FreeBSD 13.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.os, func(t *testing.T) {
			platform := PlatformInfo{
				OS:      tt.os,
				Arch:    "amd64",
				Version: tt.version,
			}

			data, err := json.Marshal(platform)
			require.NoError(t, err)

			var result PlatformInfo
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.os, result.OS)
			assert.Equal(t, tt.version, result.Version)
		})
	}
}

func TestOutputInfo_Complete(t *testing.T) {
	output := OutputInfo{
		Stdout:    "Build completed successfully\nArtifacts created",
		Stderr:    "Warning: deprecated flag used",
		Truncated: false,
		Size: OutputSize{
			Stdout: 2048,
			Stderr: 512,
		},
		Digest: OutputDigest{
			Stdout: "sha256:stdout123",
			Stderr: "sha256:stderr456",
		},
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	var result OutputInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, output.Stdout, result.Stdout)
	assert.Equal(t, output.Stderr, result.Stderr)
	assert.False(t, result.Truncated)
	assert.Equal(t, int64(2048), result.Size.Stdout)
	assert.Equal(t, int64(512), result.Size.Stderr)
}

func TestOutputInfo_Truncated(t *testing.T) {
	output := OutputInfo{
		Stdout:    "This is a very long output that has been truncated...",
		Stderr:    "",
		Truncated: true,
		Size: OutputSize{
			Stdout: 1048576,
			Stderr: 0,
		},
		Digest: OutputDigest{
			Stdout: "sha256:full-output-hash",
			Stderr: "",
		},
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	var result OutputInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.True(t, result.Truncated)
	assert.Equal(t, int64(1048576), result.Size.Stdout)
	assert.Contains(t, result.Stdout, "truncated")
}

func TestOutputInfo_OmitEmptyFields(t *testing.T) {
	output := OutputInfo{
		Stdout:    "output",
		Truncated: false,
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	// Note: size and digest structs are included even when fields are empty
	// because omitempty is on individual fields, not the structs themselves
	var result OutputInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "output", result.Stdout)
	assert.Empty(t, result.Stderr)
}

func TestOutputSize_Complete(t *testing.T) {
	size := OutputSize{
		Stdout: 10240,
		Stderr: 2048,
	}

	data, err := json.Marshal(size)
	require.NoError(t, err)

	var result OutputSize
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, int64(10240), result.Stdout)
	assert.Equal(t, int64(2048), result.Stderr)
}

func TestOutputSize_LargeValues(t *testing.T) {
	size := OutputSize{
		Stdout: 1073741824, // 1GB
		Stderr: 104857600,  // 100MB
	}

	data, err := json.Marshal(size)
	require.NoError(t, err)

	var result OutputSize
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, int64(1073741824), result.Stdout)
	assert.Equal(t, int64(104857600), result.Stderr)
}

func TestOutputDigest_Complete(t *testing.T) {
	digest := OutputDigest{
		Stdout: "sha256:abc123def456",
		Stderr: "sha256:789012ghi345",
	}

	data, err := json.Marshal(digest)
	require.NoError(t, err)

	var result OutputDigest
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "sha256:abc123def456", result.Stdout)
	assert.Equal(t, "sha256:789012ghi345", result.Stderr)
}

func TestOutputDigest_OmitEmptyFields(t *testing.T) {
	digest := OutputDigest{
		Stdout: "sha256:stdout-only",
	}

	data, err := json.Marshal(digest)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "stderr")
}

func TestResourceInfo_Complete(t *testing.T) {
	resources := ResourceInfo{
		CPU: CPUInfo{
			User:   5.5,
			System: 1.2,
			Peak:   45.8,
		},
		Memory: MemoryInfo{
			Peak:    524288000,
			Average: 262144000,
		},
		IO: IOInfo{
			BytesRead:    10485760,
			BytesWritten: 5242880,
			Operations:   500,
		},
	}

	data, err := json.Marshal(resources)
	require.NoError(t, err)

	var result ResourceInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.InDelta(t, 5.5, result.CPU.User, 0.001)
	assert.InDelta(t, 1.2, result.CPU.System, 0.001)
	assert.InDelta(t, 45.8, result.CPU.Peak, 0.001)
	assert.Equal(t, int64(524288000), result.Memory.Peak)
	assert.Equal(t, int64(262144000), result.Memory.Average)
	assert.Equal(t, int64(10485760), result.IO.BytesRead)
	assert.Equal(t, int64(5242880), result.IO.BytesWritten)
	assert.Equal(t, int64(500), result.IO.Operations)
}

func TestResourceInfo_OmitEmptyFields(t *testing.T) {
	resources := ResourceInfo{
		CPU: CPUInfo{
			User: 1.0,
		},
	}

	data, err := json.Marshal(resources)
	require.NoError(t, err)

	// CPU struct fields have omitempty
	assert.NotContains(t, string(data), "system")
	assert.NotContains(t, string(data), "peak")
}

func TestCPUInfo_Complete(t *testing.T) {
	cpu := CPUInfo{
		User:   10.5,
		System: 2.3,
		Peak:   75.2,
	}

	data, err := json.Marshal(cpu)
	require.NoError(t, err)

	var result CPUInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.InDelta(t, 10.5, result.User, 0.001)
	assert.InDelta(t, 2.3, result.System, 0.001)
	assert.InDelta(t, 75.2, result.Peak, 0.001)
}

func TestCPUInfo_OmitEmptyFields(t *testing.T) {
	cpu := CPUInfo{
		User: 5.0,
	}

	data, err := json.Marshal(cpu)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "system")
	assert.NotContains(t, string(data), "peak")
}

func TestCPUInfo_HighValues(t *testing.T) {
	cpu := CPUInfo{
		User:   3600.5, // 1 hour of user time
		System: 900.2,  // 15 minutes of system time
		Peak:   100.0,  // 100% peak
	}

	data, err := json.Marshal(cpu)
	require.NoError(t, err)

	var result CPUInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.InDelta(t, 3600.5, result.User, 0.001)
	assert.InDelta(t, 900.2, result.System, 0.001)
	assert.InDelta(t, 100.0, result.Peak, 0.001)
}

func TestMemoryInfo_Complete(t *testing.T) {
	memory := MemoryInfo{
		Peak:    1073741824,
		Average: 536870912,
	}

	data, err := json.Marshal(memory)
	require.NoError(t, err)

	var result MemoryInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, int64(1073741824), result.Peak)
	assert.Equal(t, int64(536870912), result.Average)
}

func TestMemoryInfo_OmitEmptyFields(t *testing.T) {
	memory := MemoryInfo{
		Peak: 104857600,
	}

	data, err := json.Marshal(memory)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "average")
}

func TestMemoryInfo_LargeValues(t *testing.T) {
	memory := MemoryInfo{
		Peak:    17179869184, // 16GB
		Average: 8589934592,  // 8GB
	}

	data, err := json.Marshal(memory)
	require.NoError(t, err)

	var result MemoryInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, int64(17179869184), result.Peak)
	assert.Equal(t, int64(8589934592), result.Average)
}

func TestIOInfo_Complete(t *testing.T) {
	io := IOInfo{
		BytesRead:    52428800,
		BytesWritten: 10485760,
		Operations:   1000,
	}

	data, err := json.Marshal(io)
	require.NoError(t, err)

	var result IOInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, int64(52428800), result.BytesRead)
	assert.Equal(t, int64(10485760), result.BytesWritten)
	assert.Equal(t, int64(1000), result.Operations)
}

func TestIOInfo_OmitEmptyFields(t *testing.T) {
	io := IOInfo{
		BytesRead: 1024,
	}

	data, err := json.Marshal(io)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "bytesWritten")
	assert.NotContains(t, string(data), "operations")
}

func TestIOInfo_LargeValues(t *testing.T) {
	io := IOInfo{
		BytesRead:    107374182400, // 100GB
		BytesWritten: 53687091200,  // 50GB
		Operations:   10000000,     // 10M operations
	}

	data, err := json.Marshal(io)
	require.NoError(t, err)

	var result IOInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, int64(107374182400), result.BytesRead)
	assert.Equal(t, int64(53687091200), result.BytesWritten)
	assert.Equal(t, int64(10000000), result.Operations)
}

func TestPredicate_Complete(t *testing.T) {
	startTime := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)
	endTime := time.Date(2025, 11, 12, 10, 5, 30, 0, time.UTC)

	predicate := Predicate{
		Command: CommandInfo{
			CommandLine: "cargo build --release",
			Executable:  "/usr/bin/cargo",
			Arguments:   []string{"build", "--release"},
			Shell:       "/bin/bash",
		},
		Execution: ExecutionInfo{
			StartTime: startTime,
			EndTime:   endTime,
			Duration:  330000,
			ExitCode:  0,
			Status:    "success",
		},
		Environment: EnvironmentInfo{
			WorkingDirectory: "/home/developer/rust-project",
			User:             "developer",
			Hostname:         "build-machine-01",
			Platform: PlatformInfo{
				OS:      "linux",
				Arch:    "amd64",
				Version: "Ubuntu 22.04.3 LTS",
			},
		},
		Output: &OutputInfo{
			Stdout:    "   Compiling project v1.0.0\n    Finished release [optimized] target(s) in 5m 30s",
			Stderr:    "",
			Truncated: false,
			Size: OutputSize{
				Stdout: 4096,
				Stderr: 0,
			},
			Digest: OutputDigest{
				Stdout: "sha256:complete-stdout-hash",
				Stderr: "",
			},
		},
		Resources: &ResourceInfo{
			CPU: CPUInfo{
				User:   300.5,
				System: 30.2,
				Peak:   95.8,
			},
			Memory: MemoryInfo{
				Peak:    2147483648,
				Average: 1073741824,
			},
			IO: IOInfo{
				BytesRead:    536870912,
				BytesWritten: 104857600,
				Operations:   5000,
			},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, predicate.Command.CommandLine, result.Command.CommandLine)
	assert.Equal(t, predicate.Execution.Status, result.Execution.Status)
	assert.Equal(t, predicate.Environment.WorkingDirectory, result.Environment.WorkingDirectory)
	assert.NotNil(t, result.Output)
	assert.NotNil(t, result.Resources)
	assert.InDelta(t, 300.5, result.Resources.CPU.User, 0.001)
	assert.Equal(t, int64(2147483648), result.Resources.Memory.Peak)
}

func TestPredicate_Minimal(t *testing.T) {
	startTime := time.Now()
	endTime := startTime.Add(1 * time.Second)

	predicate := Predicate{
		Command: CommandInfo{
			CommandLine: "echo hello",
		},
		Execution: ExecutionInfo{
			StartTime: startTime,
			EndTime:   endTime,
			Duration:  1000,
			ExitCode:  0,
			Status:    "success",
		},
		Environment: EnvironmentInfo{
			WorkingDirectory: "/tmp",
			Hostname:         "localhost",
			Platform: PlatformInfo{
				OS:   "linux",
				Arch: "amd64",
			},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "echo hello", result.Command.CommandLine)
	assert.Equal(t, "success", result.Execution.Status)
	assert.Nil(t, result.Output)
	assert.Nil(t, result.Resources)
}

func TestPredicate_OmitEmptyOutput(t *testing.T) {
	startTime := time.Now()
	endTime := startTime.Add(1 * time.Second)

	predicate := Predicate{
		Command: CommandInfo{
			CommandLine: "test command",
		},
		Execution: ExecutionInfo{
			StartTime: startTime,
			EndTime:   endTime,
			Duration:  1000,
			ExitCode:  0,
			Status:    "success",
		},
		Environment: EnvironmentInfo{
			WorkingDirectory: "/test",
			Hostname:         "test-host",
			Platform: PlatformInfo{
				OS:   "linux",
				Arch: "amd64",
			},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "output")
	assert.NotContains(t, string(data), "resources")
}

func TestPredicate_OmitEmptyResources(t *testing.T) {
	startTime := time.Now()
	endTime := startTime.Add(1 * time.Second)

	predicate := Predicate{
		Command: CommandInfo{
			CommandLine: "test",
		},
		Execution: ExecutionInfo{
			StartTime: startTime,
			EndTime:   endTime,
			Duration:  1000,
			ExitCode:  0,
			Status:    "success",
		},
		Environment: EnvironmentInfo{
			WorkingDirectory: "/test",
			Hostname:         "test",
			Platform: PlatformInfo{
				OS:   "linux",
				Arch: "amd64",
			},
		},
		Output: &OutputInfo{
			Stdout: "output",
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	assert.Contains(t, string(data), "output")
	assert.NotContains(t, string(data), "resources")
}

func TestCommandInfo_ComplexArguments(t *testing.T) {
	command := CommandInfo{
		CommandLine: "ffmpeg -i input.mp4 -vcodec libx264 -acodec aac output.mp4",
		Executable:  "/usr/bin/ffmpeg",
		Arguments: []string{
			"-i", "input.mp4",
			"-vcodec", "libx264",
			"-acodec", "aac",
			"output.mp4",
		},
		Shell: "/bin/sh",
	}

	data, err := json.Marshal(command)
	require.NoError(t, err)

	var result CommandInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Len(t, result.Arguments, 7)
	assert.Contains(t, result.Arguments, "-vcodec")
	assert.Contains(t, result.Arguments, "libx264")
}

func TestCommandInfo_ShellTypes(t *testing.T) {
	shells := []string{
		"/bin/sh",
		"/bin/bash",
		"/bin/zsh",
		"/usr/bin/fish",
		"C:\\Windows\\System32\\cmd.exe",
		"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
	}

	for _, shell := range shells {
		t.Run(shell, func(t *testing.T) {
			command := CommandInfo{
				CommandLine: "test command",
				Shell:       shell,
			}

			data, err := json.Marshal(command)
			require.NoError(t, err)

			var result CommandInfo
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, shell, result.Shell)
		})
	}
}

func TestExecutionInfo_TimeFormats(t *testing.T) {
	tests := []struct {
		name     string
		jsonTime string
		valid    bool
	}{
		{
			name:     "RFC3339 format",
			jsonTime: `{"start_time":"2025-11-12T10:00:00Z","end_time":"2025-11-12T10:00:01Z","duration":1000,"exit_code":0,"status":"success"}`,
			valid:    true,
		},
		{
			name:     "RFC3339 with timezone",
			jsonTime: `{"start_time":"2025-11-12T10:00:00+05:30","end_time":"2025-11-12T10:00:01+05:30","duration":1000,"exit_code":0,"status":"success"}`,
			valid:    true,
		},
		{
			name:     "RFC3339 with nanoseconds",
			jsonTime: `{"start_time":"2025-11-12T10:00:00.123456Z","end_time":"2025-11-12T10:00:01.123456Z","duration":1000,"exit_code":0,"status":"success"}`,
			valid:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var execution ExecutionInfo
			err := json.Unmarshal([]byte(tt.jsonTime), &execution)

			if tt.valid {
				require.NoError(t, err)
				assert.False(t, execution.StartTime.IsZero())
				assert.False(t, execution.EndTime.IsZero())
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestExecutionInfo_LongRunning(t *testing.T) {
	startTime := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)
	endTime := time.Date(2025, 11, 12, 12, 30, 45, 0, time.UTC)

	execution := ExecutionInfo{
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  9045000, // 2 hours 30 minutes 45 seconds in milliseconds
		ExitCode:  0,
		Status:    "success",
	}

	data, err := json.Marshal(execution)
	require.NoError(t, err)

	var result ExecutionInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, int64(9045000), result.Duration)
	assert.Equal(t, "success", result.Status)
}

func TestExecutionInfo_NonZeroExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		exitCode int
		status   string
	}{
		{
			name:     "Standard Error",
			exitCode: 1,
			status:   "failure",
		},
		{
			name:     "Command Not Found",
			exitCode: 127,
			status:   "failure",
		},
		{
			name:     "Permission Denied",
			exitCode: 126,
			status:   "failure",
		},
		{
			name:     "Timeout Signal",
			exitCode: 124,
			status:   "timeout",
		},
		{
			name:     "SIGTERM",
			exitCode: 143,
			status:   "killed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			execution := ExecutionInfo{
				StartTime: now,
				EndTime:   now.Add(1 * time.Second),
				Duration:  1000,
				ExitCode:  tt.exitCode,
				Status:    tt.status,
			}

			data, err := json.Marshal(execution)
			require.NoError(t, err)

			var result ExecutionInfo
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.exitCode, result.ExitCode)
			assert.Equal(t, tt.status, result.Status)
		})
	}
}

func TestOutputInfo_EmptyOutput(t *testing.T) {
	output := OutputInfo{
		Stdout:    "",
		Stderr:    "",
		Truncated: false,
		Size: OutputSize{
			Stdout: 0,
			Stderr: 0,
		},
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	var result OutputInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Empty(t, result.Stdout)
	assert.Empty(t, result.Stderr)
	assert.Equal(t, int64(0), result.Size.Stdout)
}

func TestOutputInfo_StderrOnly(t *testing.T) {
	output := OutputInfo{
		Stdout: "",
		Stderr: "Error: connection refused",
		Size: OutputSize{
			Stdout: 0,
			Stderr: 512,
		},
		Digest: OutputDigest{
			Stderr: "sha256:error-hash",
		},
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	var result OutputInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Empty(t, result.Stdout)
	assert.NotEmpty(t, result.Stderr)
	assert.Equal(t, int64(512), result.Size.Stderr)
}

func TestOutputInfo_MultilineOutput(t *testing.T) {
	stdout := `Line 1
Line 2
Line 3
Line 4
Line 5`

	output := OutputInfo{
		Stdout: stdout,
		Size: OutputSize{
			Stdout: int64(len(stdout)),
		},
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	var result OutputInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Contains(t, result.Stdout, "Line 1")
	assert.Contains(t, result.Stdout, "Line 5")
}

func TestOutputInfo_UTF8Encoding(t *testing.T) {
	output := OutputInfo{
		Stdout:         "Hello, World!",
		StdoutEncoding: "utf-8",
		Stderr:         "Error message",
		StderrEncoding: "utf-8",
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	var result OutputInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "Hello, World!", result.Stdout)
	assert.Equal(t, "utf-8", result.StdoutEncoding)
	assert.Equal(t, "Error message", result.Stderr)
	assert.Equal(t, "utf-8", result.StderrEncoding)
}

func TestOutputInfo_Base64Encoding(t *testing.T) {
	// Simulate base64-encoded binary data
	binaryData := []byte{0xFF, 0xFE, 0xFD, 0xFC, 0x00, 0x01, 0x02}
	// Generate the correct base64 encoding
	base64Stdout := base64.StdEncoding.EncodeToString(binaryData)

	output := OutputInfo{
		Stdout:         base64Stdout,
		StdoutEncoding: "base64",
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	var result OutputInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, base64Stdout, result.Stdout)
	assert.Equal(t, "base64", result.StdoutEncoding)

	// Verify it's valid base64 and can be decoded back to original
	decoded, err := base64.StdEncoding.DecodeString(result.Stdout)
	require.NoError(t, err)
	assert.Equal(t, binaryData, decoded)
}

func TestOutputInfo_MixedEncodings(t *testing.T) {
	// Test case where stdout is text but stderr is binary
	output := OutputInfo{
		Stdout:         "Normal text output",
		StdoutEncoding: "utf-8",
		Stderr:         "AP/+/fw=", // base64 encoded binary
		StderrEncoding: "base64",
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	var result OutputInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "Normal text output", result.Stdout)
	assert.Equal(t, "utf-8", result.StdoutEncoding)
	assert.Equal(t, "AP/+/fw=", result.Stderr)
	assert.Equal(t, "base64", result.StderrEncoding)
}

func TestOutputInfo_EncodingOmitEmpty(t *testing.T) {
	// Test that encoding fields are omitted when empty
	output := OutputInfo{
		Stdout: "test output",
		// StdoutEncoding intentionally not set
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	// Verify encoding field is not present in JSON
	assert.NotContains(t, string(data), "stdout_encoding")

	var result OutputInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "test output", result.Stdout)
	assert.Empty(t, result.StdoutEncoding)
}

func TestOutputInfo_UnicodeWithUTF8Encoding(t *testing.T) {
	// Test unicode characters with UTF-8 encoding
	output := OutputInfo{
		Stdout:         "Hello 世界 🌍 Ωμέγα",
		StdoutEncoding: "utf-8",
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	var result OutputInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "Hello 世界 🌍 Ωμέγα", result.Stdout)
	assert.Equal(t, "utf-8", result.StdoutEncoding)
}

func TestPredicate_FailedCommand(t *testing.T) {
	startTime := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)
	endTime := time.Date(2025, 11, 12, 10, 0, 2, 0, time.UTC)

	predicate := Predicate{
		Command: CommandInfo{
			CommandLine: "make test",
			Executable:  "/usr/bin/make",
			Arguments:   []string{"test"},
		},
		Execution: ExecutionInfo{
			StartTime: startTime,
			EndTime:   endTime,
			Duration:  2000,
			ExitCode:  2,
			Status:    "failure",
		},
		Environment: EnvironmentInfo{
			WorkingDirectory: "/project",
			User:             "ci",
			Hostname:         "ci-runner-01",
			Platform: PlatformInfo{
				OS:   "linux",
				Arch: "amd64",
			},
		},
		Output: &OutputInfo{
			Stdout: "Running tests...",
			Stderr: "FAIL: test_integration failed\nError: assertion failed",
			Size: OutputSize{
				Stdout: 1024,
				Stderr: 2048,
			},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "failure", result.Execution.Status)
	assert.Equal(t, 2, result.Execution.ExitCode)
	assert.NotEmpty(t, result.Output.Stderr)
}

func TestPredicate_TimeoutCommand(t *testing.T) {
	startTime := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)
	endTime := time.Date(2025, 11, 12, 10, 10, 0, 0, time.UTC)

	predicate := Predicate{
		Command: CommandInfo{
			CommandLine: "sleep infinity",
		},
		Execution: ExecutionInfo{
			StartTime: startTime,
			EndTime:   endTime,
			Duration:  600000, // 10 minutes
			ExitCode:  124,
			Status:    "timeout",
		},
		Environment: EnvironmentInfo{
			WorkingDirectory: "/tmp",
			Hostname:         "test",
			Platform: PlatformInfo{
				OS:   "linux",
				Arch: "amd64",
			},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "timeout", result.Execution.Status)
	assert.Equal(t, 124, result.Execution.ExitCode)
}

func TestEnvironmentInfo_ContainerEnvironment(t *testing.T) {
	environment := EnvironmentInfo{
		WorkingDirectory: "/app",
		User:             "root",
		Hostname:         "container-abc123def456",
		Platform: PlatformInfo{
			OS:      "linux",
			Arch:    "amd64",
			Version: "Alpine Linux v3.18",
		},
	}

	data, err := json.Marshal(environment)
	require.NoError(t, err)

	var result EnvironmentInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "root", result.User)
	assert.Contains(t, result.Hostname, "container")
	assert.Contains(t, result.Platform.Version, "Alpine")
}

func TestResourceInfo_Minimal(t *testing.T) {
	resources := ResourceInfo{
		CPU: CPUInfo{
			User: 0.1,
		},
	}

	data, err := json.Marshal(resources)
	require.NoError(t, err)

	var result ResourceInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.InDelta(t, 0.1, result.CPU.User, 0.001)
}

func TestResourceInfo_MemoryOnly(t *testing.T) {
	resources := ResourceInfo{
		Memory: MemoryInfo{
			Peak:    104857600,
			Average: 52428800,
		},
	}

	data, err := json.Marshal(resources)
	require.NoError(t, err)

	var result ResourceInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, int64(104857600), result.Memory.Peak)
	assert.Equal(t, int64(52428800), result.Memory.Average)
}

func TestResourceInfo_IOOnly(t *testing.T) {
	resources := ResourceInfo{
		IO: IOInfo{
			BytesRead:    1048576,
			BytesWritten: 524288,
			Operations:   100,
		},
	}

	data, err := json.Marshal(resources)
	require.NoError(t, err)

	var result ResourceInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, int64(1048576), result.IO.BytesRead)
	assert.Equal(t, int64(524288), result.IO.BytesWritten)
	assert.Equal(t, int64(100), result.IO.Operations)
}
