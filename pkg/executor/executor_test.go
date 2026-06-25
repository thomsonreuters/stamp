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

package executor

import (
	"bytes"
	"context"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOSCommandExecutor_CommandContext(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		args     []string
		wantType string
	}{
		{
			name:     "Simple command without args",
			command:  "echo",
			args:     []string{},
			wantType: "*executor.osCommand",
		},
		{
			name:     "Command with single arg",
			command:  "echo",
			args:     []string{"hello"},
			wantType: "*executor.osCommand",
		},
		{
			name:     "Command with multiple args",
			command:  "echo",
			args:     []string{"hello", "world"},
			wantType: "*executor.osCommand",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := &OSCommandExecutor{}

			cmd := executor.CommandContext(t.Context(), tt.command, tt.args...)

			assert.NotNil(t, cmd, "CommandContext should return a non-nil Command")
			assert.Implements(t, (*Command)(nil), cmd, "Returned value should implement Command interface")

			_, ok := cmd.(*osCommand)
			assert.True(t, ok, "CommandContext should return an *osCommand")
		})
	}
}

func TestOSCommandExecutor_CommandContext_WithCancellation(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx, cancel := context.WithCancel(t.Context())

	var sleepCmd string
	if runtime.GOOS == "windows" {
		sleepCmd = "timeout"
	} else {
		sleepCmd = "sleep"
	}

	cmd := executor.CommandContext(ctx, sleepCmd, "10")

	cancel()
	time.Sleep(10 * time.Millisecond)

	err := cmd.Run()
	assert.Error(t, err, "Command should fail when context is cancelled")
}

//nolint:dupl // Output and CombinedOutput tests are intentionally similar
func TestOSCommand_Output(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	tests := []struct {
		name        string
		command     string
		args        []string
		wantErr     bool
		wantContain string
	}{
		{
			name:        "Echo command",
			command:     "echo",
			args:        []string{"hello world"},
			wantErr:     false,
			wantContain: "hello world",
		},
		{
			name:    "Invalid command",
			command: "nonexistent_command_xyz123",
			args:    []string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := executor.CommandContext(ctx, tt.command, tt.args...)
			output, err := cmd.Output()

			if tt.wantErr {
				assert.Error(t, err, "Output should return an error for invalid command")
			} else {
				assert.NoError(t, err, "Output should not return an error")
				if tt.wantContain != "" {
					assert.Contains(t, string(output), tt.wantContain, "Output should contain expected string")
				}
			}
		})
	}
}

//nolint:dupl // Output and CombinedOutput tests are intentionally similar
func TestOSCommand_CombinedOutput(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	tests := []struct {
		name        string
		command     string
		args        []string
		wantErr     bool
		wantContain string
	}{
		{
			name:        "Echo command",
			command:     "echo",
			args:        []string{"test output"},
			wantErr:     false,
			wantContain: "test output",
		},
		{
			name:    "Invalid command",
			command: "nonexistent_command_xyz123",
			args:    []string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := executor.CommandContext(ctx, tt.command, tt.args...)
			output, err := cmd.CombinedOutput()

			if tt.wantErr {
				assert.Error(t, err, "CombinedOutput should return an error for invalid command")
			} else {
				assert.NoError(t, err, "CombinedOutput should not return an error")
				if tt.wantContain != "" {
					assert.Contains(t, string(output), tt.wantContain, "Output should contain expected string")
				}
			}
		})
	}
}

func TestOSCommand_Run(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	tests := []struct {
		name    string
		command string
		args    []string
		wantErr bool
	}{
		{
			name:    "Valid command",
			command: "echo",
			args:    []string{"test"},
			wantErr: false,
		},
		{
			name:    "Invalid command",
			command: "nonexistent_command_xyz123",
			args:    []string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := executor.CommandContext(ctx, tt.command, tt.args...)
			err := cmd.Run()

			if tt.wantErr {
				assert.Error(t, err, "Run should return an error for invalid command")
			} else {
				assert.NoError(t, err, "Run should not return an error")
			}
		})
	}
}

func TestOSCommand_StartAndWait(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	tests := []struct {
		name       string
		command    string
		args       []string
		wantErr    bool
		shouldWait bool
	}{
		{
			name:       "Valid command with wait",
			command:    "echo",
			args:       []string{"test"},
			wantErr:    false,
			shouldWait: true,
		},
		{
			name:       "Invalid command",
			command:    "nonexistent_command_xyz123",
			args:       []string{},
			wantErr:    true,
			shouldWait: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := executor.CommandContext(ctx, tt.command, tt.args...)
			err := cmd.Start()

			if tt.wantErr {
				assert.Error(t, err, "Start should return an error for invalid command")
				return
			}

			require.NoError(t, err, "Start should not return an error")

			if tt.shouldWait {
				err = cmd.Wait()
				assert.NoError(t, err, "Wait should not return an error")
			}
		})
	}
}

func TestOSCommand_StdoutPipe(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	cmd := executor.CommandContext(ctx, "echo", "test stdout pipe")

	pipe, err := cmd.StdoutPipe()
	require.NoError(t, err, "StdoutPipe should not return an error")
	require.NotNil(t, pipe, "StdoutPipe should return a non-nil pipe")

	_, ok := pipe.(io.Reader)
	assert.True(t, ok, "StdoutPipe should return an io.Reader")

	err = cmd.Start()
	require.NoError(t, err, "Start should not return an error")

	reader, ok := pipe.(io.Reader)
	require.True(t, ok)
	output, err := io.ReadAll(reader)
	require.NoError(t, err, "Reading from stdout pipe should not return an error")

	err = cmd.Wait()
	require.NoError(t, err, "Wait should not return an error")

	assert.Contains(t, string(output), "test stdout pipe", "Output should contain expected string")
}

func TestOSCommand_StderrPipe(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	var cmd Command
	if runtime.GOOS == "windows" {
		cmd = executor.CommandContext(ctx, "cmd", "/c", "echo test stderr pipe 1>&2")
	} else {
		cmd = executor.CommandContext(ctx, "sh", "-c", "echo 'test stderr pipe' >&2")
	}

	pipe, err := cmd.StderrPipe()
	require.NoError(t, err, "StderrPipe should not return an error")
	require.NotNil(t, pipe, "StderrPipe should return a non-nil pipe")

	_, ok := pipe.(io.Reader)
	assert.True(t, ok, "StderrPipe should return an io.Reader")

	err = cmd.Start()
	require.NoError(t, err, "Start should not return an error")

	reader, ok := pipe.(io.Reader)
	require.True(t, ok)
	output, err := io.ReadAll(reader)
	require.NoError(t, err, "Reading from stderr pipe should not return an error")

	err = cmd.Wait()
	require.NoError(t, err, "Wait should not return an error")

	assert.Contains(t, string(output), "test stderr pipe", "Output should contain expected string")
}

func TestOSCommand_SetDir(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	tmpDir := t.TempDir()

	testFile := "testfile.txt"
	fullPath := tmpDir + string(os.PathSeparator) + testFile
	err := os.WriteFile(fullPath, []byte("test content"), 0600)
	require.NoError(t, err, "Failed to create test file")

	var cmd Command
	if runtime.GOOS == "windows" {
		cmd = executor.CommandContext(ctx, "cmd", "/c", "dir", "/b")
	} else {
		cmd = executor.CommandContext(ctx, "ls")
	}

	cmd.SetDir(tmpDir)

	output, err := cmd.Output()
	require.NoError(t, err, "Command should execute successfully")

	outputStr := strings.TrimSpace(string(output))
	assert.Contains(t, outputStr, testFile, "Output should contain the test file")
}

func TestOSCommand_SetEnv(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	testKey := "TEST_ENV_VAR"
	testValue := "test_value_12345"

	var cmd Command
	if runtime.GOOS == "windows" {
		cmd = executor.CommandContext(ctx, "cmd", "/c", "echo", "%"+testKey+"%")
	} else {
		cmd = executor.CommandContext(ctx, "sh", "-c", "echo $"+testKey)
	}

	env := []string{testKey + "=" + testValue}
	cmd.SetEnv(env)

	output, err := cmd.Output()
	require.NoError(t, err, "Command should execute successfully")

	outputStr := strings.TrimSpace(string(output))

	if runtime.GOOS == "windows" {
		assert.True(t, strings.Contains(outputStr, testValue) || strings.Contains(outputStr, "%"+testKey+"%"),
			"Output should contain the test value or the variable name")
	} else {
		assert.Contains(t, outputStr, testValue, "Output should contain the environment variable value")
	}
}

func TestOSCommand_SetStdout(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	var stdout bytes.Buffer

	cmd := executor.CommandContext(ctx, "echo", "test stdout")
	cmd.SetStdout(&stdout)

	err := cmd.Run()
	require.NoError(t, err, "Command should execute successfully")

	output := stdout.String()
	assert.Contains(t, output, "test stdout", "Stdout buffer should contain the expected output")
}

func TestOSCommand_SetStderr(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	var stderr bytes.Buffer

	var cmd Command
	if runtime.GOOS == "windows" {
		cmd = executor.CommandContext(ctx, "cmd", "/c", "echo test stderr 1>&2")
	} else {
		cmd = executor.CommandContext(ctx, "sh", "-c", "echo 'test stderr' >&2")
	}

	cmd.SetStderr(&stderr)

	err := cmd.Run()
	require.NoError(t, err, "Command should execute successfully")

	output := stderr.String()
	assert.Contains(t, output, "test stderr", "Stderr buffer should contain the expected output")
}

func TestOSCommand_SetStdout_InvalidType(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	cmd := executor.CommandContext(ctx, "echo", "test")
	cmd.SetStdout("invalid")

	err := cmd.Run()
	assert.NoError(t, err, "Command should execute even with invalid stdout type")
}

func TestOSCommand_SetStderr_InvalidType(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	var cmd Command
	if runtime.GOOS == "windows" {
		cmd = executor.CommandContext(ctx, "cmd", "/c", "echo test 1>&2")
	} else {
		cmd = executor.CommandContext(ctx, "sh", "-c", "echo 'test' >&2")
	}

	cmd.SetStderr(12345)

	err := cmd.Run()
	assert.NoError(t, err, "Command should execute even with invalid stderr type")
}

func TestOSCommand_GetProcess(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	var cmd Command
	if runtime.GOOS == "windows" {
		// Use ping on Windows (pings localhost twice, ~1 second)
		cmd = executor.CommandContext(ctx, "ping", "-n", "2", "127.0.0.1")
	} else {
		cmd = executor.CommandContext(ctx, "sleep", "0.1")
	}

	process := cmd.GetProcess()
	assert.Nil(t, process, "Process should be nil before command starts")

	err := cmd.Start()
	require.NoError(t, err, "Start should not return an error")

	process = cmd.GetProcess()
	assert.NotNil(t, process, "Process should not be nil after command starts")

	err = cmd.Wait()
	require.NoError(t, err, "Wait should not return an error")
}

func TestOSCommand_GetProcessState(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	cmd := executor.CommandContext(ctx, "echo", "test")

	state := cmd.GetProcessState()
	assert.Nil(t, state, "ProcessState should be nil before command completes")

	err := cmd.Run()
	require.NoError(t, err, "Run should not return an error")

	state = cmd.GetProcessState()
	assert.NotNil(t, state, "ProcessState should not be nil after command completes")
}

func TestNewOSCommandExecutor(t *testing.T) {
	executor := NewOSCommandExecutor()

	assert.NotNil(t, executor, "NewOSCommandExecutor should return a non-nil executor")
	assert.Implements(t, (*CommandExecutor)(nil), executor, "NewOSCommandExecutor should return a CommandExecutor")

	_, ok := executor.(*OSCommandExecutor)
	assert.True(t, ok, "NewOSCommandExecutor should return an *OSCommandExecutor")
}

func TestNewOSCommandExecutor_Functional(t *testing.T) {
	executor := NewOSCommandExecutor()
	ctx := t.Context()

	cmd := executor.CommandContext(ctx, "echo", "factory test")
	output, err := cmd.Output()

	require.NoError(t, err, "Command created by factory executor should execute successfully")
	assert.Contains(t, string(output), "factory test", "Output should contain expected string")
}

func TestOSCommand_MultipleMethodCalls(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	tmpDir := t.TempDir()
	var stdout, stderr bytes.Buffer

	var cmd Command
	if runtime.GOOS == "windows" {
		cmd = executor.CommandContext(ctx, "cmd", "/c", "echo test output")
	} else {
		cmd = executor.CommandContext(ctx, "echo", "test output")
	}

	cmd.SetDir(tmpDir)
	cmd.SetEnv([]string{"TEST_VAR=value"})
	cmd.SetStdout(&stdout)
	cmd.SetStderr(&stderr)

	err := cmd.Run()
	require.NoError(t, err, "Command should execute successfully")

	assert.Contains(t, stdout.String(), "test output", "Stdout should contain expected output")
}

func TestOSCommand_ContextTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	executor := &OSCommandExecutor{}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	var sleepCmd string
	if runtime.GOOS == "windows" {
		sleepCmd = "timeout"
	} else {
		sleepCmd = "sleep"
	}

	cmd := executor.CommandContext(ctx, sleepCmd, "10")

	err := cmd.Run()
	assert.Error(t, err, "Command should fail due to context timeout")
}

func TestOSCommand_WaitWithoutStart(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	cmd := executor.CommandContext(ctx, "echo", "test")

	err := cmd.Wait()
	assert.Error(t, err, "Wait should return an error when called without Start")
}

func TestOSCommand_MultipleStarts(t *testing.T) {
	executor := &OSCommandExecutor{}
	ctx := t.Context()

	cmd := executor.CommandContext(ctx, "echo", "test")

	err := cmd.Start()
	require.NoError(t, err, "First Start should not return an error")

	err = cmd.Wait()
	require.NoError(t, err, "Wait should not return an error")

	err = cmd.Start()
	assert.Error(t, err, "Second Start should return an error")
}
