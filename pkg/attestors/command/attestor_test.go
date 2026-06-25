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
	"encoding/base64"
	"encoding/json"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/executor"
	"github.com/thomsonreuters/stamp/pkg/logger"
	commandpredicate "github.com/thomsonreuters/stamp/pkg/predicates/command/v1"
)

// getShellArgs returns shell and argument flag for the current platform.
func getShellArgs() (string, string) {
	if runtime.GOOS == "windows" {
		return "cmd.exe", "/c"
	}
	return "/bin/bash", "-c"
}

func TestID(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "command", attestor.ID())
}

func TestName(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "Command Run Attestor", attestor.Name())
}

func TestDescription(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "Captures comprehensive evidence of command execution", attestor.Description())
}

func TestPredicateURI(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	uri := attestor.PredicateURI()
	assert.NotEmpty(t, uri)
	assert.Contains(t, uri, "command")
}

// TestAttestor_ConfigSchema tests the configuration schema.
func TestAttestor_ConfigSchema(t *testing.T) {
	attestation := &Attestor{
		logger: logger.NewNoop(),
	}

	schema := attestation.ConfigSchema()
	assert.NotEmpty(t, schema)

	fieldNames := make(map[string]bool)
	for _, field := range schema {
		fieldNames[field.Name] = true
	}

	requiredFields := []string{
		"command",
		"execution_mode",
		"working_directory",
		"shell",
		"timeout",
		"capture_stdout",
		"capture_stderr",
		"max_output_size",
		"redact_patterns",
		"allowed_exit_codes",
		"fail_on_error",
		"environment_variables",
	}

	for _, required := range requiredFields {
		assert.True(t, fieldNames[required], "missing required field: %s", required)
	}
}

// TestAttestor_Schema tests JSON schema generation.
func TestAttestor_Schema(t *testing.T) {
	attestation := &Attestor{
		logger: logger.NewNoop(),
	}

	schema := attestation.Schema()
	require.NotNil(t, schema)
	assert.Equal(t, "Command Run Attestation", schema.Title)
	assert.NotEmpty(t, schema.Description)
}

// TestAttestor_ValidateConfig tests configuration validation.
func TestAttestor_ValidateConfig(t *testing.T) {
	attestation := &Attestor{
		logger: logger.NewNoop(),
	}

	tests := []struct {
		name      string
		config    map[string]any
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid minimal config",
			config: map[string]any{
				"command": "echo hello",
			},
			wantError: false,
		},
		{
			name: "missing command",
			config: map[string]any{
				"execution_mode": "shell",
			},
			wantError: true,
			errorMsg:  "required field is missing",
		},
		{
			name: "empty command",
			config: map[string]any{
				"command": "",
			},
			wantError: true,
			errorMsg:  "command is required",
		},
		{
			name: "invalid execution mode",
			config: map[string]any{
				"command":        "echo hello",
				"execution_mode": "invalid",
			},
			wantError: true,
			errorMsg:  "invalid execution_mode",
		},
		{
			name: "timeout too low",
			config: map[string]any{
				"command": "echo hello",
				"timeout": 0,
			},
			wantError: true,
			errorMsg:  "timeout must be between 1 and 86400",
		},
		{
			name: "timeout too high",
			config: map[string]any{
				"command": "echo hello",
				"timeout": 100000,
			},
			wantError: true,
			errorMsg:  "timeout must be between 1 and 86400",
		},
		{
			name: "max_output_size too low",
			config: map[string]any{
				"command":         "echo hello",
				"max_output_size": 500,
			},
			wantError: true,
			errorMsg:  "max_output_size must be between 1KB and 100MB",
		},
		{
			name: "invalid redact pattern",
			config: map[string]any{
				"command":         "echo hello",
				"redact_patterns": []string{"[invalid(regex"},
			},
			wantError: true,
			errorMsg:  "invalid redaction pattern",
		},
		{
			name: "valid all options",
			config: map[string]any{
				"command":            "echo hello",
				"execution_mode":     "shell",
				"timeout":            300,
				"capture_stdout":     true,
				"capture_stderr":     true,
				"max_output_size":    5242880,
				"redact_patterns":    []string{"password=.*"},
				"allowed_exit_codes": []string{"0", "1"},
				"fail_on_error":      false,
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := core.Config(tt.config)
			err := attestation.ValidateConfig(cfg)

			if tt.wantError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestAttestor_ParseConfig tests configuration parsing.
func TestAttestor_ParseConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   map[string]any
		validate func(t *testing.T, a *Attestor)
	}{
		{
			name: "default values",
			config: map[string]any{
				"command": "echo hello",
			},
			validate: func(t *testing.T, a *Attestor) {
				assert.Equal(t, "echo hello", a.config.Command)
				assert.Equal(t, ExecutionModeShell, a.config.ExecutionMode)
				assert.Equal(t, getDefaultShell(), a.config.Shell)
				assert.Equal(t, defaultTimeout, a.config.Timeout)
				assert.True(t, a.config.CaptureStdout)
				assert.True(t, a.config.CaptureStderr)
				assert.Equal(t, int64(defaultMaxOutputSize), a.config.MaxOutputSize)
				assert.True(t, a.config.FailOnError)
				assert.Equal(t, []int{0}, a.config.AllowedExitCodes)
			},
		},
		{
			name: "custom values",
			config: map[string]any{
				"command":               "npm run build",
				"execution_mode":        "direct",
				"working_directory":     "/tmp",
				"shell":                 "/bin/sh",
				"timeout":               120,
				"capture_stdout":        false,
				"capture_stderr":        true,
				"max_output_size":       1048576,
				"redact_patterns":       []string{"token=.*"},
				"allowed_exit_codes":    []string{"0", "1", "2"},
				"fail_on_error":         false,
				"environment_variables": map[string]string{"NODE_ENV": "production"},
			},
			validate: func(t *testing.T, a *Attestor) {
				assert.Equal(t, "npm run build", a.config.Command)
				assert.Equal(t, ExecutionModeDirect, a.config.ExecutionMode)
				assert.Equal(t, "/tmp", a.config.WorkingDirectory)
				assert.Equal(t, "/bin/sh", a.config.Shell)
				assert.Equal(t, 120, a.config.Timeout)
				assert.False(t, a.config.CaptureStdout)
				assert.True(t, a.config.CaptureStderr)
				assert.Equal(t, int64(1048576), a.config.MaxOutputSize)
				assert.Equal(t, []string{"token=.*"}, a.config.RedactPatterns)
				assert.Equal(t, []int{0, 1, 2}, a.config.AllowedExitCodes)
				assert.False(t, a.config.FailOnError)
				assert.Equal(t, map[string]string{"NODE_ENV": "production"}, a.config.EnvironmentVariables)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestation := &Attestor{
				logger: logger.NewNoop(),
			}

			cfg := core.Config(tt.config)
			attestation.parseConfig(cfg)

			tt.validate(t, attestation)
		})
	}
}

// TestAttestor_CompileRedactPatterns tests redaction pattern compilation.
func TestAttestor_CompileRedactPatterns(t *testing.T) {
	tests := []struct {
		name      string
		patterns  []string
		wantError bool
	}{
		{
			name:      "no custom patterns",
			patterns:  []string{},
			wantError: false,
		},
		{
			name:      "valid patterns",
			patterns:  []string{`token=[A-Za-z0-9]+`, `key=\d+`},
			wantError: false,
		},
		{
			name:      "invalid pattern",
			patterns:  []string{"[invalid("},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
				config: Config{
					RedactPatterns: tt.patterns,
				},
			}

			err := attestor.compileRedactPatterns()

			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(attestor.redactRegexps), 4)
			}
		})
	}
}

// TestAttestor_ExecuteCommand_ShellMode tests command execution in shell mode.
func TestAttestor_ExecuteCommand_ShellMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses Unix shell /bin/bash")
	}

	mockExec := executor.SetupMockCommandExecutor(t)
	mockCmd := executor.NewMockCommand()

	mockCmd.On("SetDir", mock.Anything).Maybe()
	mockCmd.On("SetEnv", mock.Anything).Maybe()
	mockCmd.On("SetStdout", mock.Anything).Maybe()
	mockCmd.On("SetStderr", mock.Anything).Maybe()
	mockCmd.On("Run").Return(nil)
	mockCmd.On("GetProcess").Return(nil).Maybe()
	mockCmd.On("GetProcessState").Return(nil).Maybe()

	mockExec.On("CommandContext", mock.Anything, "/bin/bash", "-c", "echo hello").Return(mockCmd)

	attestor := &Attestor{
		logger:   logger.NewNoop(),
		executor: mockExec,
		config: Config{
			Command:       "echo hello",
			ExecutionMode: ExecutionModeShell,
			Shell:         "/bin/bash",
			Timeout:       10,
			CaptureStdout: true,
			CaptureStderr: true,
			MaxOutputSize: 1024,
		},
	}

	result, err := attestor.executeCommand(t.Context())

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, statusSuccess, result.Status)
	mockExec.AssertExpectations(t)
	mockCmd.AssertExpectations(t)
}

// TestAttestor_ExecuteCommand_DirectMode tests command execution in direct mode.
func TestAttestor_ExecuteCommand_DirectMode(t *testing.T) {
	mockExec := executor.SetupMockCommandExecutor(t)
	mockCmd := executor.NewMockCommand()

	mockCmd.On("SetDir", mock.Anything).Maybe()
	mockCmd.On("SetEnv", mock.Anything).Maybe()
	mockCmd.On("SetStdout", mock.Anything).Maybe()
	mockCmd.On("SetStderr", mock.Anything).Maybe()
	mockCmd.On("Run").Return(nil)
	mockCmd.On("GetProcess").Return(nil).Maybe()
	mockCmd.On("GetProcessState").Return(nil).Maybe()

	mockExec.On("CommandContext", mock.Anything, "echo", "hello", "world").Return(mockCmd)

	attestor := &Attestor{
		logger:   logger.NewNoop(),
		executor: mockExec,
		config: Config{
			Command:       "echo hello world",
			ExecutionMode: ExecutionModeDirect,
			Timeout:       10,
			CaptureStdout: true,
			CaptureStderr: true,
			MaxOutputSize: 1024,
		},
	}

	result, err := attestor.executeCommand(t.Context())

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, statusSuccess, result.Status)
	mockExec.AssertExpectations(t)
	mockCmd.AssertExpectations(t)
}

// TestAttestor_ExecuteCommand_EmptyCommand tests empty command handling in direct mode.
func TestAttestor_ExecuteCommand_EmptyCommand(t *testing.T) {
	mockExec := executor.SetupMockCommandExecutor(t)

	attestor := &Attestor{
		logger:   logger.NewNoop(),
		executor: mockExec,
		config: Config{
			Command:       `""`,
			ExecutionMode: ExecutionModeDirect,
			Timeout:       10,
		},
	}

	result, err := attestor.executeCommand(t.Context())

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no command to execute")
}

// TestAttestor_ProcessOutput tests output processing with UTF-8 and Base64 encoding.
func TestAttestor_ProcessOutput(t *testing.T) {
	tests := []struct {
		name              string
		stdout            []byte
		stderr            []byte
		expectedStdoutEnc string
		expectedStderrEnc string
		validateStdout    func(t *testing.T, output string)
		validateStderr    func(t *testing.T, output string)
	}{
		{
			name:              "UTF-8 output",
			stdout:            []byte("Hello, World!"),
			stderr:            []byte("Warning message"),
			expectedStdoutEnc: "utf-8",
			expectedStderrEnc: "utf-8",
			validateStdout: func(t *testing.T, output string) {
				assert.Equal(t, "Hello, World!", output)
			},
			validateStderr: func(t *testing.T, output string) {
				assert.Equal(t, "Warning message", output)
			},
		},
		{
			name:              "Binary output",
			stdout:            []byte{0xFF, 0xFE, 0xFD, 0x00, 0x01},
			stderr:            []byte{0xDE, 0xAD, 0xBE, 0xEF},
			expectedStdoutEnc: "base64",
			expectedStderrEnc: "base64",
			validateStdout: func(t *testing.T, output string) {
				decoded, err := base64.StdEncoding.DecodeString(output)
				require.NoError(t, err)
				assert.Equal(t, []byte{0xFF, 0xFE, 0xFD, 0x00, 0x01}, decoded)
			},
			validateStderr: func(t *testing.T, output string) {
				decoded, err := base64.StdEncoding.DecodeString(output)
				require.NoError(t, err)
				assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, decoded)
			},
		},
		{
			name:              "Mixed UTF-8 and binary",
			stdout:            []byte("Valid UTF-8"),
			stderr:            []byte{0xFF, 0xFE},
			expectedStdoutEnc: "utf-8",
			expectedStderrEnc: "base64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
				config: Config{
					CaptureStdout: true,
					CaptureStderr: true,
				},
				evidence: &CommandEvidence{},
			}

			result := &ExecutionResult{
				Stdout: tt.stdout,
				Stderr: tt.stderr,
			}

			attestor.processOutput(result)

			require.NotNil(t, attestor.evidence.Output)
			assert.Equal(t, tt.expectedStdoutEnc, attestor.evidence.Output.StdoutEncoding)
			assert.Equal(t, tt.expectedStderrEnc, attestor.evidence.Output.StderrEncoding)

			if tt.validateStdout != nil {
				tt.validateStdout(t, attestor.evidence.Output.Stdout)
			}
			if tt.validateStderr != nil {
				tt.validateStderr(t, attestor.evidence.Output.Stderr)
			}

			if len(tt.stdout) > 0 {
				assert.NotEmpty(t, attestor.evidence.Output.Digest.Stdout)
				assert.Contains(t, attestor.evidence.Output.Digest.Stdout, "sha256:")
			}
			if len(tt.stderr) > 0 {
				assert.NotEmpty(t, attestor.evidence.Output.Digest.Stderr)
				assert.Contains(t, attestor.evidence.Output.Digest.Stderr, "sha256:")
			}
		})
	}
}

// TestAttestor_ApplyRedaction tests output redaction with all default patterns.
func TestAttestor_ApplyRedaction(t *testing.T) {
	tests := []struct {
		name            string
		commandLine     string
		stdout          string
		stderr          string
		expectedRedacts map[string][]string // field -> list of strings that should be redacted
	}{
		{
			name:        "password pattern",
			commandLine: "mysql -u user -ppassword=exampleSecretP@ss",
			stdout:      "Database connected with password=dbPass123",
			stderr:      "Warning: password=tempPass456 is weak",
			expectedRedacts: map[string][]string{
				"command": {"password=exampleSecretP@ss"},
				"stdout":  {"password=dbPass123"},
				"stderr":  {"password=tempPass456"},
			},
		},
		{
			name:        "token pattern",
			commandLine: "curl -H 'Authorization: Bearer token=ghp_1234567890'",
			stdout:      "Response: token=api_token_xyz",
			stderr:      "Auth failed: token=invalid_token",
			expectedRedacts: map[string][]string{
				"command": {"token=ghp_1234567890"},
				"stdout":  {"token=api_token_xyz"},
				"stderr":  {"token=invalid_token"},
			},
		},
		{
			name:        "api_key pattern with underscore",
			commandLine: "export api_key=sk-1234567890abcdef",
			stdout:      "API initialized with api_key=live_key_123",
			stderr:      "Error: api_key=test_key_456 is invalid",
			expectedRedacts: map[string][]string{
				"command": {"api_key=sk-1234567890abcdef"},
				"stdout":  {"api_key=live_key_123"},
				"stderr":  {"api_key=test_key_456"},
			},
		},
		{
			name:        "api-key pattern with hyphen",
			commandLine: "curl --header 'api-key=prod-key-xyz'",
			stdout:      "Config: api-key=default-key-abc",
			stderr:      "Warning: api-key=staging-key-def is deprecated",
			expectedRedacts: map[string][]string{
				"command": {"api-key=prod-key-xyz"},
				"stdout":  {"api-key=default-key-abc"},
				"stderr":  {"api-key=staging-key-def"},
			},
		},
		{
			name:        "apikey pattern without separator",
			commandLine: "app --config apikey=mobile_app_key",
			stdout:      "Using apikey=backend_key",
			stderr:      "Error: apikey=frontend_key not found",
			expectedRedacts: map[string][]string{
				"command": {"apikey=mobile_app_key"},
				"stdout":  {"apikey=backend_key"},
				"stderr":  {"apikey=frontend_key"},
			},
		},
		{
			name:        "secret pattern",
			commandLine: "deploy --secret=webhook_secret_123",
			stdout:      "Deployed with secret=encryption_secret_xyz",
			stderr:      "Failed: secret=signing_secret_abc is missing",
			expectedRedacts: map[string][]string{
				"command": {"secret=webhook_secret_123"},
				"stdout":  {"secret=encryption_secret_xyz"},
				"stderr":  {"secret=signing_secret_abc"},
			},
		},
		{
			name:        "multiple patterns in single output",
			commandLine: "app --token=abc123 --password=pass456 --api_key=key789 --secret=sec000",
			stdout:      "Started: token=t1 password=p2 api_key=k3 secret=s4",
			stderr:      "Debug: token=t5 password=p6 api-key=k7 secret=s8",
			expectedRedacts: map[string][]string{
				"command": {"token=abc123", "password=pass456", "api_key=key789", "secret=sec000"},
				"stdout":  {"token=t1", "password=p2", "api_key=k3", "secret=s4"},
				"stderr":  {"token=t5", "password=p6", "api-key=k7", "secret=s8"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
				evidence: &CommandEvidence{
					Command: commandpredicate.CommandInfo{
						CommandLine: tt.commandLine,
					},
					Output: &commandpredicate.OutputInfo{
						Stdout: tt.stdout,
						Stderr: tt.stderr,
					},
				},
			}

			attestor.config.RedactPatterns = []string{}
			err := attestor.compileRedactPatterns()
			require.NoError(t, err)

			attestor.applyRedaction()

			// Verify redaction occurred
			assert.Contains(t, attestor.evidence.Command.CommandLine, "[REDACTED]",
				"command line should contain [REDACTED]")
			if tt.stdout != "" {
				assert.Contains(t, attestor.evidence.Output.Stdout, "[REDACTED]",
					"stdout should contain [REDACTED]")
			}
			if tt.stderr != "" {
				assert.Contains(t, attestor.evidence.Output.Stderr, "[REDACTED]",
					"stderr should contain [REDACTED]")
			}

			// Verify sensitive values are removed
			if commandRedacts, ok := tt.expectedRedacts["command"]; ok {
				for _, sensitive := range commandRedacts {
					assert.NotContains(t, attestor.evidence.Command.CommandLine, sensitive,
						"command line should not contain sensitive value: %s", sensitive)
				}
			}

			if stdoutRedacts, ok := tt.expectedRedacts["stdout"]; ok {
				for _, sensitive := range stdoutRedacts {
					assert.NotContains(t, attestor.evidence.Output.Stdout, sensitive,
						"stdout should not contain sensitive value: %s", sensitive)
				}
			}

			if stderrRedacts, ok := tt.expectedRedacts["stderr"]; ok {
				for _, sensitive := range stderrRedacts {
					assert.NotContains(t, attestor.evidence.Output.Stderr, sensitive,
						"stderr should not contain sensitive value: %s", sensitive)
				}
			}
		})
	}

	t.Run("custom redaction patterns", func(t *testing.T) {
		attestor := &Attestor{
			logger: logger.NewNoop(),
			evidence: &CommandEvidence{
				Command: commandpredicate.CommandInfo{
					CommandLine: "app --custom-secret=xyz123",
				},
				Output: &commandpredicate.OutputInfo{
					Stdout: "Using custom-secret=abc456",
					Stderr: "",
				},
			},
		}

		attestor.config.RedactPatterns = []string{`custom-secret=[\S]+`}
		err := attestor.compileRedactPatterns()
		require.NoError(t, err)

		attestor.applyRedaction()

		assert.Contains(t, attestor.evidence.Command.CommandLine, "[REDACTED]")
		assert.Contains(t, attestor.evidence.Output.Stdout, "[REDACTED]")
		assert.NotContains(t, attestor.evidence.Command.CommandLine, "xyz123")
		assert.NotContains(t, attestor.evidence.Output.Stdout, "abc456")
	})

	t.Run("no sensitive data", func(t *testing.T) {
		attestor := &Attestor{
			logger: logger.NewNoop(),
			evidence: &CommandEvidence{
				Command: commandpredicate.CommandInfo{
					CommandLine: "echo 'Hello World'",
				},
				Output: &commandpredicate.OutputInfo{
					Stdout: "Hello World",
					Stderr: "",
				},
			},
		}

		attestor.config.RedactPatterns = []string{}
		err := attestor.compileRedactPatterns()
		require.NoError(t, err)

		originalCommand := attestor.evidence.Command.CommandLine
		originalStdout := attestor.evidence.Output.Stdout

		attestor.applyRedaction()

		assert.Equal(t, originalCommand, attestor.evidence.Command.CommandLine,
			"command line should remain unchanged when no sensitive data present")
		assert.Equal(t, originalStdout, attestor.evidence.Output.Stdout,
			"stdout should remain unchanged when no sensitive data present")
	})
}

// TestAttestor_IsAllowedExitCode tests exit code validation.
func TestAttestor_IsAllowedExitCode(t *testing.T) {
	tests := []struct {
		name         string
		allowedCodes []int
		testCode     int
		expected     bool
	}{
		{
			name:         "default - zero allowed",
			allowedCodes: []int{0},
			testCode:     0,
			expected:     true,
		},
		{
			name:         "default - non-zero not allowed",
			allowedCodes: []int{0},
			testCode:     1,
			expected:     false,
		},
		{
			name:         "multiple allowed codes",
			allowedCodes: []int{0, 1, 2},
			testCode:     1,
			expected:     true,
		},
		{
			name:         "code not in allowed list",
			allowedCodes: []int{0, 1, 2},
			testCode:     3,
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
				config: Config{
					AllowedExitCodes: tt.allowedCodes,
				},
			}

			result := attestor.isAllowedExitCode(tt.testCode)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAttestor_Lifecycle tests the full attestor lifecycle.
func TestAttestor_Lifecycle(t *testing.T) {
	mockExec := executor.SetupMockCommandExecutor(t)
	mockCmd := executor.NewMockCommand()
	mockPlatformCmd := executor.NewMockCommand()

	// Mock main command execution
	mockCmd.On("SetDir", mock.Anything).Maybe()
	mockCmd.On("SetEnv", mock.Anything).Maybe()
	mockCmd.On("SetStdout", mock.Anything).Maybe()
	mockCmd.On("SetStderr", mock.Anything).Maybe()
	mockCmd.On("Run").Return(nil)
	mockCmd.On("GetProcess").Return(nil).Maybe()
	mockCmd.On("GetProcessState").Return(nil).Maybe()

	shell, flag := getShellArgs()
	mockExec.On("CommandContext", mock.Anything, shell, flag, "echo test").Return(mockCmd)

	// Mock platform detection commands (macOS/Linux/Windows)
	mockPlatformCmd.On("Output").Return([]byte("14.0\n"), nil)
	mockExec.On("CommandContext", mock.Anything, "sw_vers", "-productVersion").Return(mockPlatformCmd).Maybe()
	mockExec.On("CommandContext", mock.Anything, "cmd", "/c", "ver").Return(mockPlatformCmd).Maybe()

	attestor := &Attestor{
		logger:   logger.NewNoop(),
		executor: mockExec,
	}

	config := core.Config(map[string]any{
		"command": "echo test",
	})

	ctx := t.Context()

	err := attestor.PreAttest(ctx, config)
	require.NoError(t, err)

	err = attestor.Attest(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, attestor.evidence)

	predicate, err := attestor.GeneratePredicate(config)
	require.NoError(t, err)
	require.NotNil(t, predicate)

	_, err = json.Marshal(predicate)
	require.NoError(t, err)

	subjects := attestor.Subjects(config)
	assert.Len(t, subjects, 1)
	assert.Contains(t, subjects[0].Name, "command-execution")
	assert.Contains(t, subjects[0].Digest, "sha256")

	err = attestor.PostAttest(ctx, config)
	require.NoError(t, err)

	mockExec.AssertExpectations(t)
	mockCmd.AssertExpectations(t)
}

// TestAttestor_GeneratePredicate_NoEvidence tests predicate generation without evidence.
func TestAttestor_GeneratePredicate_NoEvidence(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	config := core.Config(map[string]any{
		"command": "echo test",
	})

	predicate, err := attestor.GeneratePredicate(config)

	require.Error(t, err)
	assert.Nil(t, predicate)
	assert.Contains(t, err.Error(), "no evidence collected")
}

// TestAttestor_Subjects_NoEvidence tests subjects generation without evidence.
func TestAttestor_Subjects_NoEvidence(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	config := core.Config(map[string]any{
		"command": "echo test",
	})

	subjects := attestor.Subjects(config)
	assert.Empty(t, subjects)
}

// TestAttestor_SanitizeForLog tests log sanitization.
func TestAttestor_SanitizeForLog(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		redactRegexps: []*regexp.Regexp{
			regexp.MustCompile(`password=[\S]+`),
			regexp.MustCompile(`token=[\S]+`),
		},
	}

	input := "curl -H 'password=secret123' -H 'token=xyz789'"
	output := attestor.sanitizeForLog(input)

	assert.Contains(t, output, "[REDACTED]")
	assert.NotContains(t, output, "secret123")
	assert.NotContains(t, output, "xyz789")
}

// TestAttestor_BuildCommandInfo tests command info building for different execution modes.
func TestAttestor_BuildCommandInfo(t *testing.T) {
	tests := []struct {
		name         string
		config       Config
		validateInfo func(t *testing.T, info commandpredicate.CommandInfo)
	}{
		{
			name: "shell mode",
			config: Config{
				Command:       "echo hello",
				ExecutionMode: ExecutionModeShell,
				Shell:         "/bin/bash",
			},
			validateInfo: func(t *testing.T, info commandpredicate.CommandInfo) {
				assert.Equal(t, "echo hello", info.CommandLine)
				assert.Equal(t, "/bin/bash", info.Shell)
				assert.Empty(t, info.Executable)
			},
		},
		{
			name: "direct mode",
			config: Config{
				Command:       "echo hello world",
				ExecutionMode: ExecutionModeDirect,
			},
			validateInfo: func(t *testing.T, info commandpredicate.CommandInfo) {
				assert.Equal(t, "echo hello world", info.CommandLine)
				assert.Equal(t, "echo", info.Executable)
				assert.Equal(t, []string{"hello", "world"}, info.Arguments)
				assert.Empty(t, info.Shell)
			},
		},
		{
			name: "script mode with long script",
			config: Config{
				Command:       strings.Repeat("echo line\n", 20),
				ExecutionMode: ExecutionModeScript,
				Shell:         "/bin/bash",
			},
			validateInfo: func(t *testing.T, info commandpredicate.CommandInfo) {
				assert.Contains(t, info.CommandLine, "[script:")
				assert.Equal(t, "/bin/bash", info.Shell)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
				config: tt.config,
			}

			info := attestor.buildCommandInfo()
			tt.validateInfo(t, info)
		})
	}
}

// TestAttestor_FailOnDisallowedExitCode tests failure on disallowed exit codes.
func TestAttestor_FailOnDisallowedExitCode(t *testing.T) {
	mockExec := executor.SetupMockCommandExecutor(t)
	mockCmd := executor.NewMockCommand()
	mockPlatformCmd := executor.NewMockCommand()

	// Simulate non-zero exit
	mockCmd.On("SetDir", mock.Anything).Maybe()
	mockCmd.On("SetEnv", mock.Anything).Maybe()
	mockCmd.On("SetStdout", mock.Anything).Maybe()
	mockCmd.On("SetStderr", mock.Anything).Maybe()
	mockCmd.On("Run").Return(&exec.ExitError{})
	mockCmd.On("GetProcess").Return(nil).Maybe()
	mockCmd.On("GetProcessState").Return(nil).Maybe()

	shell, flag := getShellArgs()
	mockExec.On("CommandContext", mock.Anything, shell, flag, "exit 1").Return(mockCmd)

	// Mock platform detection commands
	mockPlatformCmd.On("Output").Return([]byte("14.0\n"), nil)
	mockExec.On("CommandContext", mock.Anything, "sw_vers", "-productVersion").Return(mockPlatformCmd).Maybe()
	mockExec.On("CommandContext", mock.Anything, "cmd", "/c", "ver").Return(mockPlatformCmd).Maybe()

	attestor := &Attestor{
		logger:   logger.NewNoop(),
		executor: mockExec,
	}

	config := core.Config(map[string]any{
		"command":       "exit 1",
		"fail_on_error": true,
	})

	ctx := t.Context()

	err := attestor.PreAttest(ctx, config)
	require.NoError(t, err)

	err = attestor.Attest(ctx, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disallowed code")
}

// TestAttestor_CaptureEnvironment tests environment capture.
func TestAttestor_CaptureEnvironment(t *testing.T) {
	tmpDir := t.TempDir()

	attestor := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			WorkingDirectory: tmpDir,
		},
	}

	env := attestor.captureEnvironment()

	assert.Equal(t, tmpDir, env.WorkingDirectory)
	assert.NotEmpty(t, env.Hostname)
	assert.NotEmpty(t, env.User)
	assert.NotEmpty(t, env.Platform.OS)
	assert.NotEmpty(t, env.Platform.Arch)
}
